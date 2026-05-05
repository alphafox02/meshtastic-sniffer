/*
 * Polyphase filterbank channelizer -- implementation.
 *
 * Reference: Hentschel & Fettweis, "Sample Rate Conversion for Software
 * Radio" (IEEE Comm Mag, Aug 2000); see also liquidsdr.org/blog/pfb-
 * channelizer/. The algorithm here is a textbook critically-sampled
 * decimator-by-M PFB:
 *
 *   1. Design a prototype lowpass h[0..L*M-1] with cutoff 1/(2M).
 *   2. Decompose into M branches: h_p[i][k] = h[k*M + i].
 *   3. Per input sample x[n]:
 *        branch i = n mod M                   -- forward commutator
 *        branch[i].delay <- shift_in(x[n])   -- length-L delay line
 *      When (n+1) mod M == 0 (cycle boundary):
 *        For each branch i:
 *          y_i = sum_{k=0..L-1} branch[i].delay[k] * h_p[i][k]
 *        Y[k] = FFT(y)                        -- M-point forward DFT
 *        emit Y[bin] to each channel registered on `bin`
 *
 * Forward commutator + forward FFT: an input tone at frequency +f Hz
 * lights up output bin round(f * M / Fs), with FFTW natural ordering
 * (bins 0..M/2 = positive frequencies, M/2..M-1 = negative wrap).
 *
 * Output rate per channel = Fs / M. Adjacent-channel rejection is set
 * by the prototype filter; with a Hamming-windowed sinc of length 12*M
 * we get ~-43 dB sidelobes.
 *
 * Optional pre-shift: an NCO multiply applied to input before the
 * commutator. Used to recenter the output bin grid onto an arbitrary
 * channel grid (e.g. Meshtastic 250 kHz channels are offset by
 * 125 kHz from a 0-aligned 250 kHz FFT bin grid).
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pfb.h"
#include "fftw_lock.h"

#include <fftw3.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define PFB_OUTBUF_SAMPLES 1024  /* per-bin batching to amortise callback */

typedef struct bin_sink {
    int               channel_id;
    pfb_emit_cb       cb;
    void             *user;
    /* Per-bin output buffer; flushed when full. */
    float complex     outbuf[PFB_OUTBUF_SAMPLES];
    int               outbuf_count;
    struct bin_sink  *next;        /* linked list per bin (allow multiple sinks) */
} bin_sink_t;

struct pfb {
    int               M;
    int               L;
    double            samp_rate;
    /* Polyphase taps: contiguous M*L floats, indexed h_p[i*L + k]. */
    float            *h_p;
    /* Per-branch delay lines: contiguous M*L complex, indexed dly[i*L + k]. */
    float complex    *dly;
    int               dly_w;       /* shared write index, advances each cycle */
    int               cycle;       /* counts output cycles for DC tracking */
    int               sample_count; /* 0..M-1 within current cycle */
    /* Group-delay compensation: the prototype filter has linear phase
     * with group delay (L-1)/2 OUTPUT samples (= (L*M-1)/2 input samples
     * relative to input rate). Without compensation, downstream sees a
     * fixed STO offset that shows up as k_hat near N for small-M PFBs.
     * We swallow this many output samples after startup so the very
     * first emitted sample corresponds to "true input position 0". */
    int               warmup_remaining;
    /* FFT */
    fftwf_complex    *fft_in;
    fftwf_complex    *fft_out;
    fftwf_plan        fft_plan;
    /* Pre-shift NCO */
    float complex     nco_phasor;
    float complex     nco_current;
    int               nco_renorm;
    /* Per-bin sink lists (sized M, NULL for unused bins). */
    bin_sink_t      **bins;
};

/* Hamming-windowed sinc prototype LPF, length L*M, cutoff = 1/(2M). */
static void design_prototype(float *h, int M, int L)
{
    int N = L * M;
    double cutoff = 1.0 / (2.0 * (double)M);
    double sum = 0.0;
    for (int n = 0; n < N; ++n) {
        double k = (double)n - (double)(N - 1) / 2.0;
        double sinc = (fabs(k) < 1e-12)
                      ? 2.0 * cutoff
                      : sin(2.0 * M_PI * cutoff * k) / (M_PI * k);
        double window = 0.54 - 0.46 * cos(2.0 * M_PI * (double)n / (double)(N - 1));
        h[n] = (float)(sinc * window);
        sum += h[n];
    }
    /* Normalise to unity passband gain at DC. The PFB scaling absorbs an
     * additional 1/M factor (from the FFT) so we want sum(h) ≈ 1. */
    if (sum > 0.0) {
        float inv = 1.0f / (float)sum;
        for (int n = 0; n < N; ++n) h[n] *= inv;
    }
}

pfb_t *pfb_create(int M, int L, double pre_shift_hz, double samp_rate)
{
    if (M < 1 || L < 2 || samp_rate <= 0.0) return NULL;
    /* M=1 is the degenerate case (input rate == output rate, single
     * channel = full SDR bandwidth). The PFB still works -- a single
     * branch with an identity-ish FIR + 1-point FFT (= passthrough) --
     * but it's worth guarding callers against tiny M just in case. */
    pfb_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->M = M;
    p->L = L;
    p->samp_rate = samp_rate;

    p->h_p = malloc(sizeof(float)         * (size_t)M * (size_t)L);
    p->dly = calloc((size_t)M * (size_t)L, sizeof(float complex));
    p->bins = calloc((size_t)M, sizeof(bin_sink_t *));
    p->fft_in  = fftwf_alloc_complex(M);
    p->fft_out = fftwf_alloc_complex(M);
    if (!p->h_p || !p->dly || !p->bins || !p->fft_in || !p->fft_out) {
        pfb_destroy(p);
        return NULL;
    }

    /* Design prototype, then transpose into branch-major polyphase order:
     *   h_p_branch_major[i * L + k] = h[k * M + i]
     * Index-by-branch is hot in the inner loop, so contiguous access wins. */
    float *h = malloc(sizeof(float) * (size_t)M * (size_t)L);
    if (!h) { pfb_destroy(p); return NULL; }
    design_prototype(h, M, L);
    for (int i = 0; i < M; ++i) {
        for (int k = 0; k < L; ++k) {
            p->h_p[i * L + k] = h[k * M + i];
        }
    }
    free(h);

    fftw_planner_lock();
    p->fft_plan = fftwf_plan_dft_1d(M, p->fft_in, p->fft_out,
                                    FFTW_FORWARD, FFTW_MEASURE);
    fftw_planner_unlock();
    if (!p->fft_plan) { pfb_destroy(p); return NULL; }

    /* Pre-shift NCO. exp(j*2*pi*(-pre_shift)*n/Fs); negative because we
     * want to shift the spectrum DOWN by pre_shift_hz so the channel
     * grid lands on integer FFT bins. */
    double phase_inc = -2.0 * M_PI * pre_shift_hz / samp_rate;
    p->nco_phasor  = (float complex)(cos(phase_inc) + I * sin(phase_inc));
    p->nco_current = 1.0f + 0.0f * I;

    /* Filter group delay = (L*M-1)/2 input samples = (L-1)/2 output
     * samples, plus a half-sample residual we round up. */
    p->warmup_remaining = (L - 1) / 2 + 1;

    return p;
}

int pfb_register_bin(pfb_t *p, int bin, int channel_id,
                     pfb_emit_cb cb, void *user)
{
    if (!p || bin < 0 || bin >= p->M || !cb) return -1;
    bin_sink_t *s = calloc(1, sizeof(*s));
    if (!s) return -1;
    s->channel_id = channel_id;
    s->cb = cb;
    s->user = user;
    /* Prepend to per-bin sink list. */
    s->next = p->bins[bin];
    p->bins[bin] = s;
    return 0;
}

static inline void flush_sink(bin_sink_t *s)
{
    if (s->outbuf_count > 0 && s->cb) {
        s->cb(s->channel_id, s->outbuf, (size_t)s->outbuf_count, s->user);
    }
    s->outbuf_count = 0;
}

static inline void emit_to_bin(pfb_t *p, int bin, float complex y)
{
    bin_sink_t *s = p->bins[bin];
    while (s) {
        s->outbuf[s->outbuf_count++] = y;
        if (s->outbuf_count == PFB_OUTBUF_SAMPLES) flush_sink(s);
        s = s->next;
    }
}

/* Run one PFB output cycle: FIR each branch, FFT, dispatch to per-bin
 * sinks. Called when sample_count wraps from M-1 to 0. */
static inline void pfb_one_cycle(pfb_t *p)
{
    int M = p->M;
    int L = p->L;
    int w = p->dly_w;          /* delay line write position (post-write) */

    /* For each branch i, FIR with the corresponding polyphase row. The
     * branch's delay line is dly[i*L + (w-1-k) mod L] for tap k = 0..L-1
     * (taps[0] is the most recent sample). */
    for (int i = 0; i < M; ++i) {
        const float *h = &p->h_p[i * L];
        const float complex *d = &p->dly[i * L];
        float complex acc = 0.0f + 0.0f * I;
        int idx = w;
        for (int k = 0; k < L; ++k) {
            idx = idx ? idx - 1 : L - 1;
            acc += d[idx] * h[k];
        }
        p->fft_in[i] = acc;
    }
    fftwf_execute(p->fft_plan);

    /* Drop the first warmup_remaining output cycles to compensate for
     * the prototype filter's group delay. Without this the downstream
     * LoRa demod sees a fixed STO offset (= group delay) on every
     * frame, which manifests as k_hat near N rather than 0 and breaks
     * the (N - k_hat) skip math in the state machine. */
    if (p->warmup_remaining > 0) {
        --p->warmup_remaining;
        ++p->cycle;
        return;
    }

    /* Dispatch each bin to its sinks. */
    for (int b = 0; b < M; ++b) {
        if (!p->bins[b]) continue;
        emit_to_bin(p, b, (float complex)p->fft_out[b]);
    }
    p->cycle++;
}

void pfb_process(pfb_t *p, const float complex *samples, size_t n)
{
    if (!p || !samples) return;
    int M = p->M;
    int L = p->L;
    /* M=1 special case: there's no actual channelization to do (input
     * rate == output rate, single channel). The prototype filter would
     * just attenuate LoRa chirp edges by ~6 dB while adding delay. The
     * synthetic regression suite feeds at rate == bw_hz (so M=1) and
     * needs bit-exact passthrough to match the bit-exact upstream
     * test fixtures. */
    if (M == 1) {
        for (size_t s = 0; s < n; ++s) {
            float complex x = samples[s] * p->nco_current;
            p->nco_current *= p->nco_phasor;
            if (++p->nco_renorm >= 1024) {
                p->nco_renorm = 0;
                float mag = cabsf(p->nco_current);
                if (mag > 0.0f) p->nco_current /= mag;
            }
            if (p->bins[0]) emit_to_bin(p, 0, x);
            ++p->cycle;
        }
        return;
    }
    for (size_t s = 0; s < n; ++s) {
        /* Pre-shift NCO. */
        float complex x = samples[s] * p->nco_current;
        p->nco_current *= p->nco_phasor;
        if (++p->nco_renorm >= 1024) {
            p->nco_renorm = 0;
            float mag = cabsf(p->nco_current);
            if (mag > 0.0f) p->nco_current /= mag;
        }
        /* Forward commutator: input n -> branch (n mod M). With this
         * direction and a forward FFT, output bin k = positive frequency
         * k*Fs/M (for k <= M/2) which matches the natural "input at +f
         * lights up bin +f*M/Fs" intuition we want here. */
        int branch = p->sample_count;
        /* Push x into branch's delay line at position dly_w. */
        p->dly[branch * L + p->dly_w] = x;
        ++p->sample_count;
        if (p->sample_count == M) {
            /* Cycle complete: advance write pointer, fire FIR+FFT. */
            p->dly_w = (p->dly_w + 1) % L;
            p->sample_count = 0;
            pfb_one_cycle(p);
        }
    }
}

void pfb_flush(pfb_t *p)
{
    if (!p) return;
    for (int b = 0; b < p->M; ++b) {
        bin_sink_t *s = p->bins[b];
        while (s) { flush_sink(s); s = s->next; }
    }
}

void pfb_destroy(pfb_t *p)
{
    if (!p) return;
    for (int b = 0; b < p->M; ++b) {
        bin_sink_t *s = p->bins[b];
        while (s) {
            bin_sink_t *next = s->next;
            free(s);
            s = next;
        }
    }
    if (p->fft_plan) {
        fftw_planner_lock();
        fftwf_destroy_plan(p->fft_plan);
        fftw_planner_unlock();
    }
    fftwf_free(p->fft_in);
    fftwf_free(p->fft_out);
    free(p->bins);
    free(p->dly);
    free(p->h_p);
    free(p);
}

int    pfb_M(const pfb_t *p)            { return p ? p->M : 0; }
int    pfb_L(const pfb_t *p)            { return p ? p->L : 0; }
double pfb_output_rate(const pfb_t *p)  { return p ? p->samp_rate / (double)p->M : 0.0; }
