/*
 * meshtastic-sniffer: LoRa CSS demodulator.
 *
 * Stage-by-stage implementation. The pure-algorithm stages (gray,
 * hamming, dewhiten, crc, deinterleave) are implemented from the LoRa
 * spec; they are tested standalone via lora_*() helpers in lora.h.
 *
 * The DSP path is:
 *   accumulate N=2^SF samples per symbol
 *     -> dechirp (multiply by reference downchirp)
 *     -> N-point FFT (FFTW3f)
 *     -> argmax bin = symbol value
 *   IDLE   : look for repeated identical bins (preamble)
 *   PRE_OK : count further matching upchirps
 *   SYNC   : verify sync word symbols
 *   HEADER : 8 symbols -> Hamming(8,4) -> length, CR, has_CRC
 *   PAYLOAD: cw_per_block symbols -> deinterleave -> Hamming(cr) -> bytes
 *   DELIVER: dewhiten, CRC check, frame callback
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "lora.h"
#include "fftw_lock.h"

#include <complex.h>
#include <fftw3.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ---- LoRa whitening sequence (256 bytes) ---- */
static const uint8_t LORA_WHITEN[256] = {
    0xff,0xfe,0xfc,0xf8,0xf0,0xe1,0xc2,0x85,0x0b,0x17,0x2f,0x5e,0xbc,0x78,0xf1,0xe3,
    0xc6,0x8d,0x1a,0x34,0x68,0xd0,0xa0,0x40,0x80,0x01,0x02,0x04,0x08,0x11,0x23,0x47,
    0x8e,0x1c,0x38,0x71,0xe2,0xc4,0x89,0x12,0x25,0x4b,0x97,0x2e,0x5c,0xb8,0x70,0xe0,
    0xc0,0x81,0x03,0x06,0x0c,0x19,0x32,0x64,0xc9,0x92,0x24,0x49,0x93,0x26,0x4d,0x9b,
    0x37,0x6e,0xdc,0xb9,0x72,0xe4,0xc8,0x90,0x20,0x41,0x82,0x05,0x0a,0x15,0x2b,0x56,
    0xad,0x5b,0xb6,0x6d,0xda,0xb5,0x6b,0xd6,0xac,0x59,0xb2,0x65,0xcb,0x96,0x2c,0x58,
    0xb0,0x61,0xc3,0x87,0x0f,0x1f,0x3e,0x7d,0xfb,0xf6,0xed,0xdb,0xb7,0x6f,0xde,0xbd,
    0x7a,0xf5,0xeb,0xd7,0xae,0x5d,0xba,0x74,0xe8,0xd1,0xa2,0x44,0x88,0x10,0x21,0x43,
    0x86,0x0d,0x1b,0x36,0x6c,0xd8,0xb1,0x63,0xc7,0x8f,0x1e,0x3c,0x79,0xf3,0xe7,0xce,
    0x9c,0x39,0x73,0xe6,0xcc,0x98,0x31,0x62,0xc5,0x8b,0x16,0x2d,0x5a,0xb4,0x69,0xd2,
    0xa4,0x48,0x91,0x22,0x45,0x8a,0x14,0x29,0x52,0xa5,0x4a,0x95,0x2a,0x54,0xa9,0x53,
    0xa7,0x4e,0x9d,0x3b,0x77,0xee,0xdd,0xbb,0x76,0xec,0xd9,0xb3,0x67,0xcf,0x9e,0x3d,
    0x7b,0xf7,0xef,0xdf,0xbf,0x7e,0xfd,0xfa,0xf4,0xe9,0xd3,0xa6,0x4c,0x99,0x33,0x66,
    0xcd,0x9a,0x35,0x6a,0xd4,0xa8,0x51,0xa3,0x46,0x8c,0x18,0x30,0x60,0xc1,0x83,0x07,
    0x0e,0x1d,0x3a,0x75,0xea,0xd5,0xaa,0x55,0xab,0x57,0xaf,0x5f,0xbe,0x7c,0xf9,0xf2,
    0xe5,0xca,0x94,0x28,0x50,0xa1,0x42,0x84,0x09,0x13,0x27,0x4f,0x9f,0x3f,0x7f,0x00
};

void lora_dewhiten(uint8_t *data, size_t len)
{
    size_t n = len > sizeof(LORA_WHITEN) ? sizeof(LORA_WHITEN) : len;
    for (size_t i = 0; i < n; ++i) data[i] ^= LORA_WHITEN[i];
}

uint16_t lora_gray_decode(uint16_t s) { return (uint16_t)(s ^ (s >> 1)); }
uint16_t lora_gray_encode(uint16_t s)
{
    uint16_t b = s; s >>= 1;
    while (s) { b ^= s; s >>= 1; }
    return b;
}

/* ---- Hamming decode ----------------------------------------------------
 *
 * Original work Copyright 2022 Tapparel Joachim @EPFL,TCL.
 * Modifications Copyright 2026 CEMAXECUTER LLC.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Ported from gr-lora_sdr lib/hamming_dec_impl.cc (hard-decode path).
 *
 * Codeword bit layout (MSB-first in `cw`):
 *     [d0 d1 d2 d3 | p0 p1 p2 p3]
 * with parity formulas:
 *     p0 = d0 ^ d1 ^ d2
 *     p1 = d1 ^ d2 ^ d3
 *     p2 = d0 ^ d1 ^ d3
 *     p3 = d0 ^ d2 ^ d3   (overall parity at CR=4/5)
 *
 * Caller passes `cr` in our 5..8 convention (4/5..4/8); we map to
 * gr-lora_sdr's cr_app = 1..4. */
uint8_t lora_hamming_decode(uint8_t cw, int cr, int *err)
{
    if (err) *err = 0;
    int cr_app = cr - 4;
    if (cr_app < 1) cr_app = 1;
    if (cr_app > 4) cr_app = 4;
    int cw_len = cr_app + 4;

    /* Unpack `cw` into MSB-first bit array of length cw_len. */
    int b[8];
    for (int i = 0; i < cw_len; ++i)
        b[i] = (cw >> (cw_len - 1 - i)) & 1;

    /* Data nibble in MSB-first order: d0..d3 = b[0..3], reversed for output. */
    int d0 = b[0], d1 = b[1], d2 = b[2], d3 = b[3];

    int s0 = 0, s1 = 0, s2 = 0;
    int syndrome = 0;
    switch (cr_app) {
    case 4:
        /* CR=4/8: only correct if odd parity weight. */
        {
            int total = 0;
            for (int i = 0; i < cw_len; ++i) total += b[i];
            if ((total % 2) == 0) break;  /* even parity -- no correction */
        }
        /* fallthrough into syndrome correction */
    case 3:
        s0 = b[0] ^ b[1] ^ b[2] ^ b[4];
        s1 = b[1] ^ b[2] ^ b[3] ^ b[5];
        s2 = b[0] ^ b[1] ^ b[3] ^ b[6];
        syndrome = s0 | (s1 << 1) | (s2 << 2);
        switch (syndrome) {
        case 5: d3 ^= 1; break;
        case 7: d2 ^= 1; break;
        case 3: d1 ^= 1; break;
        case 6: d0 ^= 1; break;
        default: break;
        }
        break;
    case 2:
    case 1:
        /* CR=4/6 / CR=4/5: detect-only, no correction. */
        break;
    }

    /* Output reversed: data_nibble = {d3, d2, d1, d0} per gr-lora_sdr. */
    uint8_t out = (uint8_t)((d3 << 3) | (d2 << 2) | (d1 << 1) | d0);
    return out;
}

uint16_t lora_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0x0000;
    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; ++b)
            crc = (uint16_t)((crc & 0x8000) ? (crc << 1) ^ 0x1021 : (crc << 1));
    }
    return crc;
}

/* ---- Diagonal deinterleave --------------------------------------------
 *
 * Original work Copyright 2022 Tapparel Joachim @EPFL,TCL.
 * Modifications Copyright 2026 CEMAXECUTER LLC.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Ported from gr-lora_sdr lib/deinterleaver_impl.cc (hard-decode path).
 *
 * Treats `symbols[]` as cw_len input symbols of sf_app bits each (MSB-first
 * via int2bool). Diagonal mapping per gr-lora_sdr line 125:
 *   deinter_bin[(i - j - 1) mod sf_app][i] = inter_bin[i][j]
 * Output is sf_app codewords, each cw_len bits packed MSB-first in `codewords[]`. */
static int mod_pos(int x, int m) { int r = x % m; return r < 0 ? r + m : r; }

void lora_deinterleave(const uint16_t *symbols, int sf_app, int cr_use,
                       uint8_t *codewords)
{
    if (cr_use <= 0 || sf_app <= 0) return;
    int cw_len = cr_use;     /* gr-lora_sdr: cw_len = cr_app + 4 = full codeword width */

    /* Unpack input symbols into a 2D bit matrix [cw_len][sf_app] MSB-first. */
    uint8_t inter_bin[16][16];   /* sized for max cw_len=8, sf_app=12 */
    for (int i = 0; i < cw_len; ++i) {
        uint16_t v = symbols[i];
        for (int j = 0; j < sf_app; ++j)
            inter_bin[i][j] = (uint8_t)((v >> (sf_app - 1 - j)) & 1);
    }

    /* Build deinterleaved bit matrix [sf_app][cw_len] via the diagonal map.
     * gr-lora_sdr deinterleaver_impl.cc line 125: deinter_bin[mod((i-j-1), sf_app)][i] = inter_bin[i][j] */
    uint8_t deinter_bin[16][16] = {{0}};
    for (int i = 0; i < cw_len; ++i)
        for (int j = 0; j < sf_app; ++j)
            deinter_bin[mod_pos(i - j - 1, sf_app)][i] = inter_bin[i][j];

    /* Pack each row back into a codeword (MSB-first, cw_len bits). */
    for (int i = 0; i < sf_app; ++i) {
        uint8_t cw = 0;
        for (int j = 0; j < cw_len; ++j)
            cw = (uint8_t)((cw << 1) | deinter_bin[i][j]);
        codewords[i] = cw;
    }
}

/* ---- Decoder state machine ---- */

typedef enum {
    STATE_IDLE,         /* hunting for preamble */
    STATE_PREAMBLE_OK,  /* have N matching upchirps, watching for sync word */
    STATE_HEADER,       /* reading 8 header symbols */
    STATE_PAYLOAD,      /* reading payload codewords */
} lora_state_t;

#define MAX_SF              12
#define MAX_FFT             (1 << MAX_SF)
#define PREAMBLE_MIN        5            /* match >= this many upchirps -> preamble */
#define MAX_PAYLOAD_BYTES   256
#define MAX_PAYLOAD_SYMBOLS 1024
/* Soft-decoding LLR store: one row of sf_app floats per accumulated
 * payload symbol. sf_app peaks at sf (=12 for SF12 non-LDRO). Pre-
 * dimension to 12 for simplicity even when the active sf_app is smaller. */
#define LLR_PER_SYMBOL      MAX_SF

struct lora_decoder {
    int  sf;
    int  cr;          /* coding rate denominator (5..8) */
    int  bw_hz;
    int  N;           /* 2^SF -- FFT size and samples per symbol */

    /* Precomputed reference chirps. */
    fftwf_complex *downchirp;   /* conjugate of upchirp -- for symbol decode */
    fftwf_complex *upchirp;     /* for sync-word verification */

    /* FFT plan + buffers. */
    fftwf_complex *fft_in;
    fftwf_complex *fft_out;
    fftwf_plan     fft_plan;

    /* Sample accumulator (one symbol's worth). */
    float complex *symbuf;
    int            symbuf_count;

    /* State machine. */
    lora_state_t state;
    int          preamble_count;
    int          preamble_bin;       /* bin we're tracking */
    int          sto_skip_remaining; /* gr-lora_sdr-style k_hat realignment after preamble lock */
    uint16_t     header_syms[8];
    int          header_idx;

    /* Carrier frequency offset compensation (gr-lora_sdr frame_sync_impl.cc).
     * cfo_int  : integer-bin offset, derived from dechirped downchirp peak.
     * cfo_frac : sub-bin phase rate, derived from preamble FFT phase delta.
     * cfo_phase: running phase accumulator for the per-sample correction
     *            ramp e^{-j*2*pi*cfo_frac*n/N}. */
    int          cfo_int;
    float        cfo_frac;
    double       cfo_phase;
    /* Snapshot of the last few preamble FFTs at preamble_bin, for
     * cfo_frac estimation via 1st-difference autocorrelation. Stored
     * pre-CFO-frac correction. */
    float complex preamble_fft_hist[8];
    int          preamble_fft_count;
    /* Downchirp samples captured during STATE_HEADER for cfo_int derivation:
     * we need to dechirp 1 of the 2 raw downchirps with our REFERENCE
     * upchirp (not downchirp) to find down_val = peak bin. */
    float complex downchirp_buf[MAX_FFT];
    /* Header fields (set on header decode success). */
    int          payload_len;
    int          payload_cr;
    bool         payload_has_crc;
    bool         payload_ldro;            /* Low-Data-Rate Optimization on payload */
    /* Leftover payload nibbles from the header deinterleave block
     * (positions 5..sf_app-1; first 5 were the header). */
    uint8_t      hdr_leftover[16];
    int          hdr_leftover_count;
    /* Payload accumulator (hard decode path). */
    uint16_t     payload_syms[MAX_PAYLOAD_SYMBOLS];
    int          payload_sym_count;
    int          payload_sym_target;   /* total payload symbols expected */

    /* Soft-decision decoding accumulators (when MESHTASTIC_LORA_SOFT=1).
     * Each row is sf_app floats, MSB-first; sign indicates the most-
     * likely bit (positive=1, negative=0), magnitude is the confidence.
     * Header stage stores 8 rows of header-block LLRs at sf_app=sf-2;
     * payload stage stores up to MAX_PAYLOAD_SYMBOLS rows. */
    bool         soft_decoding;
    float        header_llrs[8][LLR_PER_SYMBOL];
    float        payload_llrs[MAX_PAYLOAD_SYMBOLS][LLR_PER_SYMBOL];

    /* Per-frame metadata, updated as we go. */
    lora_frame_meta_t meta;

    lora_frame_cb_t cb;
    void           *user;
};

/* ---- Reference chirps ----
 *
 * Standard LoRa upchirp at one sample per chirp slope:
 *   up[n] = exp(j * 2*pi * ((n*n)/(2*N) - n/2 + n/(2*N)))   for n=0..N-1
 * (continuous chirp from -BW/2 to +BW/2 over N samples)
 *
 * The downchirp for dechirping is the complex conjugate. */
static void build_chirps(fftwf_complex *up, fftwf_complex *down, int N)
{
    /* Reference chirp formula matches gr-lora_sdr utilities.h
     * `build_upchirp(chirp, 0, sf)`:
     *     phi[n] = 2*pi * (n*n/(2N) - n/2)
     * The earlier `n*(n-1)/(2N)` discrete-integral form differs by
     * pi*n/N -- a 0.5-bin/sample frequency offset that lands payload
     * peaks at v+0.5, where the argmax randomly picks bin v or v+1. */
    float complex *u = (float complex *)up;
    float complex *d = (float complex *)down;
    for (int n = 0; n < N; ++n) {
        double phase = 2.0 * M_PI * ((double)n * (double)n / (2.0 * (double)N) - (double)n * 0.5);
        u[n] = (float)cos(phase) + I * (float)sin(phase);
        d[n] = conjf(u[n]);
    }
}

lora_decoder_t *lora_decoder_create(int sf, int cr, int bw_hz)
{
    if (sf < 7 || sf > 12 || cr < 5 || cr > 8 || bw_hz <= 0) return NULL;
    lora_decoder_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->sf = sf; d->cr = cr; d->bw_hz = bw_hz;
    d->N  = 1 << sf;

    d->downchirp = fftwf_alloc_complex(d->N);
    d->upchirp   = fftwf_alloc_complex(d->N);
    d->fft_in    = fftwf_alloc_complex(d->N);
    d->fft_out   = fftwf_alloc_complex(d->N);
    d->symbuf    = malloc(sizeof(float complex) * (size_t)d->N);
    if (!d->downchirp || !d->upchirp || !d->fft_in || !d->fft_out || !d->symbuf) {
        lora_decoder_destroy(d);
        return NULL;
    }
    build_chirps(d->upchirp, d->downchirp, d->N);

    /* FFTW plan creation is not thread-safe even with FFTW_ESTIMATE. */
    fftw_planner_lock();
    d->fft_plan = fftwf_plan_dft_1d(d->N, d->fft_in, d->fft_out,
                                    FFTW_FORWARD, FFTW_ESTIMATE);
    fftw_planner_unlock();
    if (!d->fft_plan) { lora_decoder_destroy(d); return NULL; }

    d->state = STATE_IDLE;
    d->meta.sf = sf; d->meta.cr = cr; d->meta.bw_hz = bw_hz;
    /* Optional soft-decision decoding. Off by default because it costs ~50KB
     * extra LLR storage per decoder and only matters near the SNR floor;
     * enable explicitly with MESHTASTIC_LORA_SOFT=1 in the env. */
    {
        const char *e = getenv("MESHTASTIC_LORA_SOFT");
        d->soft_decoding = (e && *e == '1');
    }
    return d;
}

void lora_decoder_set_callback(lora_decoder_t *d, lora_frame_cb_t cb, void *user)
{
    if (!d) return;
    d->cb = cb; d->user = user;
}

void lora_decoder_destroy(lora_decoder_t *d)
{
    if (!d) return;
    if (d->fft_plan) {
        fftw_planner_lock();
        fftwf_destroy_plan(d->fft_plan);
        fftw_planner_unlock();
    }
    fftwf_free(d->downchirp);
    fftwf_free(d->upchirp);
    fftwf_free(d->fft_in);
    fftwf_free(d->fft_out);
    free(d->symbuf);
    free(d);
}

/* ---- DSP helpers ---- */

/* Dechirp + FFT one symbol's worth (N) of samples.  Returns the
 * argmax bin (the symbol value). Also fills *peak_mag and *noise_mag
 * for SNR estimation if non-NULL. If `bin_capture` is non-NULL and
 * `capture_bin` is in [0, N), stores the complex FFT value at that
 * bin so the caller can do CFO_frac estimation from successive
 * preamble FFTs. */
static uint16_t demod_one_symbol_full(lora_decoder_t *d,
                                      const float complex *s,
                                      float *peak_mag, float *noise_mag,
                                      int capture_bin, float complex *bin_capture)
{
    /* Multiply by downchirp (s[n] * conj(upchirp[n])) */
    float complex *fft_in_c  = (float complex *)d->fft_in;
    float complex *fft_out_c = (float complex *)d->fft_out;
    float complex *down_c    = (float complex *)d->downchirp;
    for (int n = 0; n < d->N; ++n)
        fft_in_c[n] = s[n] * down_c[n];
    fftwf_execute(d->fft_plan);

    float best = 0.0f; int best_bin = 0;
    double sum = 0.0;
    for (int k = 0; k < d->N; ++k) {
        float r = crealf(fft_out_c[k]), im = cimagf(fft_out_c[k]);
        float p = r * r + im * im;
        sum += (double)p;
        if (p > best) { best = p; best_bin = k; }
    }
    if (peak_mag)  *peak_mag  = sqrtf(best);
    if (noise_mag) {
        double avg = (sum - (double)best) / (double)(d->N - 1);
        *noise_mag = (float)sqrt(avg > 0.0 ? avg : 0.0);
    }
    if (bin_capture && capture_bin >= 0 && capture_bin < d->N)
        *bin_capture = fft_out_c[capture_bin];
    return (uint16_t)best_bin;
}

static inline uint16_t demod_one_symbol(lora_decoder_t *d,
                                        const float complex *s,
                                        float *peak_mag, float *noise_mag)
{
    return demod_one_symbol_full(d, s, peak_mag, noise_mag, -1, NULL);
}

/* Dechirp samples with the UPCHIRP reference (instead of downchirp) to demod
 * a downchirp symbol; returns argmax bin. Used during sync to derive the
 * CFO_int estimate per gr-lora_sdr frame_sync_impl.cc:607
 *     down_val = get_symbol_val(symb_corr, m_upchirp). */
static int demod_downchirp_argmax(lora_decoder_t *d, const float complex *s)
{
    float complex *fft_in_c  = (float complex *)d->fft_in;
    float complex *fft_out_c = (float complex *)d->fft_out;
    float complex *up_c      = (float complex *)d->upchirp;
    for (int n = 0; n < d->N; ++n)
        fft_in_c[n] = s[n] * up_c[n];
    fftwf_execute(d->fft_plan);
    float best = 0.0f; int best_bin = 0;
    for (int k = 0; k < d->N; ++k) {
        float r = crealf(fft_out_c[k]), im = cimagf(fft_out_c[k]);
        float p = r * r + im * im;
        if (p > best) { best = p; best_bin = k; }
    }
    return best_bin;
}

/* Apply CFO correction to the reference downchirp.
 *
 * gr-lora_sdr utilities.h `build_upchirp(chirp, id, sf)`:
 *   for n < (N - id):   chirp[n] = exp(j*2*pi*(n^2/(2N) + (id/N - 0.5)*n))
 *   for n >= (N - id):  chirp[n] = exp(j*2*pi*(n^2/(2N) + (id/N - 1.5)*n))
 * The fold (the second branch) is a subtraction of 2*pi*n -- effectively
 * one full phase wrap -- so the chirp stays in the [-bw/2, +bw/2] band
 * after rolling over. Re-implementing this exactly matters because the
 * naive `up[n] * exp(j*2*pi*cfo_int*n/N)` form doesn't handle the wrap
 * and leaves a 1-bit slope error in the corrected reference. After the
 * cfo_int build, conjugate to get the downchirp and multiply by the
 * cfo_frac phase ramp e^{-j*2*pi*cfo_frac/N * n}. */
static void apply_cfo_correction(lora_decoder_t *d)
{
    float complex *u    = (float complex *)d->upchirp;
    float complex *down = (float complex *)d->downchirp;
    int id = d->cfo_int;
    int n_fold_i = d->N - id;  /* may be negative for negative cfo_int */
    double inv_N = 1.0 / (double)d->N;
    for (int n = 0; n < d->N; ++n) {
        double offset = (n < n_fold_i)
            ? ((double)id * inv_N - 0.5)
            : ((double)id * inv_N - 1.5);
        double phase = 2.0 * M_PI * ((double)n * (double)n * 0.5 * inv_N + offset * (double)n);
        float complex up_n = (float complex)(cos(phase) + I * sin(phase));
        u[n] = up_n;
        double frac_phase = -2.0 * M_PI * (double)d->cfo_frac * (double)n * inv_N;
        float complex frac_tw = (float complex)(cos(frac_phase) + I * sin(frac_phase));
        down[n] = conjf(up_n) * frac_tw;
    }
}

/* ---- Soft-decision LLR computation ----
 *
 * Original work Copyright 2022 Tapparel Joachim @EPFL,TCL.
 * Modifications Copyright 2026 CEMAXECUTER LLC.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Ported from gr-lora_sdr fft_demod_impl.cc:get_LLRs (max-log
 * approximation only; we skip the Bessel-function path because it
 * matters only for very high SNR, which is also where hard-decode
 * already wins). For each FFT bin n, treat |Y[n]|^2 as the bin
 * likelihood. For each output bit i in [0, sf_app):
 *     LLR[i] = max_{n where bit_i(symbol(n)) == 1} LL[n]
 *            - max_{n where bit_i(symbol(n)) == 0} LL[n]
 * where symbol(n) is the gray-mapped bin value the LoRa modulator
 * would have emitted at FFT bin n -- i.e. apply the same
 *     s = ((n - 1) mod 2^sf) / divider; s ^= (s >> 1)
 * post-processing inline so the LLRs are over the *information* bits
 * not the FFT bins. divider is 4 for header / LDRO, else 1.
 *
 * Output: sf_app LLRs in MSB..LSB order (LLR[0] is the high bit). */
static void compute_symbol_llrs(lora_decoder_t *d,
                                const float complex *s,
                                int sf_app,
                                bool divide_by_4,
                                float *llr_out)
{
    float complex *fft_in_c  = (float complex *)d->fft_in;
    float complex *fft_out_c = (float complex *)d->fft_out;
    float complex *down_c    = (float complex *)d->downchirp;
    for (int n = 0; n < d->N; ++n)
        fft_in_c[n] = s[n] * down_c[n];
    fftwf_execute(d->fft_plan);

    /* Per-bin |Y|^2 as max-log likelihood. */
    static float ll_buf[MAX_FFT];
    for (int k = 0; k < d->N; ++k) {
        float r = crealf(fft_out_c[k]), im = cimagf(fft_out_c[k]);
        ll_buf[k] = r * r + im * im;
    }

    int sf_full = d->sf;
    uint32_t mask_N = (uint32_t)(d->N - 1);
    /* Per output-bit accumulators. sf_app values, indexed 0..sf_app-1
     * where bit position i corresponds to bin's gray-mapped bit i. */
    float max_x1[MAX_SF] = {0};
    float max_x0[MAX_SF] = {0};
    for (int n = 0; n < d->N; ++n) {
        /* Symbol value derived from FFT bin: see fft_demod_impl.cc:218. */
        uint32_t sym_v = ((uint32_t)n - 1u) & mask_N;
        if (divide_by_4) sym_v >>= 2;
        /* gray demap (s ^= s>>1) -- in LoRa, the FFT bin maps to the
         * gray-encoded info value, so XORing in the shifted version
         * reverses the encoding. */
        sym_v = (sym_v ^ (sym_v >> 1u)) & ((1u << sf_app) - 1u);
        float ll = ll_buf[n];
        for (int i = 0; i < sf_app; ++i) {
            if (sym_v & (1u << i)) { if (ll > max_x1[i]) max_x1[i] = ll; }
            else                   { if (ll > max_x0[i]) max_x0[i] = ll; }
        }
    }
    /* gr-lora_sdr stores LLRs in MSB..LSB order: LLRs[sf-1-i] = max_x1[i] - max_x0[i].
     * We store the same way (llr_out[0] is the MSB bit). */
    for (int i = 0; i < sf_app; ++i)
        llr_out[sf_app - 1 - i] = max_x1[i] - max_x0[i];
    (void)sf_full;
}

/* Diagonal soft-deinterleave. Same map as the hard version
 *     (deinter_bin[(i - j - 1) mod sf_app][i] = inter_bin[i][j])
 * but operating on per-bit LLRs instead of bits. Output: sf_app
 * codewords each cw_len LLRs (MSB..LSB). */
static void lora_deinterleave_soft(const float (*sym_llrs)[LLR_PER_SYMBOL],
                                   int sf_app, int cr_use,
                                   float cw_llrs[16][8])
{
    int cw_len = cr_use;
    for (int i = 0; i < sf_app; ++i)
        for (int j = 0; j < cw_len; ++j)
            cw_llrs[i][j] = 0.0f;
    for (int i = 0; i < cw_len; ++i) {
        for (int j = 0; j < sf_app; ++j) {
            int row = (i - j - 1) % sf_app;
            if (row < 0) row += sf_app;
            cw_llrs[row][i] = sym_llrs[i][j];
        }
    }
}

/* Soft Hamming decode for cr 1..4 (CR4/5..4/8). For each of the 16
 * possible information nibbles, compute its codeword (CR4/5 has its
 * own LUT; CR4/6..4/8 share one) and score against the received LLRs.
 * Output: 4-bit nibble in low-LSB-first format matching the hard path. */
static uint8_t lora_hamming_decode_soft(const float *cw_llrs, int cr, int *err)
{
    if (err) *err = 0;
    int cr_app = cr - 4;
    if (cr_app < 1) cr_app = 1;
    if (cr_app > 4) cr_app = 4;
    int cw_len = cr_app + 4;
    static const uint8_t cw_LUT[16]     = {0, 23, 45, 58, 78, 89, 99, 116,
                                          139, 156, 166, 177, 197, 210, 232, 255};
    static const uint8_t cw_LUT_cr5[16] = {0, 24, 40, 48, 72, 80, 96, 120,
                                          136, 144, 160, 184, 192, 216, 232, 240};
    const uint8_t *lut = (cr_app == 1) ? cw_LUT_cr5 : cw_LUT;
    int best = 0; float best_p = -1e30f;
    for (int n = 0; n < 16; ++n) {
        uint8_t code = lut[n] >> (8 - cw_len);
        float p = 0.0f;
        for (int j = 0; j < cw_len; ++j) {
            bool bit = (code >> (cw_len - 1 - j)) & 1;
            float l = cw_llrs[j];
            float a = l < 0 ? -l : l;
            if ((bit && l > 0) || (!bit && l < 0)) p += a;
            else                                   p -= a;
        }
        if (p > best_p) { best_p = p; best = n; }
    }
    /* gr-lora_sdr returns the data-nibble bits LSB-first; match here. */
    uint8_t data_msb_first = cw_LUT[best] >> 4;   /* always cw_LUT (16 nibbles) */
    return (uint8_t)(((data_msb_first & 0x1) << 3) |
                     ((data_msb_first & 0x2) << 1) |
                     ((data_msb_first & 0x4) >> 1) |
                     ((data_msb_first & 0x8) >> 3));
}

/* Run the state machine for one accumulated symbol. */
static void state_tick(lora_decoder_t *d)
{
    float peak = 0.0f, noise = 1.0f;
    /* During preamble lock, also capture the complex FFT bin value at the
     * tracked preamble_bin so we can derive cfo_frac from successive
     * samples' phase delta. Outside PREAMBLE_OK we don't care. */
    float complex preamble_bin_val = 0.0f + 0.0f * I;
    bool capture_preamble = (d->state == STATE_PREAMBLE_OK);
    uint16_t sym = demod_one_symbol_full(d, d->symbuf, &peak, &noise,
        capture_preamble ? d->preamble_bin : -1,
        capture_preamble ? &preamble_bin_val : NULL);

    /* Per-tick state-machine trace -- enable with MESHTASTIC_LORA_TRACE=1 in
     * the env. Useful for cross-validating against gr-lora_sdr's RX. */
    static int trace_check = 0, trace_on = 0, trace_count = 0;
    if (!trace_check) {
        const char *e = getenv("MESHTASTIC_LORA_TRACE");
        trace_on = (e && *e == '1');
        trace_check = 1;
    }
    if (trace_on && trace_count++ < 2000) {
        fprintf(stderr, "[lora] state=%d sym=%u peak=%.2f snr=%.2f\n",
                d->state, sym, peak, peak / (noise > 0 ? noise : 1));
    }

    /* Preamble-detection SNR floor. Without this, silence between frames
     * has every FFT bin == 0, argmax returns bin 0, the "stable bin"
     * counter ticks to PREAMBLE_MIN, and the state machine fakes a
     * preamble lock on quiet samples -- which then mis-syncs onto the
     * actual next frame. Real LoRa preambles have peak >> noise; a 6 dB
     * margin is generous enough to ignore both noise floors and zero
     * input. */
    bool above_floor = (peak > 0.0f) && (peak > 2.0f * (noise > 0.0f ? noise : 1.0f));

    switch (d->state) {
    case STATE_IDLE: {
        /* First detection: latch the bin and start counting consecutive
         * symbols at the same bin (within 1-bin tolerance for CFO). */
        if (!above_floor) break;
        d->preamble_bin    = (int)sym;
        d->preamble_count  = 1;
        d->preamble_fft_count = 0;
        d->cfo_int         = 0;
        d->cfo_frac        = 0.0f;
        d->state           = STATE_PREAMBLE_OK;
        break;
    }
    case STATE_PREAMBLE_OK: {
        if (!above_floor) {
            /* Lost the signal -- back to hunting. */
            d->state = STATE_IDLE;
            d->preamble_count = 0;
            d->preamble_fft_count = 0;
            break;
        }
        int diff = abs((int)sym - d->preamble_bin);
        /* Account for FFT wrap-around. */
        if (diff > d->N / 2) diff = d->N - diff;
        if (diff <= 1) {
            /* Still on preamble. Cap count so we're ready to detect sync. */
            if (d->preamble_count < PREAMBLE_MIN + 4) d->preamble_count++;
            /* Snapshot the FFT bin value for cfo_frac estimation later. */
            int N_HIST = (int)(sizeof(d->preamble_fft_hist) / sizeof(d->preamble_fft_hist[0]));
            if (d->preamble_fft_count < N_HIST)
                d->preamble_fft_hist[d->preamble_fft_count++] = preamble_bin_val;
        } else if (d->preamble_count >= PREAMBLE_MIN) {
            /* Bin shifted significantly after we had a confirmed preamble:
             * this is the first sync-word symbol. Treat it as such -- skip
             * 1 more sync + ~3 downchirp symbols, then start the header.
             *
             * Sample-grid alignment (STO): k_hat = preamble_bin is the
             * residual offset between our FFT windows and the modulator's
             * symbol grid (gr-lora_sdr frame_sync_impl.cc:538). To realign,
             * drop the next (N - k_hat) samples before processing more
             * symbols -- this puts the next FFT exactly on a symbol
             * boundary. Without this, header symbols decode to garbage
             * because each window straddles two adjacent chirps. */
            d->header_idx = 0;
            d->state      = STATE_HEADER;
            int k_hat = d->preamble_bin;
            if (k_hat < 0) k_hat = 0;
            if (k_hat >= d->N) k_hat = 0;
            d->sto_skip_remaining = (d->N - k_hat) % d->N;

            /* CFO_frac estimate from the captured preamble FFT bin values:
             * gr-lora_sdr frame_sync_impl.cc:241-243 form -- accumulate
             *    four_cum += fft[i] * conj(fft[i+1])
             * over successive preamble symbols at the locked bin, then
             *    cfo_frac = -arg(four_cum) / (2*pi)
             * which gives the fractional-bin frequency offset in cycles
             * per N samples. */
            float complex four_cum = 0.0f + 0.0f * I;
            for (int i = 0; i + 1 < d->preamble_fft_count; ++i) {
                four_cum += d->preamble_fft_hist[i] *
                            conjf(d->preamble_fft_hist[i + 1]);
            }
            if (cabsf(four_cum) > 0.0f) {
                d->cfo_frac = (float)(-atan2((double)cimagf(four_cum),
                                             (double)crealf(four_cum)) /
                                      (2.0 * M_PI));
            } else {
                d->cfo_frac = 0.0f;
            }

            /* After realignment the symbol grid restarts at bin 0, so
             * subsequent CFO compensation should subtract 0 not preamble_bin. */
            d->preamble_bin = 0;
        } else {
            d->state = STATE_IDLE;
            d->preamble_count = 0;
        }
        break;
    }
    case STATE_HEADER: {
        /* On entry: state=1 consumed the first sync-word symbol AND we did
         * a (N - k_hat) STO skip. Now we drop the 2nd sync + 2 downchirps
         * (3 ticks), then need ONE more time the 0.25-symbol "quarter
         * downchirp" tail before header. We schedule a 512-sample skip
         * after header_idx reaches 3 to absorb that quarter chirp. */
        if (d->header_idx < 3) {
            /* Tick 1 = sync2 (upchirp), tick 2 = down1, tick 3 = down2.
             * On the down1 tick, demod the *downchirp* by multiplying with
             * our upchirp reference (dechirping it backwards) -- the argmax
             * of that FFT gives gr-lora_sdr's `down_val`, which encodes
             * 2*cfo_int with a sign convention based on which half of N it
             * lands in (frame_sync_impl.cc:613-621). One downchirp is
             * enough; we use the first to leave room for the quarter-chirp
             * timing. */
            if (d->header_idx == 1) {
                int down_val = demod_downchirp_argmax(d, d->symbuf);
                if ((uint32_t)down_val < (uint32_t)(d->N / 2))
                    d->cfo_int = down_val / 2;
                else
                    d->cfo_int = (down_val - d->N) / 2;
                /* Now rebuild the downchirp reference with cfo_int + cfo_frac
                 * applied. Subsequent header + payload FFTs dechirp through
                 * this corrected reference and the CFO is cancelled. */
                apply_cfo_correction(d);
                if (trace_on)
                    fprintf(stderr, "[lora] cfo_int=%d cfo_frac=%.4f (down_val=%d)\n",
                            d->cfo_int, (double)d->cfo_frac, down_val);
            }
            d->header_idx++;
            if (d->header_idx == 3) {
                /* Just consumed sync2 + down1 + down2; queue the 0.25-symbol
                 * quarter-downchirp skip before reading header. */
                d->sto_skip_remaining += d->N / 4;
            }
            break;
        }
        int hi = d->header_idx - 3;
        if (hi < 8) {
            int sf_app_h = d->sf - 2;
            if (sf_app_h < 5) sf_app_h = 5;
            if (d->soft_decoding) {
                /* In soft mode we keep per-bit LLRs; the gray demap and
                 * (raw-1) shift are folded into compute_symbol_llrs. */
                compute_symbol_llrs(d, d->symbuf, sf_app_h, true,
                                    d->header_llrs[hi]);
            } else {
                /* gr-lora_sdr fft_demod_impl.cc:313 + gray_mapping_impl.cc:70:
                 *   raw       = (bin - 1) mod 2^sf
                 *   demod_out = raw / 4   (header / LDRO mode -- DE)
                 *   gray      = demod_out ^ (demod_out >> 1)
                 * (preamble_bin is 0 after STO realignment / CFO compensation
                 * has been applied to the downchirp reference.) */
                int corr = ((int)sym - d->preamble_bin) % d->N;
                if (corr < 0) corr += d->N;
                uint16_t demod_out = (uint16_t)(corr / 4);
                uint16_t gray = (uint16_t)(demod_out ^ (demod_out >> 1));
                d->header_syms[hi] = gray;
            }
            ++d->header_idx;
        }
        if (d->header_idx == 3 + 8) {
            /* Decode header per gr-lora_sdr header_decoder_impl.cc:
             *   - sf_app = sf-2 (header always uses reduced-rate)
             *   - cr_hdr = 8 (header always 4/8)
             *   - Output 5 nibbles of header + (sf_app-5) leftover payload nibbles.
             * Original work Copyright 2022 Tapparel Joachim @EPFL,TCL.
             * Modifications Copyright 2026 CEMAXECUTER LLC.
             * SPDX-License-Identifier: GPL-3.0-or-later */
            uint8_t cw[16];
            int sf_app = d->sf - 2;
            int cr_hdr = 8;
            if (sf_app < 5) sf_app = 5;
            uint8_t n[16];
            if (d->soft_decoding) {
                float cw_llrs[16][8];
                lora_deinterleave_soft((const float (*)[LLR_PER_SYMBOL])d->header_llrs,
                                       sf_app, cr_hdr, cw_llrs);
                for (int k = 0; k < sf_app; ++k) {
                    int err = 0;
                    n[k] = lora_hamming_decode_soft(cw_llrs[k], cr_hdr, &err);
                }
            } else {
                lora_deinterleave(d->header_syms, sf_app, cr_hdr, cw);
                for (int k = 0; k < sf_app; ++k) {
                    int err = 0;
                    n[k] = lora_hamming_decode(cw[k], cr_hdr, &err);
                }
            }

            /* gr-lora_sdr header_decoder_impl.cc:133-145
             *   payload_len = (n[0] << 4) | n[1]
             *   has_crc     =  n[2] & 1
             *   cr (1..4)   =  n[2] >> 1
             *   header_chk  = ((n[3] & 1) << 4) | n[4]
             * plus checksum c4..c0 over n[0..2] (omitted here -- not yet validated). */
            d->payload_len     = (n[0] << 4) | n[1];
            d->payload_has_crc = (n[2] & 0x01) != 0;
            int hdr_cr_app     = (n[2] >> 1) & 0x07;
            d->payload_cr      = (hdr_cr_app >= 1 && hdr_cr_app <= 4) ? (hdr_cr_app + 4) : 5;

            /* Header checksum -- ported verbatim from gr-lora_sdr
             * header_decoder_impl.cc:141-152. The 5-bit checksum c4..c0 is a
             * fixed XOR pattern over n[0..2]; the received check is the low
             * bit of n[3] (high) plus n[4] (low 4 bits). */
            int header_chk = ((n[3] & 1) << 4) | (n[4] & 0x0f);
            int c4 = ((n[0] >> 3) & 1) ^ ((n[0] >> 2) & 1) ^ ((n[0] >> 1) & 1) ^ (n[0] & 1);
            int c3 = ((n[0] >> 3) & 1) ^ ((n[1] >> 3) & 1) ^ ((n[1] >> 2) & 1) ^ ((n[1] >> 1) & 1) ^ (n[2] & 1);
            int c2 = ((n[0] >> 2) & 1) ^ ((n[1] >> 3) & 1) ^ (n[1] & 1) ^ ((n[2] >> 3) & 1) ^ ((n[2] >> 1) & 1);
            int c1 = ((n[0] >> 1) & 1) ^ ((n[1] >> 2) & 1) ^ (n[1] & 1) ^ ((n[2] >> 2) & 1) ^ ((n[2] >> 1) & 1) ^ (n[2] & 1);
            int c0 = (n[0] & 1) ^ ((n[1] >> 1) & 1) ^ ((n[2] >> 3) & 1) ^ ((n[2] >> 2) & 1) ^ ((n[2] >> 1) & 1) ^ (n[2] & 1);
            int computed_chk = (c4 << 4) | (c3 << 3) | (c2 << 2) | (c1 << 1) | c0;

            d->meta.payload_len    = d->payload_len;
            d->meta.has_crc        = d->payload_has_crc;
            d->meta.header_crc_ok  = (computed_chk == header_chk) && d->payload_len > 0;
            if (!d->meta.header_crc_ok) {
                if (trace_on)
                    fprintf(stderr, "[lora] header CRC fail: got 0x%02x want 0x%02x "
                            "n=%x %x %x %x %x len=%d cr=%d crc=%d\n",
                            header_chk, computed_chk,
                            n[0], n[1], n[2], n[3], n[4],
                            d->payload_len, d->payload_cr, d->payload_has_crc);
                d->state = STATE_IDLE;
                d->preamble_count = 0;
                break;
            }
            /* Stash leftover header-block nibbles (positions 5..sf_app-1)
             * -- these are the first nibbles of the actual payload. */
            d->hdr_leftover_count = 0;
            for (int k = 5; k < sf_app && d->hdr_leftover_count < (int)sizeof(d->hdr_leftover); ++k)
                d->hdr_leftover[d->hdr_leftover_count++] = n[k];
            if (trace_on) {
                fprintf(stderr, "[lora] HEADER: nibbles=%x %x %x %x %x | len=%d cr=%d crc=%d | sym_target=will_compute\n",
                        n[0], n[1], n[2], n[3], n[4],
                        d->payload_len, d->payload_cr, d->payload_has_crc);
            }

            /* Low-Data-Rate Optimization (LDRO): per the LoRa spec, when the
             * symbol duration exceeds ~16 ms the payload uses sf-2 application
             * bits per symbol (same as the header) so each symbol covers more
             * time and is robust to clock drift. Auto-detect via the canonical
             * 16ms threshold (gr-lora_sdr lora_rx.py uses LDRO_MAX_DURATION_MS
             * = 16). For SF12@125kHz this fires (32.8ms > 16ms); for
             * SF11@250kHz it does not (8.2ms). */
            d->payload_ldro = ((double)(1 << d->sf) * 1000.0 / (double)d->bw_hz) > 16.0;

            /* Total payload symbol count (gr-lora_sdr frame_sync_impl.cc:419):
             *   m_symb_numb = ceil((2*pay_len - sf + 2 + 5 + crc*4)
             *                       / (sf - 2*ldro)) * (4 + cr)
             * The numerator uses full sf regardless of ldro; the denominator
             * uses sf-2 when ldro is on (matches gr-lora_sdr exactly). */
            int crc_bits = d->payload_has_crc ? 4 : 0;
            int denom = d->sf - (d->payload_ldro ? 2 : 0);
            int numer = 2 * d->payload_len - d->sf + 2 + 5 + crc_bits;
            if (numer < 0) numer = 0;
            int payload_symbol_count = (int)ceil((double)numer / (double)denom) * d->payload_cr;
            if (payload_symbol_count < 0) payload_symbol_count = 0;
            if (payload_symbol_count > MAX_PAYLOAD_SYMBOLS) payload_symbol_count = MAX_PAYLOAD_SYMBOLS;

            d->payload_sym_target = payload_symbol_count;
            d->payload_sym_count  = 0;
            d->state              = STATE_PAYLOAD;
            if (trace_on) fprintf(stderr, "[lora] payload_sym_target = %d\n", payload_symbol_count);

            if (d->payload_sym_target == 0) {
                /* Empty payload -> deliver immediately as just-header. */
                if (d->cb) d->cb(NULL, 0, &d->meta, d->user);
                d->state = STATE_IDLE;
                d->preamble_count = 0;
            }
        }
        break;
    }
    case STATE_PAYLOAD: {
        /* In LDRO mode the payload uses sf-2 application bits per symbol, just
         * like the header, so we divide the (raw - 1) value by 4 the same way
         * fft_demod_impl.cc:313 does for header / LDRO. */
        int sf_p_active = d->payload_ldro ? (d->sf - 2) : d->sf;
        if (d->soft_decoding) {
            if (d->payload_sym_count < MAX_PAYLOAD_SYMBOLS)
                compute_symbol_llrs(d, d->symbuf, sf_p_active, d->payload_ldro,
                                    d->payload_llrs[d->payload_sym_count++]);
        } else {
            int corr = ((int)sym - d->preamble_bin - 1) % d->N;
            if (corr < 0) corr += d->N;
            uint16_t demod_out = d->payload_ldro ? (uint16_t)(corr / 4) : (uint16_t)corr;
            uint16_t gray = lora_gray_decode(demod_out);
            if (d->payload_sym_count < MAX_PAYLOAD_SYMBOLS)
                d->payload_syms[d->payload_sym_count++] = gray;
        }

        if (d->payload_sym_count >= d->payload_sym_target) {
            /* Decode the payload codewords block by block. */
            uint8_t bytes[MAX_PAYLOAD_BYTES];
            int byte_count = 0;
            int sf_p = d->payload_ldro ? (d->sf - 2) : d->sf;
            int cr_p = d->payload_cr;
            /* Carry a pending half-byte across blocks: when sf_p is odd
             * (e.g. SF=11) each block produces an odd number of nibbles
             * and the last one rolls into the start of the next block. */
            int pending_lo = -1;   /* >=0 means we have a half-byte waiting for its hi nibble */
            /* First absorb leftover header-block payload nibbles. */
            for (int k = 0; k < d->hdr_leftover_count && byte_count < MAX_PAYLOAD_BYTES; ++k) {
                uint8_t nib = d->hdr_leftover[k] & 0x0f;
                if (pending_lo < 0) pending_lo = nib;
                else { bytes[byte_count++] = (uint8_t)((nib << 4) | pending_lo); pending_lo = -1; }
            }
            for (int blk = 0; blk + cr_p <= d->payload_sym_count; blk += cr_p) {
                uint8_t cw_hard[16];
                float   cw_soft[16][8];
                if (d->soft_decoding) {
                    lora_deinterleave_soft(
                        (const float (*)[LLR_PER_SYMBOL])&d->payload_llrs[blk],
                        sf_p, cr_p, cw_soft);
                } else {
                    lora_deinterleave(&d->payload_syms[blk], sf_p, cr_p, cw_hard);
                }
                for (int r = 0; r < sf_p && byte_count < MAX_PAYLOAD_BYTES; ++r) {
                    int err;
                    uint8_t nib = d->soft_decoding
                        ? lora_hamming_decode_soft(cw_soft[r], cr_p, &err)
                        : lora_hamming_decode(cw_hard[r], cr_p, &err);
                    if (pending_lo < 0) {
                        pending_lo = nib;        /* save as low nibble of next byte */
                    } else {
                        bytes[byte_count++] = (uint8_t)((nib << 4) | (pending_lo & 0x0f));
                        pending_lo = -1;
                    }
                }
            }
            int total = d->payload_len + (d->payload_has_crc ? 2 : 0);
            if (byte_count > total) byte_count = total;
            lora_dewhiten(bytes, (size_t)byte_count);

            if (d->payload_has_crc && byte_count >= 2) {
                uint16_t got_crc = (uint16_t)(bytes[byte_count-2] |
                                              ((uint16_t)bytes[byte_count-1] << 8));
                uint16_t want_crc = lora_crc16(bytes, (size_t)(byte_count - 2));
                d->meta.payload_crc_ok = (got_crc == want_crc);
            } else {
                d->meta.payload_crc_ok = !d->payload_has_crc;
            }

            if (trace_on)
                fprintf(stderr, "[lora] DELIVER: %d payload bytes, crc_ok=%d, first 8: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                        d->payload_len, d->meta.payload_crc_ok,
                        bytes[0], bytes[1], bytes[2], bytes[3],
                        bytes[4], bytes[5], bytes[6], bytes[7]);
            if (d->cb) d->cb(bytes, (size_t)d->payload_len, &d->meta, d->user);
            d->state = STATE_IDLE;
            d->preamble_count = 0;
        }
        break;
    }
    }
}

void lora_decoder_feed(lora_decoder_t *d, const float complex *samples, size_t n)
{
    if (!d || !samples) return;
    for (size_t i = 0; i < n; ++i) {
        /* STO realignment: after preamble lock we skip (N - k_hat) samples
         * to land the next FFT window on the modulator's symbol boundary. */
        if (d->sto_skip_remaining > 0) {
            --d->sto_skip_remaining;
            continue;
        }
        d->symbuf[d->symbuf_count++] = samples[i];
        if (d->symbuf_count == d->N) {
            state_tick(d);
            d->symbuf_count = 0;
        }
    }
}
