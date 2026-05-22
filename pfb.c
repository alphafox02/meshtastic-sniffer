/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
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
 */

#include "pfb.h"
#include "fftw_lock.h"

#include <fftw3.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define PFB_OUTBUF_SAMPLES 1024  /* per-bin batching to amortise callback */
#define SINK_RING_N        4     /* buffers per sink in the rotation pool */

/* ---- Async sink-dispatch worker pool --------------------------------
 *
 * Goal: take lora_decoder_feed() (the per-channel demod state machine)
 * off the channelizer/SDR thread. pfb_one_cycle() formerly ran every
 * channel's demod serially via flush_sink() -- so the heavy 250 kHz
 * BW group's 400+ sinks all had to clear before the next FFT cycle.
 *
 * Design: a fixed-size pool of worker threads, channels sharded by
 *   channel_id % n_workers, MPSC queue per worker (multiple PFB groups
 *   can submit concurrently under OMP). Each channel's lora_decoder_t
 *   is touched by exactly one worker, preserving per-channel sample
 *   order without locking inside the decoder.
 *
 * Buffer ownership: each bin_sink_t owns a small ring of identical
 *   outbufs. Producer fills `active`; when full, swaps `active` to the
 *   next free buffer and hands the full one to the owning worker.
 *   Worker runs the cb on it and returns the buffer to the sink's free
 *   list. If the free list is empty (worker behind), producer BLOCKS
 *   until a buffer comes back -- no sample drops.
 *
 * Quiescence: each pfb_t tracks `in_flight` work submitted but not yet
 *   completed. pfb_flush() submits any partial outbufs and waits until
 *   in_flight reaches 0 -- required so file-replay (and the A/B harness)
 *   sees deterministic frame output.
 */

typedef struct bin_sink bin_sink_t;     /* fwd */

typedef struct {
    pfb_emit_cb    cb;
    void          *user;
    int            channel_id;
    float complex *samples;   /* borrowed buffer; returned to sink free list */
    size_t         n;
    bin_sink_t    *sink;      /* for buffer-return + owner pfb decrement */
} sink_work_t;

typedef struct {
    pthread_t        tid;
    int              id;
    pthread_mutex_t  mu;
    pthread_cond_t   not_empty;
    pthread_cond_t   not_full;
    sink_work_t     *ring;
    size_t           cap;
    size_t           head, tail, size;
    _Atomic uint64_t submitted;
    _Atomic uint64_t completed;
    _Atomic uint64_t bp_waits;     /* producer waited because queue was full */
} sink_worker_t;

static struct {
    pthread_mutex_t  init_mu;
    int              initialized;
    int              refcount;       /* live pfb_t count */
    int              n_workers;
    sink_worker_t   *workers;
    _Atomic int      shutdown;
    /* Global counter for per-sink free-buffer pool backpressure (producer
     * blocked because all SINK_RING_N buffers were still in flight at the
     * worker). Distinct from per-worker bp_waits (queue-full backpressure).
     * Either firing in production means workers can't keep up with sample
     * rate -- see MESHTASTIC_PFB_STATS=1. */
    _Atomic uint64_t freebuf_waits;
} g_pool = {
    .init_mu = PTHREAD_MUTEX_INITIALIZER,
};

struct bin_sink {
    int               channel_id;
    pfb_emit_cb       cb;
    void             *user;
    /* Buffer pool -- only the producer mutates active/outbuf_count. */
    float complex    *bufs[SINK_RING_N];
    float complex    *active;
    int               outbuf_count;
    /* Free buffer LIFO, shared between producer (pulls) and workers (push). */
    pthread_mutex_t   free_mu;
    pthread_cond_t    free_cv;
    float complex    *free_stack[SINK_RING_N];
    int               free_top;
    /* Owner pfb (for in_flight bookkeeping + flush signal). */
    pfb_t            *owner;
    /* Linked list of sinks on the same FFT bin (allow multiple sinks). */
    struct bin_sink  *next;
};

struct pfb {
    int               M;
    int               L;
    double            samp_rate;
    /* Polyphase taps: contiguous M*L floats, indexed h_p[i*L + k]. */
    float            *h_p;
    /* Per-branch delay lines: each branch stores a duplicated reverse ring
     * so pfb_one_cycle can dot the newest-to-oldest L samples contiguously.
     * Indexed dly[i*dly_stride + k], with dly_stride = 2*L. */
    float complex    *dly;
    int               dly_stride;
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
    /* Quiescence tracking: incremented when a sink buffer is submitted to
     * a worker, decremented when the worker completes the cb. pfb_flush
     * waits for this to reach 0. */
    pthread_mutex_t   flush_mu;
    pthread_cond_t    flush_cv;
    _Atomic int       in_flight;
};

/* ---- worker pool: lazy init, refcounted teardown ----------------- */

static void *sink_worker_main(void *arg);
static int   verbose_pfb_stats(void);

/* Returns 0 on success, -1 if any allocation or thread spawn fails. On
 * failure all partially-allocated state is freed and g_pool stays in
 * the uninitialised state -- the caller (pfb_create) must propagate the
 * failure so we never sink_submit() into a NULL/zero-worker pool. */
static int g_pool_init_locked(void)
{
    if (g_pool.initialized) return 0;

    int n = 1;
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (nproc > 1) n = (int)(nproc - 1);
    if (n > 16) n = 16;
    const char *env = getenv("MESHTASTIC_SINK_WORKERS");
    if (env && *env) {
        int v = atoi(env);
        if (v >= 1 && v <= 64) n = v;
    }

    sink_worker_t *ws = calloc((size_t)n, sizeof(*ws));
    if (!ws) return -1;

    atomic_store(&g_pool.shutdown, 0);

    int spawned = 0;
    for (int i = 0; i < n; ++i) {
        sink_worker_t *w = &ws[i];
        w->id   = i;
        w->cap  = 256;
        w->ring = calloc(w->cap, sizeof(*w->ring));
        if (!w->ring) goto fail;
        if (pthread_mutex_init(&w->mu, NULL) != 0) {
            free(w->ring); w->ring = NULL;
            goto fail;
        }
        if (pthread_cond_init(&w->not_empty, NULL) != 0) {
            pthread_mutex_destroy(&w->mu);
            free(w->ring); w->ring = NULL;
            goto fail;
        }
        if (pthread_cond_init(&w->not_full, NULL) != 0) {
            pthread_cond_destroy(&w->not_empty);
            pthread_mutex_destroy(&w->mu);
            free(w->ring); w->ring = NULL;
            goto fail;
        }
        if (pthread_create(&w->tid, NULL, sink_worker_main, w) != 0) {
            pthread_cond_destroy(&w->not_full);
            pthread_cond_destroy(&w->not_empty);
            pthread_mutex_destroy(&w->mu);
            free(w->ring); w->ring = NULL;
            goto fail;
        }
        ++spawned;
    }

    g_pool.n_workers   = n;
    g_pool.workers     = ws;
    g_pool.initialized = 1;
    fprintf(stderr, "pfb: sink worker pool started with %d threads\n", n);
    return 0;

fail:
    /* Tell already-spawned threads to exit, then join + free everything. */
    atomic_store(&g_pool.shutdown, 1);
    for (int j = 0; j < spawned; ++j) {
        sink_worker_t *w = &ws[j];
        pthread_mutex_lock(&w->mu);
        pthread_cond_broadcast(&w->not_empty);
        pthread_mutex_unlock(&w->mu);
    }
    for (int j = 0; j < spawned; ++j) {
        sink_worker_t *w = &ws[j];
        pthread_join(w->tid, NULL);
        pthread_cond_destroy(&w->not_full);
        pthread_cond_destroy(&w->not_empty);
        pthread_mutex_destroy(&w->mu);
        free(w->ring);
    }
    free(ws);
    atomic_store(&g_pool.shutdown, 0);
    return -1;
}

static void g_pool_shutdown_locked(void)
{
    if (!g_pool.initialized) return;
    atomic_store(&g_pool.shutdown, 1);
    for (int i = 0; i < g_pool.n_workers; ++i) {
        sink_worker_t *w = &g_pool.workers[i];
        pthread_mutex_lock(&w->mu);
        pthread_cond_broadcast(&w->not_empty);
        pthread_mutex_unlock(&w->mu);
    }
    for (int i = 0; i < g_pool.n_workers; ++i) {
        sink_worker_t *w = &g_pool.workers[i];
        if (w->tid) pthread_join(w->tid, NULL);
        pthread_mutex_destroy(&w->mu);
        pthread_cond_destroy(&w->not_empty);
        pthread_cond_destroy(&w->not_full);
        free(w->ring);
    }
    if (verbose_pfb_stats()) {
        uint64_t tot_sub = 0, tot_done = 0, tot_bp = 0;
        for (int i = 0; i < g_pool.n_workers; ++i) {
            sink_worker_t *w = &g_pool.workers[i];
            uint64_t sub = atomic_load(&w->submitted);
            uint64_t cmp = atomic_load(&w->completed);
            uint64_t bp  = atomic_load(&w->bp_waits);
            tot_sub  += sub;
            tot_done += cmp;
            tot_bp   += bp;
            fprintf(stderr, "pfb sink worker %2d: submitted=%llu completed=%llu bp_waits=%llu\n",
                    i,
                    (unsigned long long)sub,
                    (unsigned long long)cmp,
                    (unsigned long long)bp);
        }
        fprintf(stderr, "pfb sink pool: total submitted=%llu completed=%llu queue_bp=%llu freebuf_waits=%llu\n",
                (unsigned long long)tot_sub,
                (unsigned long long)tot_done,
                (unsigned long long)tot_bp,
                (unsigned long long)atomic_load(&g_pool.freebuf_waits));
    }
    free(g_pool.workers);
    g_pool.workers = NULL;
    g_pool.initialized = 0;
    g_pool.n_workers = 0;
}

/* Stub for an existing-global verbose flag; pfb.c has no external "verbose"
 * symbol of its own, so just key off the env var the rest of the build uses. */
static int verbose_pfb_stats(void)
{
    const char *e = getenv("MESHTASTIC_PFB_STATS");
    return (e && *e && *e != '0');
}

static void sink_submit(bin_sink_t *s, float complex *buf, size_t n);

static void *sink_worker_main(void *arg)
{
    sink_worker_t *w = (sink_worker_t *)arg;
    for (;;) {
        pthread_mutex_lock(&w->mu);
        while (w->size == 0 && !atomic_load(&g_pool.shutdown))
            pthread_cond_wait(&w->not_empty, &w->mu);
        if (w->size == 0) {
            /* shutdown && queue empty */
            pthread_mutex_unlock(&w->mu);
            break;
        }
        sink_work_t work = w->ring[w->head];
        w->head = (w->head + 1) % w->cap;
        w->size--;
        pthread_cond_signal(&w->not_full);
        pthread_mutex_unlock(&w->mu);

        /* Run the per-channel callback (e.g. lora_decoder_feed via
         * pfb_emit_adapter). Single-threaded per channel by sharding. */
        if (work.cb)
            work.cb(work.channel_id, work.samples, work.n, work.user);
        atomic_fetch_add(&w->completed, 1);

        /* Return buffer to the sink's free pool. */
        bin_sink_t *s = work.sink;
        pthread_mutex_lock(&s->free_mu);
        s->free_stack[s->free_top++] = work.samples;
        pthread_cond_signal(&s->free_cv);
        pthread_mutex_unlock(&s->free_mu);

        /* Decrement owner's in_flight; signal pfb_flush waiter if last. */
        pfb_t *owner = s->owner;
        if (atomic_fetch_sub(&owner->in_flight, 1) == 1) {
            pthread_mutex_lock(&owner->flush_mu);
            pthread_cond_signal(&owner->flush_cv);
            pthread_mutex_unlock(&owner->flush_mu);
        }
    }
    return NULL;
}

static void sink_submit(bin_sink_t *s, float complex *buf, size_t n)
{
    sink_worker_t *w = &g_pool.workers[(unsigned)s->channel_id % (unsigned)g_pool.n_workers];

    /* Bump owner's in_flight BEFORE enqueueing -- otherwise pfb_flush
     * could observe in_flight==0 between this enqueue and the worker's
     * post-cb decrement and exit prematurely. */
    atomic_fetch_add(&s->owner->in_flight, 1);

    pthread_mutex_lock(&w->mu);
    while (w->size == w->cap) {
        atomic_fetch_add(&w->bp_waits, 1);
        pthread_cond_wait(&w->not_full, &w->mu);
    }
    w->ring[w->tail] = (sink_work_t){
        .cb         = s->cb,
        .user       = s->user,
        .channel_id = s->channel_id,
        .samples    = buf,
        .n          = n,
        .sink       = s,
    };
    w->tail = (w->tail + 1) % w->cap;
    w->size++;
    atomic_fetch_add(&w->submitted, 1);
    pthread_cond_signal(&w->not_empty);
    pthread_mutex_unlock(&w->mu);
}

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
    p->dly_stride = 2 * L;
    p->dly = calloc((size_t)M * (size_t)p->dly_stride, sizeof(float complex));
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

    pthread_mutex_init(&p->flush_mu, NULL);
    pthread_cond_init(&p->flush_cv, NULL);
    atomic_store(&p->in_flight, 0);

    /* Refcount the shared worker pool; lazy-init on first pfb_t. If init
     * fails we tear down the half-built pfb and refuse -- partially-running
     * async state would cause sink_submit() to hit NULL workers or modulo
     * zero. Better to fail loudly than ship a synchronous-fallback path. */
    pthread_mutex_lock(&g_pool.init_mu);
    int pool_rc = (g_pool.refcount == 0) ? g_pool_init_locked() : 0;
    if (pool_rc == 0) g_pool.refcount++;
    pthread_mutex_unlock(&g_pool.init_mu);
    if (pool_rc != 0) {
        fprintf(stderr, "pfb: sink worker pool init failed; refusing pfb_create\n");
        /* Inline minimal teardown -- we never bumped pool refcount, so
         * don't go through pfb_destroy() (which would decrement). */
        pthread_mutex_destroy(&p->flush_mu);
        pthread_cond_destroy(&p->flush_cv);
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
        return NULL;
    }

    return p;
}

int pfb_register_bin(pfb_t *p, int bin, int channel_id,
                     pfb_emit_cb cb, void *user)
{
    if (!p || bin < 0 || bin >= p->M || !cb) return -1;
    bin_sink_t *s = calloc(1, sizeof(*s));
    if (!s) return -1;
    s->channel_id = channel_id;
    s->cb         = cb;
    s->user       = user;
    s->owner      = p;
    /* Allocate SINK_RING_N output buffers. bufs[0] is the initial active;
     * the rest go on the free stack. Worker returns push back here. */
    for (int i = 0; i < SINK_RING_N; ++i) {
        s->bufs[i] = malloc(sizeof(float complex) * PFB_OUTBUF_SAMPLES);
        if (!s->bufs[i]) {
            for (int j = 0; j < i; ++j) free(s->bufs[j]);
            free(s);
            return -1;
        }
    }
    s->active = s->bufs[0];
    s->free_top = 0;
    for (int i = 1; i < SINK_RING_N; ++i)
        s->free_stack[s->free_top++] = s->bufs[i];
    pthread_mutex_init(&s->free_mu, NULL);
    pthread_cond_init(&s->free_cv, NULL);
    /* Prepend to per-bin sink list. */
    s->next = p->bins[bin];
    p->bins[bin] = s;
    return 0;
}

/* Submit s->active to its owning worker and swap in a fresh buffer.
 * Blocks if the sink's free pool is empty (worker behind). */
static inline void flush_sink(bin_sink_t *s)
{
    if (s->outbuf_count == 0 || !s->cb) {
        s->outbuf_count = 0;
        return;
    }
    float complex *to_submit = s->active;
    size_t n = (size_t)s->outbuf_count;

    /* Acquire a free buffer to become the new active. Backpressure here
     * (free pool empty) means the worker for this channel hasn't caught
     * up; we wait rather than drop samples. Bumped freebuf_waits is the
     * production canary for "demod can't keep up with sample rate". */
    pthread_mutex_lock(&s->free_mu);
    if (s->free_top == 0) {
        atomic_fetch_add(&g_pool.freebuf_waits, 1);
        do { pthread_cond_wait(&s->free_cv, &s->free_mu); }
        while (s->free_top == 0);
    }
    s->active = s->free_stack[--s->free_top];
    pthread_mutex_unlock(&s->free_mu);
    s->outbuf_count = 0;

    sink_submit(s, to_submit, n);
}

static inline void emit_to_bin(pfb_t *p, int bin, float complex y)
{
    bin_sink_t *s = p->bins[bin];
    while (s) {
        s->active[s->outbuf_count++] = y;
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
     * branch's delay line is stored in reverse ring order and duplicated:
     * dly[base + 0..L-1] is always newest-to-oldest for tap k = 0..L-1.
     * This keeps the hot dot product contiguous without a per-cycle copy. */
    int base = (L - w) % L;
    int stride = p->dly_stride;
    for (int i = 0; i < M; ++i) {
        const float *h = &p->h_p[i * L];
        const float *d = (const float *)&p->dly[i * stride + base];
        float acc_re = 0.0f, acc_im = 0.0f;
        for (int k = 0; k < L; ++k) {
            float hk = h[k];
            acc_re += d[2 * k] * hk;
            acc_im += d[2 * k + 1] * hk;
        }
        p->fft_in[i] = acc_re + I * acc_im;
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
        /* Push x into this branch's duplicated reverse ring. */
        int rev = L - 1 - p->dly_w;
        float complex *d = &p->dly[branch * p->dly_stride];
        d[rev] = x;
        d[rev + L] = x;
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
    /* 1. Submit any partial active buffers. */
    for (int b = 0; b < p->M; ++b) {
        bin_sink_t *s = p->bins[b];
        while (s) { flush_sink(s); s = s->next; }
    }
    /* 2. Wait for every in-flight work item belonging to this pfb to
     * complete. Required for file-replay determinism: the A/B harness
     * needs all samples drained through lora_decoder_feed before the
     * process exits, or trailing frames disappear from one run vs the
     * other depending on shutdown timing. */
    pthread_mutex_lock(&p->flush_mu);
    while (atomic_load(&p->in_flight) > 0)
        pthread_cond_wait(&p->flush_cv, &p->flush_mu);
    pthread_mutex_unlock(&p->flush_mu);
}

void pfb_destroy(pfb_t *p)
{
    if (!p) return;
    /* Drain any in-flight work before tearing sinks down -- the workers
     * dereference bin_sink_t in their return path. */
    pfb_flush(p);
    for (int b = 0; b < p->M; ++b) {
        bin_sink_t *s = p->bins[b];
        while (s) {
            bin_sink_t *next = s->next;
            for (int i = 0; i < SINK_RING_N; ++i) free(s->bufs[i]);
            pthread_mutex_destroy(&s->free_mu);
            pthread_cond_destroy(&s->free_cv);
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
    pthread_mutex_destroy(&p->flush_mu);
    pthread_cond_destroy(&p->flush_cv);
    free(p);

    /* Release worker-pool refcount; the last live pfb_t shuts the pool
     * down. We hold init_mu so this race-pairs with pfb_create. */
    pthread_mutex_lock(&g_pool.init_mu);
    if (--g_pool.refcount == 0) g_pool_shutdown_locked();
    pthread_mutex_unlock(&g_pool.init_mu);
}

int    pfb_M(const pfb_t *p)            { return p ? p->M : 0; }
int    pfb_L(const pfb_t *p)            { return p ? p->L : 0; }
double pfb_output_rate(const pfb_t *p)  { return p ? p->samp_rate / (double)p->M : 0.0; }
