/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Significant portions of the bit-level decode (hard-decode Hamming,
 * deinterleave, gray, dewhiten, preamble-mode-vote) are ported from
 * gr-lora_sdr by Joachim Tapparel @ EPFL TCL Lab,
 * https://github.com/tapparelj/gr-lora_sdr (GPL-3.0-or-later).
 * Per-stage citations appear inline at the relevant call sites. CSS
 * demodulation, frame state machine, FFT / CFO handling and integration
 * with the polyphase channelizer are original to this project.
 *
 * meshtastic-sniffer: LoRa CSS demodulator.
 *
 * Stage-by-stage implementation. The DSP path is:
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
 */

#include "lora.h"
#include "fftw_lock.h"

#include <complex.h>
#include <fftw3.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ---- Demod state-machine instrumentation ------------------------------
 *
 * Each decoder reports per-SF counters and (signal/noise) ratios into a
 * single process-global table, accumulated lock-free with atomics. The
 * cost is one atomic_fetch_add per state transition, which is negligible
 * relative to a full N-point FFT per symbol. Dump fires from main.c at
 * shutdown so a soak run produces a self-contained summary on stderr.
 *
 * "Pyramid view": every preamble candidate either decays back to IDLE,
 * locks, or sails through to a sync byte; every sync either fails the
 * 5-bit header checksum or proceeds to payload decode; every payload
 * either has its CRC validated or is published with payload_no_crc.
 * The ratios between adjacent rows are the diagnostic. A healthy real-
 * radio capture has preamble_locks >> sync_seen >> header_pass, and a
 * meaningful crc_pass / crc_fail ratio. A false-positive flood shows
 * many candidates -> few locks, narrow SNR clusters, and ~0 crc_pass.
 */
#define LORA_STATS_SF_MIN     7
#define LORA_STATS_SF_MAX    12
#define LORA_STATS_SF_COUNT  (LORA_STATS_SF_MAX - LORA_STATS_SF_MIN + 1)
/* 2dB-wide buckets from -10..+38 dB plus underflow (bucket 0) / overflow
 * (bucket 25). Anything below -10 or above +38 dB is exotic enough that
 * a single overflow column is fine. */
#define LORA_STATS_SNR_LO_DB  (-10)
#define LORA_STATS_SNR_STEP    2
#define LORA_STATS_SNR_BUCKETS 26

typedef struct {
    atomic_uint_fast64_t preamble_candidates [LORA_STATS_SF_COUNT];
    atomic_uint_fast64_t preamble_locks      [LORA_STATS_SF_COUNT];
    atomic_uint_fast64_t sync_seen           [LORA_STATS_SF_COUNT];
    atomic_uint_fast64_t header_attempts     [LORA_STATS_SF_COUNT];
    atomic_uint_fast64_t header_checksum_pass[LORA_STATS_SF_COUNT];
    atomic_uint_fast64_t header_checksum_fail[LORA_STATS_SF_COUNT];
    atomic_uint_fast64_t payload_attempts    [LORA_STATS_SF_COUNT];
    atomic_uint_fast64_t payload_crc_present [LORA_STATS_SF_COUNT];
    atomic_uint_fast64_t payload_crc_pass    [LORA_STATS_SF_COUNT];
    atomic_uint_fast64_t payload_crc_fail    [LORA_STATS_SF_COUNT];
    atomic_uint_fast64_t payload_no_crc      [LORA_STATS_SF_COUNT];
    atomic_uint_fast64_t published_frames    [LORA_STATS_SF_COUNT];
    atomic_uint_fast64_t snr_hist_preamble [LORA_STATS_SNR_BUCKETS];
    atomic_uint_fast64_t snr_hist_header   [LORA_STATS_SNR_BUCKETS];
    atomic_uint_fast64_t snr_hist_crc_pass [LORA_STATS_SNR_BUCKETS];
    /* Payload-length histogram for CRC pass vs fail, in 30-byte buckets
     * [0-29, 30-59, 60-89, 90-119, 120-149, 150-179, 180-209, 210+]. The
     * "is the payload corruption length-dependent" question becomes
     * directly readable: if pass-buckets weight toward short lengths and
     * fail-buckets toward long lengths, drift accumulates with payload
     * duration. */
    atomic_uint_fast64_t crc_pass_by_len   [8];
    atomic_uint_fast64_t crc_fail_by_len   [8];
} lora_demod_stats_t;

static lora_demod_stats_t g_demod_stats;

static inline int stats_sf_idx(int sf)
{
    if (sf < LORA_STATS_SF_MIN) return -1;
    if (sf > LORA_STATS_SF_MAX) return -1;
    return sf - LORA_STATS_SF_MIN;
}

static inline int stats_snr_bucket(double snr_db)
{
    if (!isfinite(snr_db)) return 0;
    int b = (int)floor((snr_db - LORA_STATS_SNR_LO_DB) / (double)LORA_STATS_SNR_STEP) + 1;
    if (b < 0) b = 0;
    if (b > LORA_STATS_SNR_BUCKETS - 1) b = LORA_STATS_SNR_BUCKETS - 1;
    return b;
}

static inline int stats_paylen_bucket(int payload_len)
{
    if (payload_len < 0) return 0;
    int b = payload_len / 30;
    if (b > 7) b = 7;
    return b;
}

#define STATS_BUMP(field, sf) do { \
        int _i = stats_sf_idx(sf); \
        if (_i >= 0) \
            atomic_fetch_add_explicit(&g_demod_stats.field[_i], 1, memory_order_relaxed); \
    } while (0)

#define STATS_SNR(hist, snr_db) do { \
        int _b = stats_snr_bucket(snr_db); \
        atomic_fetch_add_explicit(&g_demod_stats.hist[_b], 1, memory_order_relaxed); \
    } while (0)

void lora_demod_stats_reset(void)
{
    memset(&g_demod_stats, 0, sizeof(g_demod_stats));
}

static void stats_dump_hist(FILE *fp, const char *label,
                            const atomic_uint_fast64_t *hist)
{
    uint64_t total = 0;
    for (int i = 0; i < LORA_STATS_SNR_BUCKETS; ++i)
        total += atomic_load_explicit(&hist[i], memory_order_relaxed);
    fprintf(fp, "  %-12s n=%-10llu", label, (unsigned long long)total);
    if (total == 0) { fprintf(fp, "  (empty)\n"); return; }
    fprintf(fp, "  [<-10");
    for (int i = 0; i < LORA_STATS_SNR_BUCKETS; ++i) {
        unsigned long long v =
            (unsigned long long)atomic_load_explicit(&hist[i],
                                                     memory_order_relaxed);
        if (i == 0)                          fprintf(fp, " %llu", v);
        else if (i == LORA_STATS_SNR_BUCKETS - 1)
                                             fprintf(fp, " >%d:%llu",
                                                     LORA_STATS_SNR_LO_DB +
                                                     LORA_STATS_SNR_STEP *
                                                     (LORA_STATS_SNR_BUCKETS - 2),
                                                     v);
        else                                 fprintf(fp, " %d:%llu",
                                                     LORA_STATS_SNR_LO_DB +
                                                     LORA_STATS_SNR_STEP * (i - 1),
                                                     v);
    }
    fprintf(fp, "]\n");
}

void lora_demod_stats_dump(FILE *fp)
{
    if (!fp) return;
    /* Sum to detect "nothing ran at all" so we don't spam an empty table.
     * Anything observed (even just preamble candidates above the floor)
     * is worth printing. */
    uint64_t total_candidates = 0;
    for (int i = 0; i < LORA_STATS_SF_COUNT; ++i)
        total_candidates += atomic_load_explicit(
            &g_demod_stats.preamble_candidates[i], memory_order_relaxed);
    if (total_candidates == 0) {
        fprintf(fp, "[demod-stats] no preamble candidates observed.\n");
        return;
    }
    fprintf(fp, "[demod-stats] per-SF counters:\n");
    fprintf(fp, "  %-22s %10s %10s %10s %10s %10s %10s\n",
            "stage", "SF7", "SF8", "SF9", "SF10", "SF11", "SF12");
#define ROW(label, field) do { \
        fprintf(fp, "  %-22s", label); \
        for (int _i = 0; _i < LORA_STATS_SF_COUNT; ++_i) { \
            fprintf(fp, " %10llu", (unsigned long long)atomic_load_explicit( \
                &g_demod_stats.field[_i], memory_order_relaxed)); \
        } \
        fprintf(fp, "\n"); \
    } while (0)
    ROW("preamble_candidates",  preamble_candidates);
    ROW("preamble_locks",       preamble_locks);
    ROW("sync_seen",            sync_seen);
    ROW("header_attempts",      header_attempts);
    ROW("header_checksum_pass", header_checksum_pass);
    ROW("header_checksum_fail", header_checksum_fail);
    ROW("payload_attempts",     payload_attempts);
    ROW("payload_crc_present",  payload_crc_present);
    ROW("payload_crc_pass",     payload_crc_pass);
    ROW("payload_crc_fail",     payload_crc_fail);
    ROW("payload_no_crc",       payload_no_crc);
    ROW("published_frames",     published_frames);
#undef ROW
    fprintf(fp, "[demod-stats] SNR histograms (2dB buckets):\n");
    stats_dump_hist(fp, "preamble",   g_demod_stats.snr_hist_preamble);
    stats_dump_hist(fp, "header_pass",g_demod_stats.snr_hist_header);
    stats_dump_hist(fp, "crc_pass",   g_demod_stats.snr_hist_crc_pass);
    fprintf(fp, "[demod-stats] CRC pass/fail by payload length (30-byte buckets):\n");
    fprintf(fp, "  %-12s %8s %8s %8s %8s %8s %8s %8s %8s\n", "",
            "0-29", "30-59", "60-89", "90-119", "120-149", "150-179", "180-209", "210+");
    fprintf(fp, "  %-12s", "pass");
    for (int i = 0; i < 8; ++i)
        fprintf(fp, " %8llu", (unsigned long long)atomic_load_explicit(
            &g_demod_stats.crc_pass_by_len[i], memory_order_relaxed));
    fprintf(fp, "\n  %-12s", "fail");
    for (int i = 0; i < 8; ++i)
        fprintf(fp, " %8llu", (unsigned long long)atomic_load_explicit(
            &g_demod_stats.crc_fail_by_len[i], memory_order_relaxed));
    fprintf(fp, "\n");
    fflush(fp);
}

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
    int  N;           /* 2^SF -- FFT size; samples per chirp slope unit at bw_hz */
    int  os_factor;   /* input rate / bw_hz; 1 = legacy. >=2 enables fractional STO. */
    int  samples_per_symbol; /* N * os_factor */
    int  sto_offset;  /* integer sub-sample offset 0..os_factor-1 chosen during preamble lock */

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
    /* Running sum + count of dechirped peak magnitudes across matched
     * preamble ticks. Used to detect window-straddle ticks where the
     * argmax bin still lands on the preamble bin but the peak magnitude
     * drops to ~sinc(0.5) of the preamble mean (= the FFT window is
     * straddling the preamble/sync chirp boundary). Such ticks must
     * trigger the sync transition even though their bin matches, or
     * we over-count preamble by one symbol and read the header one
     * symbol late -- the os_factor>=2 SFO=0 baseline failure. */
    double       preamble_peak_sum;
    int          preamble_peak_count;
    /* Set the first time preamble_count crosses PREAMBLE_MIN within one
     * STATE_PREAMBLE_OK run; cleared on every IDLE->PREAMBLE_OK entry.
     * Lets the stats counter record one "lock" per preamble rather than
     * one per symbol while we sit on the locked bin. */
    int          preamble_locked_once;
    int          preamble_bin;       /* bin we're tracking; updated to mode on lock */
    /* Recent preamble bins captured during PREAMBLE_OK, used to compute the
     * mode at lock time (= gr-lora_sdr's `most_frequent(preamb_up_vals)`).
     * The IDLE-entry bin can be off by ±1 due to the FFT peak landing on
     * the noisier early sym; subsequent ticks settle to the true k_hat.
     * Picking the most frequent value matches gr-lora's k_hat exactly,
     * which keeps the (N - k_hat) STO skip aligned to the input sample. */
    int          preamble_bin_hist[16];
    int          preamble_bin_hist_count;
    int          sto_skip_remaining; /* gr-lora_sdr-style k_hat realignment after preamble lock */
    /* One-shot per-symbol consume adjust set by SFO drift code. +1 means
     * the next symbol's FFT window starts 1 sample EARLIER (carry the
     * current symbol's last sample forward across the symbuf reset).
     * -1 means start 1 sample LATER (one extra sto-skip). 0 = no shift. */
    int          sfo_next_sym_shift;
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

    /* SFO/STO sub-bin tracking, gr-lora_sdr frame_sync_impl.cc port.
     * Set via lora_decoder_set_center_freq(); when 0 the SFO compensation
     * paths are inert and the decoder behaves as before. */
    double         center_freq_hz;
    /* Per-payload-symbol drift accumulator (fractional samples). Per gr-lora
     * sfo_cum += sfo_hat; when |sfo_cum| > 1/(2*os_factor), one sample is
     * dropped or added before the next FFT and sfo_cum is decremented by
     * 1/os_factor. */
    double         sfo_cum;
    double         sfo_hat;       /* drift per payload symbol; set at DC2 */
    float          sto_frac;      /* RCTSL sub-bin estimate at lock time */
    /* Rolling buffer of the last K dechirped preamble symbols, used by
     * RCTSL. Allocated when center_freq_hz is set. */
    float complex *preamble_dechirped;
    int            preamble_dechirped_capacity; /* K */
    int            preamble_dechirped_count;
    int            preamble_dechirped_next;     /* next slot to fill (ring) */
    /* 2N-point FFT for RCTSL (zero-padded for sub-bin resolution). */
    fftwf_complex *fft2_in;
    fftwf_complex *fft2_out;
    fftwf_plan     fft2_plan;

    /* Per-frame metadata, updated as we go. */
    lora_frame_meta_t meta;
    /* Running SNR accumulator across the header + payload symbols.
     * dB-domain mean of (peak / noise_floor_avg) per FFT, averaged at
     * frame delivery and written into meta.snr_db. */
    double            snr_db_sum;
    int               snr_db_count;

    /* Frame-sync trace fields (gated by MESHTASTIC_DEBUG_FRAMESYNC env).
     * Behavior-inert when the env flag is unset; only the bookkeeping
     * happens (one int increment per delivered/aborted frame, eight
     * float writes per header). Used for side-by-side comparison with
     * gr-lora_sdr's frame_sync_impl.cc on the same input file. */
    int               framesync_frame_idx;   /* monotonic per-decoder */
    int               framesync_k_hat;       /* preamble mode bin at lock */
    int               framesync_sto_skip;    /* sto_skip set at lock */
    int               framesync_dc2_down_val;
    int               framesync_trim_input;
    int               framesync_header_bins[8];
    float             framesync_header_mags[8];

    lora_frame_cb_t cb;
    void           *user;

    lora_preamble_cb_t preamble_cb;
    void              *preamble_user;

    /* TDOA stream cursor (caller-opaque). Set per feed batch via
     * lora_decoder_set_stream_cursor. samples_in_chunk counts samples
     * passed through this feed batch (both skipped-by-sto and accepted
     * into symbuf). At preamble lock fire, the field
     *     meta.preamble_lock_sample_idx = stream_chunk_anchor +
     *         samples_in_chunk * stream_step_per_sample
     * is stamped on the per-decoder meta struct so the next frame
     * delivered to the frame callback inherits the lock-time anchor. */
    uint64_t stream_chunk_anchor;
    uint32_t stream_step_per_sample;
    uint32_t samples_in_chunk;
};

/* ---- Reference chirps ----
 *
 * Standard LoRa upchirp at one sample per chirp slope:
 *   up[n] = exp(j * 2*pi * ((n*n)/(2*N) - n/2 + n/(2*N)))   for n=0..N-1
 * (continuous chirp from -BW/2 to +BW/2 over N samples)
 *
 * The downchirp for dechirping is the complex conjugate. */

/* Cached one-shot read of MESHTASTIC_DEBUG_FRAMESYNC: when set to "1"
 * the decoder emits per-frame side-by-side-with-gr-lora trace lines
 * tagged "[fs]" on stderr. Unset (default) is a no-op: the env getenv
 * is paid once per process, then a static int gate is consulted. */
static int framesync_enabled(void)
{
    static int cached = -1;
    if (cached < 0) {
        const char *e = getenv("MESHTASTIC_DEBUG_FRAMESYNC");
        cached = (e && e[0] == '1') ? 1 : 0;
    }
    return cached;
}

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
    return lora_decoder_create_os(sf, cr, bw_hz, 1);
}

lora_decoder_t *lora_decoder_create_os(int sf, int cr, int bw_hz, int os_factor)
{
    if (sf < 7 || sf > 12 || cr < 5 || cr > 8 || bw_hz <= 0) return NULL;
    if (os_factor < 1 || os_factor > 16) return NULL;
    lora_decoder_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->sf = sf; d->cr = cr; d->bw_hz = bw_hz;
    d->N  = 1 << sf;
    d->os_factor = os_factor;
    d->samples_per_symbol = d->N * os_factor;

    d->downchirp = fftwf_alloc_complex(d->N);
    d->upchirp   = fftwf_alloc_complex(d->N);
    d->fft_in    = fftwf_alloc_complex(d->N);
    d->fft_out   = fftwf_alloc_complex(d->N);
    d->symbuf    = malloc(sizeof(float complex) * (size_t)d->samples_per_symbol);
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

void lora_decoder_set_stream_cursor(lora_decoder_t *d, uint64_t chunk_anchor,
                                    uint32_t step_per_sample)
{
    if (!d) return;
    d->stream_chunk_anchor    = chunk_anchor;
    d->stream_step_per_sample = step_per_sample;
    d->samples_in_chunk       = 0;
}

void lora_decoder_set_preamble_cb(lora_decoder_t *d, lora_preamble_cb_t cb, void *user)
{
    if (!d) return;
    d->preamble_cb = cb; d->preamble_user = user;
}

/* Number of preamble upchirps to average for the RCTSL estimator. gr-lora_sdr
 * uses (preamble_len - 3); Meshtastic preambles are 8 symbols so 5 fits but
 * 4 is a good compromise that keeps the per-decoder buffer modest at SF12. */
#define PREAMBLE_DECHIRPED_K 4

void lora_decoder_set_center_freq(lora_decoder_t *d, double center_freq_hz)
{
    if (!d) return;
    d->center_freq_hz = center_freq_hz;
    if (center_freq_hz <= 0.0) return;
    /* Lazy-allocate the SFO compensation buffers on first set. */
    if (!d->preamble_dechirped) {
        d->preamble_dechirped_capacity = PREAMBLE_DECHIRPED_K;
        d->preamble_dechirped = calloc((size_t)PREAMBLE_DECHIRPED_K * d->N,
                                       sizeof(float complex));
    }
    if (!d->fft2_in) {
        d->fft2_in  = fftwf_alloc_complex((size_t)2 * d->N);
        d->fft2_out = fftwf_alloc_complex((size_t)2 * d->N);
        if (d->fft2_in && d->fft2_out) {
            fftw_planner_lock();
            d->fft2_plan = fftwf_plan_dft_1d(2 * d->N, d->fft2_in, d->fft2_out,
                                             FFTW_FORWARD, FFTW_ESTIMATE);
            fftw_planner_unlock();
        }
    }
}

void lora_decoder_destroy(lora_decoder_t *d)
{
    if (!d) return;
    if (d->fft_plan) {
        fftw_planner_lock();
        fftwf_destroy_plan(d->fft_plan);
        fftw_planner_unlock();
    }
    if (d->fft2_plan) {
        fftw_planner_lock();
        fftwf_destroy_plan(d->fft2_plan);
        fftw_planner_unlock();
    }
    fftwf_free(d->downchirp);
    fftwf_free(d->upchirp);
    fftwf_free(d->fft_in);
    fftwf_free(d->fft_out);
    if (d->fft2_in)  fftwf_free(d->fft2_in);
    if (d->fft2_out) fftwf_free(d->fft2_out);
    free(d->preamble_dechirped);
    free(d->symbuf);
    free(d);
}

/* ---- DSP helpers ----
 *
 * When os_factor > 1, the symbol buffer holds N*os samples per symbol.
 * Pick N samples with two layers of sub-sample correction for
 * dechirp+FFT.
 *
 * Picks samples at indices os/2 + os*k - phase - fine, k=0..N-1.
 *   phase = d->sto_offset (integer, 0..os-1), chosen by the phase
 *           scan in state_tick at IDLE / first PREAMBLE_OK tick.
 *   fine  = lrintf(sto_frac * os_factor), the per-symbol sub-output-
 *           sample STO correction in INPUT samples. sto_frac is the
 *           RCTSL fractional estimate set at preamble lock
 *           (compute_sto_frac, range [-0.5, +0.5] output samples).
 *           Ports gr-lora_sdr frame_sync_impl.cc:501.
 *
 * For os_factor=1 the early return makes this a memcpy. fine is also
 * 0 there since sto_frac in [-0.5, +0.5] times 1 rounds to 0. */
static inline const float complex *
downsample_symbol(lora_decoder_t *d, const float complex *src, int phase,
                  float complex *scratch)
{
    if (d->os_factor == 1) return src;
    int os = d->os_factor;
    int half = os / 2;
    if (phase < 0) phase = 0;
    if (phase >= os) phase = os - 1;
    /* Sub-output-sample STO correction (gr-lora_sdr frame_sync_impl.cc:501).
     * At os=2: lrint of sto_frac in [-0.5, +0.5] * 2 = {-1, 0, +1} input
     * samples (= ±0.5 output samples). At os=4: {-2, -1, 0, +1, +2}
     * input samples. Without this, the integer phase pick leaves up to
     * 1 input sample of residue at os=2; at SFO-induced fractional
     * symbol-boundary positions that residue manifests as a 1-bin
     * header dechirp shift. */
    /* Continuous in-frame STO tracking: the static RCTSL sto_frac is the
     * timing residual at preamble lock; sfo_cum is the drift accumulated
     * since DC2 (sfo_cum += sfo_hat per symbol, state_tick tail). Folding
     * sfo_cum into the per-symbol fine shift re-centres the dechirp window
     * as the sample clock drifts across the frame -- the static one-shot
     * sto_frac alone leaves the frame tail ~0.4 output samples off at
     * SF9 SFO=25, smearing the last payload symbols off the bin grid.
     *
     * Complementary to the integer-sample carry-back below (not double
     * counting): when the carry-back fires it advances the window +1 input
     * sample AND decrements sfo_cum by 1/os, so this lrint drops by exactly
     * 1 input sample -- net correction stays sto_frac + total_drift either
     * way. At SFO=0 sfo_hat=0 so sfo_cum stays 0 and this is inert. */
    int fine = (int)lrintf((d->sto_frac + (float)d->sfo_cum) * (float)os);
    for (int k = 0; k < d->N; ++k) {
        int idx = half + os * k - phase - fine;
        if (idx < 0) idx = 0;
        if (idx >= d->samples_per_symbol) idx = d->samples_per_symbol - 1;
        scratch[k] = src[idx];
    }
    return scratch;
}

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
    /* CFO-compensated dechirp. Per gr-lora_sdr frame_sync_impl.cc:631-634,
     * CFO compensation lives on the SAMPLE side, not in a mutated chirp
     * reference. We pre-rotate the input by exp(-j*2*pi*cfo_bins*n/N)
     * where cfo_bins = cfo_int + cfo_frac, then dechirp by the CANONICAL
     * downchirp. Mathematically equivalent to mutating the chirp; in
     * practice the chirp-mutation approach didn't actually shift the
     * FFT argmax bin in our pipeline (verified 2026-05-27 via
     * choke-point trace). Sample rotation does. */
    float complex *fft_in_c  = (float complex *)d->fft_in;
    float complex *fft_out_c = (float complex *)d->fft_out;
    float complex *down_c    = (float complex *)d->downchirp;
    double cfo_bins = (double)d->cfo_int + (double)d->cfo_frac;
    if (cfo_bins != 0.0) {
        double k = -2.0 * M_PI * cfo_bins / (double)d->N;
        for (int n = 0; n < d->N; ++n) {
            double ph = k * (double)n;
            float complex rot = (float)cos(ph) + I * (float)sin(ph);
            fft_in_c[n] = s[n] * rot * down_c[n];
        }
    } else {
        for (int n = 0; n < d->N; ++n)
            fft_in_c[n] = s[n] * down_c[n];
    }
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
 *     symb_corr   = in_down * CFO_frac_correc
 *     down_val    = get_symbol_val(symb_corr, m_upchirp)
 * The cfo_frac_correc precondition is critical: without it, residual
 * fractional CFO biases the integer-bin readout of down_val by up to
 * ±1, which then mis-derives cfo_int. */
static int demod_downchirp_argmax(lora_decoder_t *d, const float complex *s)
{
    float complex *fft_in_c  = (float complex *)d->fft_in;
    float complex *fft_out_c = (float complex *)d->fft_out;
    float complex *up_c      = (float complex *)d->upchirp;
    double inv_N = 1.0 / (double)d->N;
    /* Pre-correct cfo_frac (already estimated from preamble) on the input
     * samples before dechirping. Equivalent to gr-lora's symb_corr step. */
    for (int n = 0; n < d->N; ++n) {
        double frac_phase = -2.0 * M_PI * (double)d->cfo_frac * (double)n * inv_N;
        float complex frac_tw = (float complex)(cos(frac_phase) + I * sin(frac_phase));
        fft_in_c[n] = s[n] * frac_tw * up_c[n];
    }
    fftwf_execute(d->fft_plan);
    float best = 0.0f; int best_bin = 0;
    for (int k = 0; k < d->N; ++k) {
        float r = crealf(fft_out_c[k]), im = cimagf(fft_out_c[k]);
        float p = r * r + im * im;
        if (p > best) { best = p; best_bin = k; }
    }
    {
        const char *e = getenv("MESHTASTIC_DEBUG_DUMP_DC2");
        if (e && *e == '1') {
            fprintf(stderr, "[lora] DC2 in: s[0..3]= (%+0.3f%+0.3fi) (%+0.3f%+0.3fi) (%+0.3f%+0.3fi) (%+0.3f%+0.3fi)  up_c[0..3]= (%+0.3f%+0.3fi) (%+0.3f%+0.3fi) (%+0.3f%+0.3fi) (%+0.3f%+0.3fi)\n",
                crealf(s[0]), cimagf(s[0]), crealf(s[1]), cimagf(s[1]),
                crealf(s[2]), cimagf(s[2]), crealf(s[3]), cimagf(s[3]),
                crealf(up_c[0]), cimagf(up_c[0]), crealf(up_c[1]), cimagf(up_c[1]),
                crealf(up_c[2]), cimagf(up_c[2]), crealf(up_c[3]), cimagf(up_c[3]));
            /* Also show second/third peak to see if there's spectral splitting. */
            float p2 = 0; int b2 = 0, p3 = 0, b3 = 0;
            float pf = 0; int bf = 0;
            for (int k = 0; k < d->N; ++k) {
                float r = crealf(fft_out_c[k]), im = cimagf(fft_out_c[k]);
                float p = r*r + im*im;
                if (p > pf && k != best_bin) { pf = p; bf = k; }
            }
            fprintf(stderr, "[lora] DC2 FFT: peak=%d (mag=%.1f), 2nd=%d (mag=%.1f)\n",
                best_bin, sqrtf(best), bf, sqrtf(pf));
        }
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
    /* No-op. CFO correction now lives in demod_one_symbol_full as a
     * per-sample input rotation. The chirp references stay canonical
     * across the frame's lifetime; reset_to_idle still rebuilds them
     * defensively. */
    (void)d;
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
    /* Same per-sample CFO pre-rotation as demod_one_symbol_full so the
     * soft-decode path's LLRs use a properly compensated FFT. */
    double cfo_bins = (double)d->cfo_int + (double)d->cfo_frac;
    if (cfo_bins != 0.0) {
        double k = -2.0 * M_PI * cfo_bins / (double)d->N;
        for (int n = 0; n < d->N; ++n) {
            double ph = k * (double)n;
            float complex rot = (float)cos(ph) + I * (float)sin(ph);
            fft_in_c[n] = s[n] * rot * down_c[n];
        }
    } else {
        for (int n = 0; n < d->N; ++n)
            fft_in_c[n] = s[n] * down_c[n];
    }
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

/* Drop back to STATE_IDLE and zero every per-frame field so a re-entry
 * doesn't carry stale values from the failed/completed frame. Called from
 * every code path that aborts a frame mid-flight (sync-word mismatch,
 * header CRC fail, lost SNR), and after a successful DELIVER. */
static void reset_to_idle(lora_decoder_t *d)
{
    d->state              = STATE_IDLE;
    d->preamble_count     = 0;
    d->preamble_locked_once = 0;
    d->preamble_fft_count = 0;
    d->preamble_bin_hist_count = 0;
    d->preamble_peak_sum  = 0.0;
    d->preamble_peak_count = 0;
    d->header_idx         = 0;
    d->sto_skip_remaining = 0;
    d->hdr_leftover_count = 0;
    d->payload_sym_count  = 0;
    d->payload_sym_target = 0;
    d->payload_ldro       = false;
    d->cfo_int            = 0;
    d->cfo_frac           = 0.0f;
    d->snr_db_sum         = 0.0;
    d->snr_db_count       = 0;
    d->sfo_cum            = 0.0;
    d->sfo_hat            = 0.0;
    d->sto_frac           = 0.0f;
    d->sfo_next_sym_shift = 0;
    d->preamble_dechirped_count = 0;
    d->preamble_dechirped_next  = 0;
    /* Rebuild the chirp references to id=0. apply_cfo_correction
     * (called at DC2) mutates d->upchirp and d->downchirp in place
     * to bake the just-measured cfo_int into the reference. Without
     * rebuilding here, the *next* frame's preamble detection runs
     * against a stale shifted reference -- its FFT peaks land at
     * (true_bin - prev_cfo_int) instead of true_bin, k_hat is wrong,
     * sto_skip is wrong, header symbols decode bit-corrupted.
     * Cross-validated 2026-05-25 against gr-lora_sdr on
     * b205_cluster2.cs8: gr-lora_sdr decoded 4 distinct CRC-valid
     * frames from !433c0b98, our decoder caught the first one cleanly
     * and produced bit-corrupted (CRC-fail) copies of the other three
     * with the drift-across-payload signature -- because the chirp
     * references stayed mutated from the first frame's cfo_int. */
    build_chirps(d->upchirp, d->downchirp, d->N);
}

/* RCTSL (Rational Combined Three Spectral Line) fractional STO estimator.
 *
 * Ported from gr-lora_sdr frame_sync_impl.cc:254-320 (estimate_STO_frac).
 * Algorithm: zero-pad each saved dechirped preamble symbol to 2N samples,
 * FFT it, accumulate per-bin |Y|^2 across all saved symbols, find the
 * argmax k0 across the 2N-point averaged spectrum, then apply the
 * Cui Yang interpolation formula on three adjacent spectral lines:
 *
 *   u = 64*N / 406.5506497
 *   v = u * 2.4674
 *   wa = (Y[+1] - Y[-1]) / ( u*(Y[+1]+Y[-1]) + v*Y[0] )
 *   ka = wa * N / pi
 *   k_residual = ((k0 + ka)/2) mod 1
 *   sto_frac = k_residual - (k_residual > 0.5 ? 1 : 0)
 *
 * Result is in [-0.5, +0.5] -- sub-bin fractional STO offset. Stored on
 * the decoder for downstream use; we don't currently apply it as a
 * sample-shift (would require os_factor>=2). For os_factor=1 channelizer
 * output this still measures the offset so future work can fold it into
 * the FFT phase-rotation path. */
static void compute_sto_frac(lora_decoder_t *d)
{
    if (!d->preamble_dechirped || d->preamble_dechirped_count == 0 ||
        !d->fft2_plan) {
        d->sto_frac = 0.0f;
        return;
    }
    const int N  = d->N;
    const int M2 = 2 * N;
    /* Accumulate |Y|^2 across saved symbols. */
    static double mag_sq[2 * MAX_FFT];
    for (int j = 0; j < M2; ++j) mag_sq[j] = 0.0;
    for (int s = 0; s < d->preamble_dechirped_count; ++s) {
        const float complex *sym = &d->preamble_dechirped[(size_t)s * N];
        float complex *in = (float complex *)d->fft2_in;
        for (int i = 0; i < N;  ++i) in[i] = sym[i];
        for (int i = N; i < M2; ++i) in[i] = 0.0f + 0.0f * I;
        fftwf_execute(d->fft2_plan);
        const float complex *out = (const float complex *)d->fft2_out;
        for (int j = 0; j < M2; ++j) {
            float r = crealf(out[j]), im = cimagf(out[j]);
            mag_sq[j] += (double)(r * r + im * im);
        }
    }
    /* argmax */
    int k0 = 0;
    double peak = mag_sq[0];
    for (int j = 1; j < M2; ++j) {
        if (mag_sq[j] > peak) { peak = mag_sq[j]; k0 = j; }
    }
    /* Three spectral lines (wrap-around). */
    double Y_1 = mag_sq[(k0 - 1 + M2) % M2];
    double Y0  = mag_sq[k0];
    double Y1  = mag_sq[(k0 + 1) % M2];
    double u = 64.0 * (double)N / 406.5506497;
    double v = u * 2.4674;
    double denom = u * (Y1 + Y_1) + v * Y0;
    double wa = (denom != 0.0) ? (Y1 - Y_1) / denom : 0.0;
    double ka = wa * (double)N / M_PI;
    double k_residual = fmod(((double)k0 + ka) / 2.0, 1.0);
    if (k_residual < 0) k_residual += 1.0;
    d->sto_frac = (float)(k_residual - (k_residual > 0.5 ? 1.0 : 0.0));
}

/* Run the state machine for one accumulated symbol. */
static void state_tick(lora_decoder_t *d)
{
    /* Scratch for the downsampled symbol when os_factor>1. */
    static float complex scratch[MAX_FFT];
    /* During IDLE/PREAMBLE_OK, search across all sub-sample phases and
     * pick the one with the strongest peak. This is the integer-step
     * fractional-STO recovery that gr-lora_sdr does internally. Once
     * a preamble is locked we stick with the chosen sto_offset for the
     * rest of the frame. */
    if (d->os_factor > 1 &&
        (d->state == STATE_IDLE ||
         (d->state == STATE_PREAMBLE_OK && !d->preamble_locked_once))) {
        float best_peak = -1.0f;
        int   best_phase = 0;
        for (int ph = 0; ph < d->os_factor; ++ph) {
            const float complex *cand = downsample_symbol(d, d->symbuf, ph, scratch);
            float pk = 0.0f, ns = 1.0f;
            (void)demod_one_symbol(d, cand, &pk, &ns);
            if (pk > best_peak) { best_peak = pk; best_phase = ph; }
        }
        d->sto_offset = best_phase;
    }
    const float complex *sym_samples = downsample_symbol(d, d->symbuf,
                                                         d->sto_offset, scratch);
    float peak = 0.0f, noise = 1.0f;
    /* During preamble lock, also capture the complex FFT bin value at the
     * tracked preamble_bin so we can derive cfo_frac from successive
     * samples' phase delta. Outside PREAMBLE_OK we don't care. */
    float complex preamble_bin_val = 0.0f + 0.0f * I;
    bool capture_preamble = (d->state == STATE_PREAMBLE_OK);
    uint16_t sym = demod_one_symbol_full(d, sym_samples, &peak, &noise,
        capture_preamble ? d->preamble_bin : -1,
        capture_preamble ? &preamble_bin_val : NULL);

    /* SNR accumulation across the demodulated frame. We average the dB
     * ratio of FFT peak to noise-floor-average across header+payload
     * symbols and write it into meta.snr_db at frame delivery. Ignore
     * IDLE and PREAMBLE_OK ticks (those before lock are mostly noise);
     * STATE_HEADER and STATE_PAYLOAD are the meaningful ones. */
    if ((d->state == STATE_HEADER || d->state == STATE_PAYLOAD) &&
        peak > 0.0f && noise > 0.0f) {
        double snr_db = 20.0 * log10((double)peak / (double)noise);
        d->snr_db_sum += snr_db;
        d->snr_db_count++;
    }

    /* Per-tick state-machine trace. Enabled by either MESHTASTIC_LORA_TRACE=1
     * in the env (legacy) or -vvv on the command line. Useful for cross-
     * validating against the upstream RX. */
    extern int verbose;
    static int trace_check = 0, trace_on = 0, trace_count = 0;
    if (!trace_check) {
        const char *e = getenv("MESHTASTIC_LORA_TRACE");
        trace_on = (e && *e == '1') || (verbose >= 3);
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
        d->preamble_bin_hist[0] = (int)sym;
        d->preamble_bin_hist_count = 1;
        d->preamble_peak_sum   = (double)peak;
        d->preamble_peak_count = 1;
        d->cfo_int         = 0;
        d->cfo_frac        = 0.0f;
        d->state           = STATE_PREAMBLE_OK;
        d->preamble_locked_once = 0;
        STATS_BUMP(preamble_candidates, d->sf);
        break;
    }
    case STATE_PREAMBLE_OK: {
        if (!above_floor) {
            /* Lost the signal -- back to hunting. */
            if (framesync_enabled())
                fprintf(stderr,
                    "[fs] frame=%d POK_TICK sym=%d peak=%.3f noise=%.3f decision=below_floor\n",
                    d->framesync_frame_idx + 1, (int)sym,
                    (double)peak, (double)noise);
            reset_to_idle(d);
            d->preamble_fft_count = 0;
            break;
        }
        int diff = abs((int)sym - d->preamble_bin);
        /* Account for FFT wrap-around. */
        if (diff > d->N / 2) diff = d->N - diff;
        /* Detect window-straddle ticks where the dechirped FFT spans
         * the preamble->sync chirp boundary. In that case the argmax
         * bin can land on the preamble bin (matching) but the peak
         * magnitude drops to ~sinc(0.5) of the preamble mean (the
         * energy is split between bin v and bin v+sync_offset). If
         * we treat such a tick as still-preamble we over-count by one
         * symbol and start the header one symbol late -- the
         * os_factor=2 SFO=0 baseline failure. After at least
         * PREAMBLE_MIN clean matches, a peak drop below
         * STRADDLE_PEAK_RATIO of the running mean triggers the sync
         * transition regardless of bin. Threshold 0.7 catches the
         * observed ~0.5 ratio on straddle ticks with plenty of margin
         * over natural preamble-peak variations. */
        const float STRADDLE_PEAK_RATIO = 0.7f;
        float preamble_peak_mean = (d->preamble_peak_count > 0)
            ? (float)(d->preamble_peak_sum / (double)d->preamble_peak_count)
            : 0.0f;
        bool straddle_trigger =
            (d->preamble_count >= PREAMBLE_MIN)
            && (preamble_peak_mean > 0.0f)
            && (peak < STRADDLE_PEAK_RATIO * preamble_peak_mean);
        if (framesync_enabled()) {
            /* frame_idx here is the *prospective* index of the frame
             * currently being assembled; it gets committed at LOCK. The
             * "+1" reflects that the LOCK emit hasn't yet incremented
             * the counter for this frame attempt. */
            const char *decision;
            if (diff <= 2 && !straddle_trigger)
                decision = "still";
            else if (straddle_trigger)
                decision = "sync_start_straddle";
            else if (d->preamble_count >= PREAMBLE_MIN)
                decision = "sync_start";
            else
                decision = "shift_in_prelock";
            fprintf(stderr,
                "[fs] frame=%d POK_TICK sym=%d peak=%.3f bin=%d diff=%d pcount=%d "
                "mean_peak=%.3f decision=%s\n",
                d->framesync_frame_idx + 1, (int)sym, (double)peak,
                d->preamble_bin, diff, d->preamble_count,
                (double)preamble_peak_mean, decision);
        }
        /* ±2 bin tolerance: with Hamming-window leakage and residual CFO,
         * the preamble FFT peak can oscillate between three adjacent
         * bins. A ±1 tolerance fires SHIFT spuriously on the wobble.
         * The smallest sync-word offset we still need to detect cleanly
         * is sync_word=1 -> bin = 8 (LoRa convention), so ±2 leaves
         * margin without missing real syncs. */
        if (diff <= 2 && !straddle_trigger) {
            /* Still on preamble. Cap count so we're ready to detect sync. */
            if (d->preamble_count < PREAMBLE_MIN + 4) d->preamble_count++;
            /* Update the running preamble-peak mean used by the
             * straddle detector above. Capped at the same horizon as
             * preamble_count so a late strong tick doesn't dilute the
             * mean and let an outright noise tick masquerade as a
             * straddle later. */
            d->preamble_peak_sum   += (double)peak;
            d->preamble_peak_count += 1;
            /* First tick where we've collected PREAMBLE_MIN matching symbols
             * is a "lock". Record only once per preamble run so the lock
             * count is a per-preamble event, not a per-symbol event. */
            if (d->preamble_count >= PREAMBLE_MIN && !d->preamble_locked_once) {
                d->preamble_locked_once = 1;
                STATS_BUMP(preamble_locks, d->sf);
                float snr_db = (peak > 0.0f && noise > 0.0f)
                               ? (float)(20.0 * log10((double)peak / (double)noise))
                               : 0.0f;
                if (peak > 0.0f && noise > 0.0f)
                    STATS_SNR(snr_hist_preamble, snr_db);
                /* TDOA: stash the stream cursor at the moment of lock
                 * directly on the per-decoder meta so the next frame
                 * delivered (if any) inherits a race-free per-frame
                 * anchor. Subsequent locks on the same decoder
                 * overwrite this only after the current preamble run
                 * resets via reset_to_idle. */
                d->meta.preamble_lock_sample_idx =
                    d->stream_chunk_anchor +
                    (uint64_t)d->samples_in_chunk *
                    (uint64_t)d->stream_step_per_sample;
                /* TDOA: also stash a software-lock wall-clock at the
                 * moment of lock-detect. On a GPSDO-disciplined host
                 * CLOCK_REALTIME is sub-microsecond; this is strictly
                 * better than the dedup-emit timestamp the existing
                 * station_t_ns field uses (which fires after the
                 * whole frame demods). NOT a sample-derived TOA --
                 * PFB / scheduling / buffering latency is still in
                 * the picture; fusion labels this as
                 * timestamp_class=software_lock, not "precise". */
                {
                    struct timespec ts;
                    clock_gettime(CLOCK_REALTIME, &ts);
                    d->meta.preamble_lock_t_ns =
                        (uint64_t)ts.tv_sec * 1000000000ULL +
                        (uint64_t)ts.tv_nsec;
                }
                /* Fire the preamble-lock callback. Subscribers (the
                 * scan-then-focus pool, scanners, telemetry) get the
                 * event before header decode starts -- the right
                 * trigger for "wake a focused decoder for this slot". */
                if (d->preamble_cb) {
                    d->preamble_cb(d->sf, d->cr, d->bw_hz, snr_db,
                                   d->preamble_user);
                }
            }
            /* Snapshot the FFT bin value for cfo_frac estimation later. */
            int N_HIST = (int)(sizeof(d->preamble_fft_hist) / sizeof(d->preamble_fft_hist[0]));
            if (d->preamble_fft_count < N_HIST)
                d->preamble_fft_hist[d->preamble_fft_count++] = preamble_bin_val;
            /* Stash bin value for k_hat = mode computation at lock time. */
            int B_HIST = (int)(sizeof(d->preamble_bin_hist) / sizeof(d->preamble_bin_hist[0]));
            if (d->preamble_bin_hist_count < B_HIST)
                d->preamble_bin_hist[d->preamble_bin_hist_count++] = (int)sym;
            /* Snapshot the dechirped time-domain samples for RCTSL sto_frac
             * estimation. demod_one_symbol_full left them in d->fft_in.
             * Rolling buffer keeps the last K preamble symbols. */
            if (d->preamble_dechirped) {
                int K = d->preamble_dechirped_capacity;
                int slot = d->preamble_dechirped_next;
                memcpy(&d->preamble_dechirped[(size_t)slot * d->N],
                       d->fft_in, sizeof(float complex) * (size_t)d->N);
                d->preamble_dechirped_next = (slot + 1) % K;
                if (d->preamble_dechirped_count < K)
                    d->preamble_dechirped_count++;
            }
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
            STATS_BUMP(sync_seen,       d->sf);
            STATS_BUMP(header_attempts, d->sf);
            /* RCTSL fractional STO estimate. Currently advisory-only at
             * os_factor=1 (sub-sample shift would need os>=2); the value
             * is stored on the decoder for downstream use. */
            compute_sto_frac(d);
            /* TDOA: convert the channel-rate sto_frac estimate to
             * SDR-sample units, in TOA-positive-late convention, and
             * stamp it on the meta the next delivered frame will
             * inherit. Read-only metadata; the demod path does not
             * use this field.
             *
             * Sign note: gr-lora_sdr's sto_frac is "shift our window
             * LATER by sto_frac to catch a preamble that arrived
             * sto_frac LATE relative to where we sampled." The
             * existing fine-skip path at lora.c:downsample_symbol
             * uses that convention directly. For the TOA-style
             * consumer field we want
             *     toa_sample = preamble_lock_sample_idx + frac
             * where frac > 0 means the preamble arrived a fraction
             * later than the integer cursor. Empirically (FFT-domain
             * known-delay synth fixture in tests/test_subsample_toa.py)
             * those two conventions disagree by a sign, so we negate
             * here at publish time. d->sto_frac itself is untouched. */
            d->meta.preamble_lock_sample_frac =
                -d->sto_frac * (float)d->stream_step_per_sample;
            /* k_hat = mode of the captured preamble bins (gr-lora_sdr's
             * `most_frequent(preamb_up_vals, n_up_req)` form, frame_sync_impl.cc:534).
             * The IDLE-entry latch can be off by ±1 due to FFT peak landing
             * on a noisier early sym; subsequent ticks settle to the true
             * value. Picking the mode keeps (N - k_hat) skip aligned to the
             * actual symbol grid -- a 1-bin error here = 4 input samples =
             * 1 output sample shift on every payload symbol's FFT bin. */
            int k_hat = d->preamble_bin;
            if (d->preamble_bin_hist_count >= 2) {
                int best_bin = d->preamble_bin_hist[0];
                int best_count = 1;
                for (int i = 0; i < d->preamble_bin_hist_count; ++i) {
                    int c = 0;
                    for (int j = 0; j < d->preamble_bin_hist_count; ++j)
                        if (d->preamble_bin_hist[j] == d->preamble_bin_hist[i]) c++;
                    if (c > best_count) {
                        best_count = c;
                        best_bin   = d->preamble_bin_hist[i];
                    }
                }
                k_hat = best_bin;
            }
            if (k_hat < 0) k_hat = 0;
            if (k_hat >= d->N) k_hat = 0;
            /* The preamble peak bin combines (STO_int + CFO_int) mod N.
             * For positive CFO the bin lands at a small positive value;
             * for negative CFO it wraps to N + signed_offset (i.e.
             * "near N"). Treat k_hat as a signed offset in [-N/2, N/2)
             * before computing the skip so the wrap doesn't flip the
             * alignment by a full symbol. Without this fix, the total
             * advance after PREAMBLE_OK->HEADER->DC2 reduces to
             *     3.25*N + (cfo_int - k_hat_signed)
             * which is 3.25*N exactly when cfo_int = k_hat_signed -- it
             * does for positive CFO (k_hat == cfo_int), but for negative
             * CFO the raw k_hat (= N + cfo_int) leaves a -N residue and
             * we end up reading symbols one full symbol earlier than
             * intended. Header symbols then dechirp at the wrong
             * position and the 5-bit checksum fails. */
            int k_signed = (k_hat >= d->N / 2) ? (k_hat - d->N) : k_hat;
            /* sto_skip_remaining is consumed in lora_decoder_feed at the
             * INPUT rate (samp_rate = os_factor * bw_hz). The signed
             * offset is multiplied by os_factor to convert from output-
             * rate bins to input samples.
             *
             * Note: the just-consumed PREAMBLE_OK tick already advanced
             * us one full symbol past the last preamble end. Adding
             * (N - k_signed) more samples lands us at start_of_DC1 for
             * either CFO sign. */
            d->sto_skip_remaining = (d->N - k_signed) * d->os_factor;

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
            /* DEBUG: env-gated force of cfo_frac to a fixed value, to
             * isolate whether the cfo_frac path itself causes the
             * |cfo_frac|>~0.38 cliff observed in synthetic tests. */
            {
                const char *e = getenv("MESHTASTIC_DEBUG_FORCE_CFO_FRAC");
                if (e) d->cfo_frac = (float)atof(e);
            }

            /* After the (N - k_hat) skip the symbol grid restarts at bin 0
             * so subsequent header/payload FFT-bin interpretation should
             * subtract 0 (not k_hat). */
            d->preamble_bin = 0;

            if (framesync_enabled()) {
                ++d->framesync_frame_idx;
                d->framesync_k_hat    = k_hat;
                d->framesync_sto_skip = d->sto_skip_remaining;
                /* sto_fine is the per-symbol input-sample shift
                 * downsample_symbol will apply from sto_frac. At os=1
                 * always 0 (lrint of [-0.5, +0.5]*1 = 0); at os>=2
                 * this surfaces the gr-lora-style sub-output-sample
                 * correction alongside the integer phase pick. */
                int fs_fine = (d->os_factor > 1)
                    ? (int)lrintf(d->sto_frac * (float)d->os_factor)
                    : 0;
                fprintf(stderr,
                    "[fs] frame=%d LOCK sf=%d os=%d k_hat=%d k_signed=%d sto_skip=%d "
                    "sto_frac=%+0.4f sto_fine=%+d cfo_frac=%+0.4f preamble_bins=[",
                    d->framesync_frame_idx, d->sf, d->os_factor, k_hat, k_signed,
                    d->sto_skip_remaining,
                    (double)d->sto_frac, fs_fine, (double)d->cfo_frac);
                int hist_n = d->preamble_bin_hist_count;
                for (int i = 0; i < hist_n; ++i)
                    fprintf(stderr, "%d%s", d->preamble_bin_hist[i],
                            i == hist_n - 1 ? "" : ",");
                fprintf(stderr, "]\n");
            }
            d->preamble_bin_hist_count = 0;
        } else {
            reset_to_idle(d);
        }
        break;
    }
    case STATE_HEADER: {
        /* On entry: PREAMBLE_OK consumed the NET_ID1 tick (one full symbol
         * past the last preamble end) AND we just queued a (N - k_hat)
         * skip. Combined, those land us at start_of_DC1 -- NET_ID2 is
         * absorbed into the skip+overshoot. Now read 2 ticks (DC1, DC2),
         * measure cfo_int on DC2, then queue the 0.25-symbol quarter-down
         * tail trim before header[0]. Total post-preamble alignment:
         *   1 sym (shifted NET_ID1) + (N - k_hat) skip + 2 sym (DC1+DC2)
         *   + N/4 + cfo_int trim  =  4.25*N - k_hat + cfo_int  ✓ matches
         *   gr-lora_sdr's frame_sync (NET_ID1+NET_ID2+DC1+DC2 + QUARTER_DOWN
         *   trim of N/4 + cfo_int after a (N - k_hat) DETECT-exit consume). */
        if (d->header_idx < 2) {
            /* tick 0 = DC1 (downchirp, sym from upchirp dechirp is junk),
             * tick 1 = DC2 (measure cfo_int from downchirp dechirp). */
            if (d->header_idx == 1) {
                int down_val = demod_downchirp_argmax(d, sym_samples);
                /* DC2 dechirp peak lives at round(2*(cfo_int + cfo_frac))
                 * (with cfo_frac already estimated from preamble). The
                 * naive floor-divide form `cfo_int = down_val / 2`
                 * silently drops the half-bin LSB, which manifests as a
                 * 1-bin cfo_int error any time the true CFO falls on a
                 * half-bin boundary and cfo_frac wraps to its sign-
                 * opposite (e.g. true cfo_bins = 11.71 -> cfo_frac is
                 * estimated as -0.29 by the preamble four_cum, DC2 peak
                 * lands at 23.42 which rounds to 23 or 24 from noise;
                 * cfo_int = 11 or 12 from floor-divide gives
                 * cfo_bins = 10.71 or 11.71 -- correct only half the
                 * time). Disambiguate by using cfo_frac to pick the
                 * rounding direction: cfo_int = round(down_val/2 -
                 * cfo_frac). Both DC2 measurements (23 or 24) converge
                 * to the same cfo_int. Manifests at SFO=25 ppm on the
                 * Short/Medium/Long{Fast,Turbo} cells where induced
                 * cfo_bins ~= 11.71 hits the half-bin boundary. */
                int signed_down = (down_val < d->N / 2)
                                  ? down_val
                                  : down_val - d->N;
                d->cfo_int = (int)lrint((double)signed_down / 2.0
                                        - (double)d->cfo_frac);
                if (framesync_enabled())
                    d->framesync_dc2_down_val = down_val;
                /* DEBUG: env-gated force of cfo_int. */
                {
                    const char *e = getenv("MESHTASTIC_DEBUG_FORCE_CFO_INT");
                    if (e) d->cfo_int = atoi(e);
                }
                /* Now rebuild the downchirp reference with cfo_int + cfo_frac
                 * applied. Subsequent header + payload FFTs dechirp through
                 * this corrected reference and the carrier offset is gone. */
                apply_cfo_correction(d);
                if (trace_on)
                    fprintf(stderr, "[lora] cfo_int=%d cfo_frac=%.4f (down_val=%d)\n",
                            d->cfo_int, (double)d->cfo_frac, down_val);
                /* gr-lora_sdr-style SFO drift estimate, frame_sync_impl.cc:638.
                 * Same-crystal assumption: sample-rate offset and carrier
                 * offset are proportional. sfo_hat (in fractional samples
                 * per symbol) = (cfo_bins) * bw_hz / center_freq_hz where
                 * cfo_bins = cfo_int + cfo_frac. Drives the per-symbol
                 * consume-count adjustment in STATE_PAYLOAD below. */
                if (d->center_freq_hz > 0.0) {
                    double cfo_bins = (double)d->cfo_int + (double)d->cfo_frac;
                    d->sfo_hat = cfo_bins * (double)d->bw_hz / d->center_freq_hz;
                } else {
                    d->sfo_hat = 0.0;
                }
                d->sfo_cum = 0.0;
            }
            d->header_idx++;
            if (d->header_idx == 2) {
                /* Just consumed DC1 + DC2; queue the 0.25-symbol
                 * quarter-downchirp tail skip plus the carrier-offset
                 * time correction before reading header[0].
                 *
                 * The trim's cfo_int+cfo_frac term is a TIME-domain
                 * correction, separate from the FREQUENCY-domain
                 * rotation now living in demod_one_symbol_full /
                 * compute_symbol_llrs. The preamble lock at bin k_hat
                 * absorbs (STO + cfo_int) into the skip; the trim's
                 * +cfo_int+cfo_frac then re-adds the cfo time shift
                 * so the symbol window grid stays at the true symbol
                 * boundary rather than the preamble-locked grid (those
                 * differ by exactly cfo_int+cfo_frac samples when
                 * STO=0). Rotation in the demod handles the residual
                 * cfo-induced frequency offset of the dechirped peak. */
                double trim_out = (double)d->N / 4.0
                                + (double)d->cfo_int
                                + (double)d->cfo_frac;
                int trim_input = (int)lrint(trim_out * (double)d->os_factor);
                if (trim_input < 0) trim_input = 0;
                d->sto_skip_remaining += trim_input;
                if (framesync_enabled()) {
                    d->framesync_trim_input = trim_input;
                    fprintf(stderr,
                        "[fs] frame=%d DC2  down_val=%d cfo_int=%d cfo_frac=%+0.4f "
                        "trim_input=%d sto_skip_after=%d\n",
                        d->framesync_frame_idx, d->framesync_dc2_down_val,
                        d->cfo_int, (double)d->cfo_frac,
                        trim_input, d->sto_skip_remaining);
                }
            }
            break;
        }
        int hi = d->header_idx - 2;
        if (hi < 8) {
            int sf_app_h = d->sf - 2;
            if (sf_app_h < 5) sf_app_h = 5;
            if (d->soft_decoding) {
                /* In soft mode we keep per-bit LLRs; the gray demap and
                 * (raw-1) shift are folded into compute_symbol_llrs. */
                compute_symbol_llrs(d, sym_samples, sf_app_h, true,
                                    d->header_llrs[hi]);
            } else {
                /* gr-lora_sdr fft_demod_impl.cc:313 + gray_mapping_impl.cc:70:
                 *   raw       = (bin - 1) mod 2^sf      <-- TX gray_demap added +1
                 *   demod_out = raw / 4   (header / LDRO mode -- DE)
                 *   gray      = demod_out ^ (demod_out >> 1)
                 * The -1 cancels the TX gray_demap +1 offset so symbol
                 * value 0 maps cleanly to bin 0 after dechirp+FFT. On
                 * synthetic IQ the integer-divide by 4 quietly absorbs
                 * the missing -1 most of the time, but on real radio
                 * it shifts the header nibbles by 1 bin and CRC fails. */
                int corr = ((int)sym - d->preamble_bin - 1) % d->N;
                if (corr < 0) corr += d->N;
                uint16_t demod_out = (uint16_t)(corr / 4);
                uint16_t gray = (uint16_t)(demod_out ^ (demod_out >> 1));
                d->header_syms[hi] = gray;
            }
            if (framesync_enabled() && hi >= 0 && hi < 8) {
                d->framesync_header_bins[hi] = (int)sym;
                d->framesync_header_mags[hi] = peak;
            }
            ++d->header_idx;
        }
        if (d->header_idx == 2 + 8) {
            if (framesync_enabled()) {
                fprintf(stderr, "[fs] frame=%d HEADER bins=[",
                        d->framesync_frame_idx);
                for (int i = 0; i < 8; ++i)
                    fprintf(stderr, "%d%s", d->framesync_header_bins[i],
                            i == 7 ? "" : ",");
                fprintf(stderr, "] mags=[");
                for (int i = 0; i < 8; ++i)
                    fprintf(stderr, "%.3f%s", (double)d->framesync_header_mags[i],
                            i == 7 ? "" : ",");
                fprintf(stderr, "]\n");
            }
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
                STATS_BUMP(header_checksum_fail, d->sf);
                if (trace_on)
                    fprintf(stderr, "[lora] header CRC fail: got 0x%02x want 0x%02x "
                            "n=%x %x %x %x %x len=%d cr=%d crc=%d\n",
                            header_chk, computed_chk,
                            n[0], n[1], n[2], n[3], n[4],
                            d->payload_len, d->payload_cr, d->payload_has_crc);
                reset_to_idle(d);
                break;
            }
            STATS_BUMP(header_checksum_pass, d->sf);
            STATS_BUMP(payload_attempts,     d->sf);
            /* SNR at header-pass uses the live FFT peak/noise at this
             * symbol -- the running snr_db_sum is also updated for the
             * 8 header symbols, but the per-symbol ratio at the moment
             * of header validation is the most directly comparable to
             * the preamble-lock SNR (same single-symbol time scale). */
            if (peak > 0.0f && noise > 0.0f)
                STATS_SNR(snr_hist_header,
                          20.0 * log10((double)peak / (double)noise));
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
                d->meta.snr_db = (d->snr_db_count > 0)
                               ? (float)(d->snr_db_sum / (double)d->snr_db_count)
                               : 0.0f;
                d->meta.payload_crc_ok = !d->payload_has_crc;
                STATS_BUMP(payload_no_crc, d->sf);
                if (d->cb) {
                    d->cb(NULL, 0, &d->meta, d->user);
                    STATS_BUMP(published_frames, d->sf);
                }
                reset_to_idle(d);
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
                compute_symbol_llrs(d, sym_samples, sf_p_active, d->payload_ldro,
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
                /* Zero-init silences a GCC may-be-uninitialized warning:
                 * cw_hard is written by lora_deinterleave() inside the
                 * d->soft_decoding==false branch and read by
                 * lora_hamming_decode() inside the same branch. The
                 * conditions match but the compiler can't prove it. */
                uint8_t cw_hard[16] = {0};
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
            /* CRC bytes are NOT whitened on TX (see references/gr-lora_sdr
             * dewhitening_impl.cc:100-105 -- the dewhitener explicitly
             * passes the CRC tail through untouched). Dewhitening over
             * those bytes here would corrupt the received CRC field
             * before verify, and historically caused payload_crc_ok to
             * always be false. Only dewhiten the payload portion. */
            size_t pay_only = (size_t)d->payload_len;
            if (pay_only > (size_t)byte_count) pay_only = (size_t)byte_count;
            lora_dewhiten(bytes, pay_only);

            if (d->payload_has_crc && byte_count >= 4) {
                /* LoRa's CRC-16 convention (see references/gr-lora_sdr's
                 * add_crc_impl.cc:124-136 and crc_verif_impl.cc:120-123):
                 *   - compute CRC-16/CCITT (poly 0x1021, init 0x0000)
                 *     over payload[0 .. N-3]  (the first N-2 payload bytes)
                 *   - XOR that with payload[N-1] (low byte) and
                 *     payload[N-2] << 8 (high byte)
                 *   - compare to the 2-byte CRC field that follows the payload
                 * The XOR-with-the-last-2-payload-bytes step is what makes
                 * LoRa's CRC different from "vanilla" CRC-16/CCITT verify,
                 * and was missing here -- so every clean-decode frame
                 * historically reported payload_crc_ok=false. */
                size_t pay_len = (size_t)byte_count - 2;
                uint16_t got_crc = (uint16_t)(bytes[byte_count-2] |
                                              ((uint16_t)bytes[byte_count-1] << 8));
                uint16_t want_crc = lora_crc16(bytes, pay_len - 2);
                want_crc ^= bytes[pay_len - 1];
                want_crc ^= (uint16_t)bytes[pay_len - 2] << 8;
                d->meta.payload_crc_ok = (got_crc == want_crc);
                STATS_BUMP(payload_crc_present, d->sf);
                {
                    int _lb = stats_paylen_bucket(d->payload_len);
                    if (d->meta.payload_crc_ok) {
                        STATS_BUMP(payload_crc_pass, d->sf);
                        atomic_fetch_add_explicit(
                            &g_demod_stats.crc_pass_by_len[_lb], 1,
                            memory_order_relaxed);
                    } else {
                        STATS_BUMP(payload_crc_fail, d->sf);
                        atomic_fetch_add_explicit(
                            &g_demod_stats.crc_fail_by_len[_lb], 1,
                            memory_order_relaxed);
                    }
                }
            } else {
                d->meta.payload_crc_ok = !d->payload_has_crc;
                STATS_BUMP(payload_no_crc, d->sf);
            }

            /* Stash the running average SNR for this frame so callers
             * (feed/web) can render it. */
            d->meta.snr_db = (d->snr_db_count > 0)
                           ? (float)(d->snr_db_sum / (double)d->snr_db_count)
                           : 0.0f;
            if (d->meta.payload_crc_ok && d->payload_has_crc)
                STATS_SNR(snr_hist_crc_pass, (double)d->meta.snr_db);
            if (trace_on) {
                fprintf(stderr, "[lora] DELIVER: %d payload bytes, crc_ok=%d, snr=%.1fdB, "
                                "cfo_int=%d cfo_frac=%.4f sym_target=%d first 8: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                        d->payload_len, d->meta.payload_crc_ok,
                        (double)d->meta.snr_db,
                        d->cfo_int, (double)d->cfo_frac, d->payload_sym_target,
                        bytes[0], bytes[1], bytes[2], bytes[3],
                        bytes[4], bytes[5], bytes[6], bytes[7]);
                if (d->payload_has_crc && byte_count >= 4) {
                    /* CRC-present diagnostic. Compact dump aimed at a
                     * single visual inspection on a fresh known-node
                     * capture: "is the payload almost right (a few bit
                     * flips near a decision boundary), byte-shifted (off-
                     * by-one nibble packing or skipped header leftover),
                     * whitened wrong (CRC bytes XORed, or wrong whitening
                     * offset), or just broadly corrupted (CFO drift /
                     * symbol timing collapse)". */
                    size_t pay_len = (size_t)byte_count - 2;
                    uint16_t got_crc = (uint16_t)(bytes[byte_count-2] |
                                                  ((uint16_t)bytes[byte_count-1] << 8));
                    uint16_t want_crc = lora_crc16(bytes, pay_len - 2);
                    want_crc ^= bytes[pay_len - 1];
                    want_crc ^= (uint16_t)bytes[pay_len - 2] << 8;
                    fprintf(stderr,
                        "[lora]   got_crc=0x%04x want_crc=0x%04x payload_len=%d byte_count=%d tail=%02x %02x %02x %02x\n",
                        got_crc, want_crc, d->payload_len, byte_count,
                        bytes[byte_count-4], bytes[byte_count-3],
                        bytes[byte_count-2], bytes[byte_count-1]);
                }
            }
            if (d->cb) {
                d->cb(bytes, (size_t)d->payload_len, &d->meta, d->user);
                STATS_BUMP(published_frames, d->sf);
            }
            reset_to_idle(d);
        }
        break;
    }
    }

    /* gr-lora_sdr-style per-symbol SFO drift adjustment, frame_sync_impl.cc:855-862.
     *
     * sfo_hat is fractional samples of drift per symbol, set at DC2 from the
     * measured CFO and the slot's center frequency (same-crystal assumption).
     * Per symbol we accumulate sfo_cum; when it crosses 1/(2*os_factor) we
     * skip an input sample before the next FFT to maintain symbol-grid
     * alignment. Applied to every symbol AFTER the DC2 measurement -- the
     * header data symbols also need this, not just payload.
     *
     * Positive direction only for now: shifts the next FFT start one sample
     * later via sto_skip_remaining. Negative direction (receiver clock slow,
     * sample stream falls behind grid) is unimplemented.
     *
     * Conditional on state to skip preamble + DC1 + DC2 ticks. After
     * reset_to_idle (frame delivered) the state machine returns to IDLE
     * and sfo_hat is zeroed, so the accumulator quiesces. */
    bool apply_drift = (d->state == STATE_HEADER && d->header_idx >= 2)
                    || (d->state == STATE_PAYLOAD);
    if (apply_drift && d->sfo_hat != 0.0) {
        d->sfo_cum += d->sfo_hat;
        /* Threshold = 1.0 instead of gr-lora's 1/(2*os) = 0.5. Empirically
         * a 0.5 threshold fires the carry-back mechanism at moderate drift
         * cells (LongSlow SFO=5 ppm) where the cumulative drift over a
         * frame is only ~1 sample and the decoder already tolerates it
         * without help. The cost of carry-back (one sample of phase-
         * discontinuity contamination in the next FFT) outweighs the
         * benefit at low drift. Threshold 1.0 only fires when accumulated
         * drift would push the FFT peak ~1 full bin off the symbol grid. */
        const double thresh = 1.0;
        const double adj = 1.0 / (double)d->os_factor;
        if (d->sfo_cum > thresh) {
            d->sfo_next_sym_shift = +1;
            d->sfo_cum -= adj;
        } else if (d->sfo_cum < -thresh) {
            d->sfo_next_sym_shift = -1;
            d->sfo_cum += adj;
        }
        const char *dbg = getenv("MESHTASTIC_LORA_DEBUG_SFO");
        if (dbg && *dbg == '1') {
            fprintf(stderr, "[sfo] state=%d hdr_idx=%d sfo_hat=%.4f cum=%.4f shift=%+d\n",
                    d->state, d->header_idx, d->sfo_hat, d->sfo_cum,
                    d->sfo_next_sym_shift);
        }
    }
}

void lora_decoder_feed(lora_decoder_t *d, const float complex *samples, size_t n)
{
    if (!d || !samples) return;
    /* All sample counts (skip + symbuf) are in INPUT samples (rate =
     * os_factor * bw_hz). When os_factor=1 this is a no-op vs the old
     * code; when os_factor>=2 the symbol buffer holds os_factor times
     * more raw samples and state_tick downsamples internally with the
     * fractional-STO offset before dechirp+FFT. */
    int spsym = d->samples_per_symbol;
    for (size_t i = 0; i < n; ++i) {
        if (d->sto_skip_remaining > 0) {
            --d->sto_skip_remaining;
            ++d->samples_in_chunk;
            continue;
        }
        d->symbuf[d->symbuf_count++] = samples[i];
        ++d->samples_in_chunk;
        if (d->symbuf_count == spsym) {
            state_tick(d);
            /* Apply SFO drift-corrected symbol boundary shift, set by
             * state_tick during STATE_HEADER post-DC2 / STATE_PAYLOAD.
             *
             * +1 = next FFT 1 sample EARLIER. Achieved by reusing this
             *      symbol's last sample as the next symbol's first.
             * -1 = next FFT 1 sample LATER. Achieved via one extra
             *      sto_skip_remaining (which lora_decoder_feed already
             *      honors at the top of this loop).
             *  0 = no shift (default). */
            if (d->sfo_next_sym_shift > 0) {
                d->symbuf[0] = d->symbuf[spsym - 1];
                d->symbuf_count = 1;
            } else if (d->sfo_next_sym_shift < 0) {
                d->sto_skip_remaining += 1;
                d->symbuf_count = 0;
            } else {
                d->symbuf_count = 0;
            }
            d->sfo_next_sym_shift = 0;
        }
    }
}
