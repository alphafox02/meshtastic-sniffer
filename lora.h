/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: LoRa CSS demodulator.
 *
 * One instance per (channel center, BW, SF, CR). Fed baseband samples
 * by the channelizer at exactly bw_hz. Emits decoded LoRa frames
 * (raw bytes after CRC verification) to a callback.
 *
 * Pipeline:
 *   baseband samples (1 sample/chirp-slope-unit)
 *     -> [frame sync] preamble detection, sync word, CFO/STO correction
 *     -> [fft demod]  dechirp by complex conjugate of upchirp,
 *                     2^SF-point FFT, take argmax bin per symbol
 *     -> [gray + deinterleave] gray-decode, diagonal deinterleave
 *     -> [hamming]    correct codewords (Hamming(8,4)/(7,4)/(6,4)/(5,4))
 *     -> [dewhiten]   XOR with the 256-byte LoRa whitening sequence
 *     -> [CRC16]      verify two-byte trailing CRC if header asserts it
 *     -> on_frame(payload, len, header_metadata)
 *
 */

#ifndef LORA_H
#define LORA_H

#include <complex.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct lora_decoder lora_decoder_t;

typedef struct lora_frame_meta {
    int      sf;
    int      cr;            /* coding rate denominator 5..8 */
    int      bw_hz;
    int      payload_len;   /* explicit-header payload length */
    bool     has_crc;
    bool     header_crc_ok;
    bool     payload_crc_ok;
    float    rssi_db;       /* indicated by demodulator (estimated) */
    float    snr_db;
    float    cfo_hz;        /* carrier frequency offset estimate */
    /* TDOA: caller-opaque stream cursor at the moment of preamble lock
     * for this frame. The decoder stashes it from its internal
     * stream_cursor + per-feed sample offset (set via
     * lora_decoder_set_stream_cursor). 0 if the caller never set the
     * cursor (synthetic feeds, selftest). */
    uint64_t preamble_lock_sample_idx;
    /* TDOA: fractional-sample timing offset of the preamble peak, in
     * SDR-sample units (same unit as preamble_lock_sample_idx), so a
     * consumer computes
     *
     *     toa_sample = preamble_lock_sample_idx + preamble_lock_sample_frac
     *
     * without needing to know the channelizer or focused-worker
     * decimation. Derived from the RCTSL fractional-STO estimate
     * (compute_sto_frac), converted to SDR units via the same step
     * value the caller passed to lora_decoder_set_stream_cursor.
     * Read-only metadata -- decode behavior is unaffected. Range is
     * roughly [-step/2, +step/2] SDR samples; 0 on synthetic feeds
     * that never set a stream cursor. */
    float    preamble_lock_sample_frac;
} lora_frame_meta_t;

typedef void (*lora_frame_cb_t)(const uint8_t *payload, size_t payload_len,
                                const lora_frame_meta_t *meta, void *user);

/* Fired exactly once per preamble run, the first time the decoder
 * collects PREAMBLE_MIN matching upchirp symbols (gr-lora_sdr's
 * preamble lock). "Not raw energy, not CRC": a real preamble has been
 * detected but header decode has not started yet -- the right point
 * to wake a focused decoder from a stare-mode pool. snr_db is the
 * lock-time peak/noise estimate; user is whatever the caller passed
 * to lora_decoder_set_preamble_cb (typically a channel id). */
typedef void (*lora_preamble_cb_t)(int sf, int cr, int bw_hz,
                                   float snr_db, void *user);

/* os_factor: input rate is os_factor * bw_hz. 1 = legacy (synthetic IQ,
 * already at bw_hz). >=2 enables fractional-STO realignment which is
 * necessary to lock real-radio captures with sub-sample timing offset. */
lora_decoder_t *lora_decoder_create(int sf, int cr, int bw_hz);
lora_decoder_t *lora_decoder_create_os(int sf, int cr, int bw_hz, int os_factor);

/* Bind a frame callback. Called from inside lora_decoder_feed when a
 * complete frame has been decoded (or discarded after CRC failure if
 * meta->payload_crc_ok is false but the user wants soft fails). */
void lora_decoder_set_callback(lora_decoder_t *dec,
                               lora_frame_cb_t cb, void *user);

/* Register a preamble-lock callback. Fires exactly once per detected
 * preamble (the same transition that bumps the preamble_locks stat).
 * Safe to leave NULL; passing NULL clears any prior registration. */
void lora_decoder_set_preamble_cb(lora_decoder_t *dec,
                                  lora_preamble_cb_t cb, void *user);

/* TDOA: announce the absolute stream-cursor value of the FIRST sample
 * in the next lora_decoder_feed() call, plus how many cursor units
 * each consumed input sample represents. The decoder treats both
 * values as opaque uint64/uint32 and stashes
 *
 *     chunk_anchor + samples_consumed_in_chunk * step_per_sample
 *
 * at the moment its preamble-lock state fires, then propagates that
 * value through lora_frame_meta_t.preamble_lock_sample_idx for any
 * frame that comes out of the lock. Callers driving the decoder from
 * a chunk-oriented stream should pass step_per_sample = SDR samples
 * per consumed input sample (= channelizer or DDC decim factor) and
 * chunk_anchor = SDR sample index of the first sample in the next
 * feed. Synthetic / selftest paths can leave both at 0; the field
 * stays 0 and downstream consumers see no anchor. */
void lora_decoder_set_stream_cursor(lora_decoder_t *dec,
                                    uint64_t chunk_anchor,
                                    uint32_t step_per_sample);

/* Set the slot's RF carrier frequency in Hz. Enables gr-lora_sdr-style
 * SFO drift compensation: at preamble lock the decoder derives an SFO
 * estimate from the measured CFO using the same-crystal assumption
 * (sfo_hat = (cfo_int+cfo_frac) * bw_hz / center_freq_hz), then per
 * payload symbol it accumulates drift and shifts the FFT window by
 * one sample when the accumulator crosses 0.5. 0 (default) keeps the
 * SFO path inert. Must be called before decode if you want compensation. */
void lora_decoder_set_center_freq(lora_decoder_t *dec, double center_freq_hz);

/* Feed one batch of complex baseband samples (rate = bw_hz). */
void lora_decoder_feed(lora_decoder_t *dec,
                       const float complex *samples, size_t n);

void lora_decoder_destroy(lora_decoder_t *dec);

/* ---- Standalone helpers exposed for unit testing -----------------------
 *
 * These are pure functions; no decoder state required. */

/* Convert symbol value to gray-coded equivalent and back.
 * For LoRa: gray_decode(s) = s ^ (s >> 1). */
uint16_t lora_gray_decode(uint16_t s);
uint16_t lora_gray_encode(uint16_t s);

/* Hamming decode: (5,4), (6,4), (7,4), (8,4) per CR=5..8.
 * Returns the 4-bit data nibble. *err is set to 1 if a single-bit
 * correction was applied, 2 if uncorrectable, 0 if clean. */
uint8_t lora_hamming_decode(uint8_t cw, int cr, int *err);

/* Dewhiten: XOR data in-place with the LoRa whitening sequence
 * starting from offset 0. */
void lora_dewhiten(uint8_t *data, size_t len);

/* LoRa CRC16: polynomial 0x1021 (CCITT), init 0x0000, no reflection,
 * XOR'd with last two bytes per the LoRa spec quirk.  Returns the
 * computed CRC for `data[0..len-1]`. */
uint16_t lora_crc16(const uint8_t *data, size_t len);

/* Diagonal deinterleave: cr_use codewords of (sf_app=sf-2 | sf) bits each
 * are stored by row at the demod output; we read them back diagonally
 * to undo the LoRa interleaver. `sf_app` is sf-2 for the header (and
 * for low-data-rate-optimization payloads) and sf otherwise. */
void lora_deinterleave(const uint16_t *symbols, int sf_app, int cr_use,
                       uint8_t *codewords);

/* ---- Demod state-machine instrumentation -------------------------------
 *
 * Always-on lock-free atomic counters that record what the demodulator
 * did across every decoder instance in the process. The wideband channelizer
 * fans baseband to up to N decoders in parallel; without these counters
 * it's hard to tell whether a "no frames decoded" result means we're not
 * locking preambles, locking but failing header checksum, or sailing
 * through to bogus payloads. Dump prints a per-SF table plus three SNR
 * histograms (at preamble lock, header checksum pass, and CRC pass).
 * Output is short enough to leave in production. */
#include <stdio.h>
void lora_demod_stats_reset(void);
void lora_demod_stats_dump(FILE *fp);

#endif /* LORA_H */
