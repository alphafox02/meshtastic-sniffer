/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: polyphase filterbank channelizer.
 *
 * Decimator-by-M PFB with critical sampling: input at Fs, M output
 * channels at Fs/M each. Channels are uniformly spaced by Fs/M starting
 * from the (pre-shifted) input's DC. Adjacent channels are isolated by
 * the prototype filter -- with a Hamming-windowed sinc of length L*M
 * the worst-case sidelobe is around -42 dB, which keeps a strong LoRa
 * chirp from leaking into the neighbour bin.
 *
 * Classical critically-sampled PFB: per cycle of M input samples we
 * commute each into its branch's delay line, FIR each branch with its
 * polyphase row of the prototype, then FFT the M branch outputs to
 * produce one sample per output channel. Cost amortizes to (L + log M)
 * ops per input sample -- vs O(M) for the per-channel cascade DDC, an
 * O(M / log M) speedup.
 *
 */

#ifndef PFB_H
#define PFB_H

#include <complex.h>
#include <stddef.h>

typedef struct pfb pfb_t;

/* Per-bin output callback: fired once per output cycle (Fs/M rate) for
 * each bin that was registered with pfb_register_bin. */
typedef void (*pfb_emit_cb)(int channel_id, const float complex *iq,
                            size_t n, void *user);

/* Construct a critically-sampled PFB.
 *   M  = number of channels = FFT size = decimation factor
 *   L  = taps per polyphase branch (8..16 typical; bigger = sharper rolloff)
 *   pre_shift_hz = DC-aligned NCO offset applied to the input, used to
 *                  align the output bin grid to the channel grid.
 *                  Pass 0 if input is already aligned.
 *   samp_rate = input sample rate Fs in Hz
 * Returns NULL on allocation failure. */
pfb_t *pfb_create(int M, int L, double pre_shift_hz, double samp_rate);

/* Register an output bin. bin is in FFTW natural order (0..M-1, where
 * 0..M/2 = positive frequencies, M/2..M-1 = negative frequencies in
 * FFT-shift sense). Multiple decoders may bind to the same bin -- a
 * bin's callback list is stored as a linked list. */
int pfb_register_bin(pfb_t *p, int bin, int channel_id,
                     pfb_emit_cb cb, void *user);

/* Feed `n` complex samples at the input rate. Outputs are batched and
 * dispatched via the registered callbacks at output rate. */
void pfb_process(pfb_t *p, const float complex *samples, size_t n);

/* Flush any partial per-bin output buffers to their callbacks. Does
 * NOT reset the polyphase delay line, commutator phase, or warmup
 * counter -- that would lose continuity in the middle of a stream.
 * Call once at end-of-stream (file replay EOF) so the demods see the
 * tail. */
void pfb_flush(pfb_t *p);

void pfb_destroy(pfb_t *p);

/* Inspect: useful for debugging / verbose logging. */
int    pfb_M(const pfb_t *p);
int    pfb_L(const pfb_t *p);
double pfb_output_rate(const pfb_t *p);

#endif /* PFB_H */
