/*
 * meshtastic-sniffer: per-channel decimating DDC.
 *
 * Takes a single wideband IQ stream from the SDR and feeds N
 * narrowband baseband streams to the LoRa demod -- one per
 * (frequency, bandwidth) pair.
 *
 * Each output stream runs at exactly bw_hz (1 sample per chirp slope
 * unit), which is the natural input rate for a LoRa CSS demod with
 * FFT size 2^SF.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef CHANNELIZER_H
#define CHANNELIZER_H

#include <complex.h>
#include <stddef.h>
#include <stdint.h>

#define CHANNELIZER_MAX_CHANNELS 256
#define CHANNELIZER_OUTBUF_SAMPLES 4096   /* batch size delivered to the callback */

typedef void (*channelizer_cb_t)(int channel_id,
                                 const float complex *baseband,
                                 size_t num_samples,
                                 void *user);

typedef struct channel_cfg {
    uint64_t          f_hz;       /* RF center frequency of the channel  */
    int               bw_hz;      /* LoRa BW: 62500/125000/250000/500000 (or 2.4 GHz wide variants) */
    int               sf;         /* spreading factor 7..12 */
    int               cr;         /* coding rate denominator 5..8 (4/5..4/8) */
    channelizer_cb_t  on_baseband;
    void             *user;
} channel_cfg_t;

typedef struct channelizer channelizer_t;

channelizer_t *channelizer_create(uint64_t f_center, uint32_t samp_rate);

/* Returns assigned channel_id (>= 0) on success, -1 on failure
 * (full table or non-integer decimation ratio for the requested BW). */
int  channelizer_add_channel(channelizer_t *c, const channel_cfg_t *cfg);

int  channelizer_num_channels(const channelizer_t *c);

/* Feed wideband samples (interleaved complex). Two flavours so we can
 * skip a copy when the SDR backend is already producing int8 IQ. */
void channelizer_process_int8 (channelizer_t *c, const int8_t *iq_pairs, size_t n_complex);
void channelizer_process_float(channelizer_t *c, const float complex *iq, size_t n_complex);

void channelizer_destroy(channelizer_t *c);

#endif /* CHANNELIZER_H */
