/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * HackRF native backend for inmarsat-sniffer
 *
 */
#ifndef INMARSAT_HACKRF_H
#define INMARSAT_HACKRF_H

void hackrf_backend_list(void);
void *hackrf_backend_setup(const char *serial);
void *hackrf_stream_thread(void *arg);

#include <stddef.h>
#include <stdint.h>

/* Transmit a pre-built int8 IQ buffer (interleaved I,Q) on the HackRF the
 * sniffer is receiving with. RX is stopped, the buffer is played at
 * (freq_hz, rate_hz, txvga_db, amp), then the RX configuration is restored
 * and streaming resumes. Samples are dropped while transmitting.
 * Returns 0 on success, -1 with a message in err otherwise. Thread-safe;
 * concurrent callers serialize. */
int hackrf_tx_play(const int8_t *iq, size_t nbytes, uint64_t freq_hz,
                   uint32_t rate_hz, int txvga_db, int amp,
                   char *err, size_t errlen);

/* 1 while the sniffer has an open HackRF it is streaming from. */
int hackrf_tx_available(void);

#include <math.h>

/* Frequency to program into the HackRF so it lands on f_hz despite a
 * clock error of ppm (positive = oscillator runs fast). RX tuning and
 * tools/meshtastic_tx.py (TX LO) use this same formula and rounding, so
 * one --ppm moves both directions identically; tests/tx/params_check
 * holds them together. */
static inline uint64_t hackrf_ppm_tune_hz(double f_hz, double ppm)
{
    return (uint64_t)floor(f_hz * (1.0 - ppm * 1e-6) + 0.5);
}

#endif
