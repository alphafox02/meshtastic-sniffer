/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Airspy R2/Mini native backend for inmarsat-sniffer
 *
 */

#ifndef __AIRSPY_BACKEND_H__
#define __AIRSPY_BACKEND_H__

#include <stdint.h>

void airspy_backend_list(void);
void *airspy_backend_setup(uint64_t serial);
void *airspy_stream_thread(void *arg);
void airspy_backend_close(void *ctx);

/* Pick the supported rate closest to (and not less than) `requested_hz`.
 * Call before setup to auto-select when samp_rate is 0 or unsupported. */
double airspy_pick_samplerate(double requested_hz);

#endif
