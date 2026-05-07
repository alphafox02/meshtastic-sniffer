/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * BladeRF native backend for inmarsat-sniffer
 *
 */
#ifndef INMARSAT_BLADERF_H
#define INMARSAT_BLADERF_H

void bladerf_backend_list(void);
void *bladerf_backend_setup(int instance);
void *bladerf_stream_thread(void *arg);

#endif
