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

#endif
