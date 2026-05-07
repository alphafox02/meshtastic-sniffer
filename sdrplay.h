/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * SDRplay native API v3 backend for inmarsat-sniffer
 *
 */

#ifndef SDRPLAY_H
#define SDRPLAY_H

void sdrplay_list(void);
void *sdrplay_setup(const char *serial);
void *sdrplay_stream_thread(void *arg);
void sdrplay_close(void *ctx);

#endif
