/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * RTL-SDR native backend for inmarsat-sniffer
 *
 */

#ifndef RTLSDR_H
#define RTLSDR_H

void rtlsdr_backend_list(void);
void *rtlsdr_backend_setup(int dev_index);
void *rtlsdr_stream_thread(void *arg);
void rtlsdr_backend_close(void *ctx);

#endif
