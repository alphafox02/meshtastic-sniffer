/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * USRP (UHD) native backend for inmarsat-sniffer
 *
 */
#ifndef INMARSAT_USRP_H
#define INMARSAT_USRP_H

void usrp_backend_list(void);
void *usrp_backend_setup(const char *serial);
void *usrp_stream_thread(void *arg);
char *usrp_get_serial(const char *name);

#endif
