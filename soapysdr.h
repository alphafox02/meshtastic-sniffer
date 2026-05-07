/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * SoapySDR backend
 *
 */

#ifndef SOAPYSDR_H
#define SOAPYSDR_H

#include <SoapySDR/Device.h>

void soapy_list(void);
SoapySDRDevice *soapy_setup(int id, const char *args);
void *soapy_stream_thread(void *arg);
void soapy_close(SoapySDRDevice *device);

#endif
