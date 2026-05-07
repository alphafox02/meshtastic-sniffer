/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * File-replay backend for meshtastic-sniffer.
 *
 */

#ifndef FILE_SRC_H
#define FILE_SRC_H

#include "sdr.h"

/* Auto-detects iq_format from path extension when iq_format is left at its
 * default of FMT_CI8: .cf32/.fc32 -> FMT_CF32, .cs16/.sc16 -> FMT_CI16,
 * everything else -> FMT_CI8. Returns NULL on failure. */
void *file_src_setup(const char *path);
void *file_src_thread(void *arg);   /* arg is the FILE* from setup */

#endif
