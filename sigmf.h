/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: SigMF metadata reader.
 *
 * If user passes --file=PATH and a sibling PATH.sigmf-meta exists,
 * pull core:sample_rate, core:frequency, and core:datatype from it
 * to populate samp_rate, center_freq, and iq_format. User CLI flags
 * (--rate, --center, --iq-format) take precedence.
 *
 */

#ifndef SIGMF_H
#define SIGMF_H

#include "sdr.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct sigmf_meta {
    bool         have_sample_rate;
    double       sample_rate;
    bool         have_frequency;
    double       frequency_hz;
    bool         have_datatype;
    iq_format_t  datatype;
} sigmf_meta_t;

/* For "foo.cf32" tries "foo.cf32.sigmf-meta" then "foo.sigmf-meta".
 * Returns true if a sigmf-meta was found AND parsed at least one
 * useful field. */
bool sigmf_load_for_path(const char *iq_path, sigmf_meta_t *out);

#endif
