/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: SigMF metadata reader.
 *
 * Hand-rolled JSON-ish key/value extractor -- we only care about three
 * fields and don't want to drag in a JSON parser. Tolerant of
 * comments, whitespace, and field reorder.
 *
 */

#include "sigmf.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

static char *read_file(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return NULL;
    if (st.st_size <= 0 || st.st_size > 1024 * 1024) return NULL;  /* sanity */
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)st.st_size, f);
    fclose(f);
    buf[n] = 0;
    return buf;
}

/* Find "key" : value | "value" in `s` and return value start, or NULL. */
static const char *find_value(const char *s, const char *key)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(s, needle);
    if (!p) return NULL;
    p += strlen(needle);
    while (*p && (*p == ' ' || *p == '\t' || *p == ':' )) ++p;
    return p;
}

static iq_format_t map_datatype(const char *s)
{
    /* SigMF datatype strings: cf32_le, cf32_be, ci16_le, ci8 */
    if (!strncasecmp(s, "cf32", 4)) return FMT_CF32;
    if (!strncasecmp(s, "ci16", 4) || !strncasecmp(s, "cs16", 4)) return FMT_CI16;
    return FMT_CI8;
}

bool sigmf_load_for_path(const char *iq_path, sigmf_meta_t *out)
{
    if (!iq_path || !out) return false;
    memset(out, 0, sizeof(*out));

    /* Try PATH.sigmf-meta then strip-extension PATH-with-extension-replaced. */
    char p1[1024], p2[1024];
    snprintf(p1, sizeof(p1), "%s.sigmf-meta", iq_path);
    char *meta = read_file(p1);
    if (!meta) {
        const char *dot = strrchr(iq_path, '.');
        if (dot) {
            size_t base = (size_t)(dot - iq_path);
            if (base < sizeof(p2) - 16) {
                memcpy(p2, iq_path, base);
                strcpy(p2 + base, ".sigmf-meta");
                meta = read_file(p2);
            }
        }
    }
    if (!meta) return false;

    bool any = false;
    const char *v;
    if ((v = find_value(meta, "core:sample_rate")) != NULL) {
        out->sample_rate = strtod(v, NULL);
        out->have_sample_rate = out->sample_rate > 0;
        any |= out->have_sample_rate;
    }
    if ((v = find_value(meta, "core:frequency")) != NULL) {
        out->frequency_hz = strtod(v, NULL);
        out->have_frequency = out->frequency_hz > 0;
        any |= out->have_frequency;
    }
    if ((v = find_value(meta, "core:datatype")) != NULL) {
        while (*v == '"' || *v == ' ') ++v;
        out->datatype = map_datatype(v);
        out->have_datatype = true;
        any = true;
    }

    free(meta);
    return any;
}
