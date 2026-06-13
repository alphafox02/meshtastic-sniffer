/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Opt-in FFTW wisdom persistence. See fftw_wisdom.h.
 */

#include "fftw_wisdom.h"
#include "fftw_lock.h"

#include <errno.h>
#include <fftw3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

char *fftw_wisdom_default_path(void)
{
    const char *xdg = getenv("XDG_CACHE_HOME");
    const char *home = getenv("HOME");
    const char *base;
    char prefix[512];

    if (xdg && *xdg) {
        snprintf(prefix, sizeof(prefix), "%s/meshtastic-sniffer", xdg);
        base = prefix;
    } else if (home && *home) {
        snprintf(prefix, sizeof(prefix), "%s/.cache/meshtastic-sniffer", home);
        base = prefix;
    } else {
        return NULL;
    }

    size_t n = strlen(base) + strlen("/fftw.wisdom") + 1;
    char *out = malloc(n);
    if (!out) return NULL;
    snprintf(out, n, "%s/fftw.wisdom", base);
    return out;
}

/* Create the directory path leading up to `file_path` (mkdir -p of dirname),
 * permissions 0700 since this is per-user cache. Returns 0 on success. */
static int ensure_parent_dir(const char *file_path)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", file_path);
    char *slash = strrchr(buf, '/');
    if (!slash || slash == buf) return 0;
    *slash = '\0';

    /* Walk the prefix creating each component if missing. */
    for (char *p = buf + 1; *p; ++p) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if (mkdir(buf, 0700) != 0 && errno != EEXIST) return -1;
    return 0;
}

bool fftw_wisdom_load(const char *path)
{
    if (!path || !*path) return false;
    if (access(path, R_OK) != 0) {
        /* First run, or user just nuked the cache. Not an error. */
        return false;
    }
    fftw_planner_lock();
    int ok = fftwf_import_wisdom_from_filename(path);
    fftw_planner_unlock();
    if (ok) {
        fprintf(stderr, "fftw: loaded wisdom from %s\n", path);
        return true;
    }
    fprintf(stderr, "fftw: could not import wisdom from %s "
                    "(corrupt or wrong FFTW version) -- ignoring\n", path);
    return false;
}

bool fftw_wisdom_save(const char *path)
{
    if (!path || !*path) return false;
    if (ensure_parent_dir(path) != 0) {
        fprintf(stderr, "fftw: cannot create parent dir for %s: %s\n",
                path, strerror(errno));
        return false;
    }
    fftw_planner_lock();
    int ok = fftwf_export_wisdom_to_filename(path);
    fftw_planner_unlock();
    if (ok) {
        fprintf(stderr, "fftw: saved wisdom to %s\n", path);
        return true;
    }
    fprintf(stderr, "fftw: failed to write wisdom to %s\n", path);
    return false;
}
