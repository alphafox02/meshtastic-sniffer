/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Opt-in FFTW wisdom persistence.
 *
 * On startup the binary creates a handful of FFTW plans (the PFB
 * channelizer in particular uses FFTW_MEASURE, which times multiple
 * implementations). On ARM hosts that can take several seconds the
 * first time; on the Pi 5 it has been reported to take minutes for
 * the larger M values.
 *
 * If enabled, fftw_wisdom_load() reads accumulated wisdom from a
 * cache file before any plan is created; fftw_wisdom_save() writes
 * the accumulated wisdom (including anything new this run) back to
 * the same file at shutdown. Subsequent runs reuse the timing data
 * and skip the measurement phase.
 *
 * The feature is off by default to avoid creating cache files
 * users did not ask for. Enable via --fftw-wisdom[=PATH]:
 *   --fftw-wisdom                 use $XDG_CACHE_HOME/meshtastic-sniffer/fftw.wisdom
 *                                 (or $HOME/.cache/meshtastic-sniffer/fftw.wisdom)
 *   --fftw-wisdom=PATH            use the explicit file path
 *
 * load/save are no-ops when the feature is disabled (path NULL). On
 * any disk error the binary logs and continues; wisdom is purely a
 * speedup, never a correctness input.
 */

#ifndef FFTW_WISDOM_H
#define FFTW_WISDOM_H

#include <stdbool.h>

/* Resolve the cache path the user asked for. If `opt_path` is "" or
 * NULL, returns a heap-allocated default under XDG_CACHE_HOME (or
 * $HOME/.cache as fallback). Returns NULL only on OOM. Caller frees. */
char *fftw_wisdom_default_path(void);

/* Load wisdom from `path`. Call BEFORE any fftwf_plan_* call. Quietly
 * returns false if the file does not exist (first-run case). */
bool fftw_wisdom_load(const char *path);

/* Save the in-memory wisdom (accumulated across this run) to `path`.
 * Creates intermediate directories as needed. */
bool fftw_wisdom_save(const char *path);

#endif
