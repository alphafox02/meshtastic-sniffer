/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * FFTW thread-safety wrapper.
 * FFTW plan creation is not thread-safe. All plan calls must be serialized.
 *
 */

#ifndef FFTW_LOCK_H
#define FFTW_LOCK_H

#include <pthread.h>

extern pthread_mutex_t fftw_planner_mutex;

static inline void fftw_planner_lock(void)   { pthread_mutex_lock(&fftw_planner_mutex); }
static inline void fftw_planner_unlock(void) { pthread_mutex_unlock(&fftw_planner_mutex); }

#endif
