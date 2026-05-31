/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Implementation: see iq_snapshot.h for the architecture summary.
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "iq_snapshot.h"
#include "iq_ring.h"
#include "sdr.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define QUEUE_CAP_DEFAULT          64
#define WRITER_POLL_SLEEP_MS       3      /* short sleep while waiting on ring */
#define WRITER_WAIT_TIMEOUT_MS     2000   /* give up if ring doesn't advance */
#define JANITOR_EVERY_N_SNAPSHOTS  16
#define IQ_PATH_MAX                512

static struct {
    int                       inited;
    iq_snapshot_cfg_t         cfg;
    iq_ring_t                *ring;
    size_t                    bytes_per_sample;
    const char               *ext;   /* "cs8" or "cf32" */

    pthread_t                 writer_tid;
    int                       writer_running;

    pthread_mutex_t           qmu;
    pthread_cond_t            qcond;
    iq_snapshot_event_t      *q;
    int                       q_cap;
    int                       q_head;
    int                       q_tail;
    int                       q_count;
    int                       shutdown;

    iq_snapshot_counters_t    counters;
    pthread_mutex_t           counters_mu;
} g = {0};

static void counters_bump(uint64_t *field)
{
    pthread_mutex_lock(&g.counters_mu);
    (*field)++;
    pthread_mutex_unlock(&g.counters_mu);
}

static int mkdir_p(const char *path)
{
    /* Create a directory tree like /a/b/c. Tolerates existing
     * components. */
    char tmp[IQ_PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len == 0) return -1;
    if (tmp[len - 1] == '/') tmp[len - 1] = 0;
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static void utc_yyyymmdd(uint64_t t_ns, char out[16])
{
    time_t t = (time_t)(t_ns / 1000000000ULL);
    struct tm tm_utc;
    gmtime_r(&t, &tm_utc);
    strftime(out, 16, "%Y%m%d", &tm_utc);
}

static void utc_hhmmss(uint64_t t_ns, char out[16])
{
    time_t t = (time_t)(t_ns / 1000000000ULL);
    struct tm tm_utc;
    gmtime_r(&t, &tm_utc);
    strftime(out, 16, "%H%M%S", &tm_utc);
}

/* Janitor: walk every day-folder under DIR and prune oldest files
 * first until both caps are satisfied. Cheap because the date-shard
 * bounds the scan width per call. */
typedef struct {
    char    path[IQ_PATH_MAX];
    time_t  mtime;
    off_t   size;
} prune_entry_t;

static int prune_cmp(const void *a, const void *b)
{
    const prune_entry_t *ea = a, *eb = b;
    if (ea->mtime < eb->mtime) return -1;
    if (ea->mtime > eb->mtime) return  1;
    return 0;
}

static void janitor_run(void)
{
    if (!g.cfg.dir) return;
    /* Two passes: list all matching files (.cs8/.cf32 + .json siblings),
     * then prune oldest until caps satisfied. */
    DIR *root = opendir(g.cfg.dir);
    if (!root) return;
    size_t cap = 256;
    size_t n = 0;
    prune_entry_t *list = malloc(cap * sizeof(*list));
    if (!list) { closedir(root); return; }
    long long total_bytes = 0;

    struct dirent *de;
    while ((de = readdir(root)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char day_path[IQ_PATH_MAX];
        snprintf(day_path, sizeof(day_path), "%s/%s", g.cfg.dir, de->d_name);
        struct stat st_day;
        if (stat(day_path, &st_day) != 0 || !S_ISDIR(st_day.st_mode)) continue;
        DIR *day = opendir(day_path);
        if (!day) continue;
        struct dirent *fe;
        while ((fe = readdir(day)) != NULL) {
            if (fe->d_name[0] == '.') continue;
            const char *dot = strrchr(fe->d_name, '.');
            if (!dot) continue;
            if (strcmp(dot, ".cs8") != 0 && strcmp(dot, ".cf32") != 0
                && strcmp(dot, ".json") != 0) continue;
            char fp[IQ_PATH_MAX];
            snprintf(fp, sizeof(fp), "%s/%s", day_path, fe->d_name);
            struct stat st;
            if (stat(fp, &st) != 0) continue;
            if (n == cap) {
                cap *= 2;
                prune_entry_t *grow = realloc(list, cap * sizeof(*list));
                if (!grow) { free(list); closedir(day); closedir(root); return; }
                list = grow;
            }
            snprintf(list[n].path, sizeof(list[n].path), "%s", fp);
            list[n].mtime = st.st_mtime;
            list[n].size  = st.st_size;
            total_bytes  += (long long)st.st_size;
            ++n;
        }
        closedir(day);
    }
    closedir(root);

    if (n == 0) { free(list); return; }
    qsort(list, n, sizeof(*list), prune_cmp);

    time_t now = time(NULL);
    long long disk_cap_bytes = g.cfg.disk_cap_mb > 0
        ? (long long)g.cfg.disk_cap_mb * 1024LL * 1024LL : 0;

    /* Prune oldest until both caps satisfied. */
    for (size_t i = 0; i < n; ++i) {
        int too_big   = disk_cap_bytes > 0 && total_bytes > disk_cap_bytes;
        int too_old   = g.cfg.age_cap_seconds > 0 &&
                        (now - list[i].mtime) > g.cfg.age_cap_seconds;
        if (!too_big && !too_old) break;
        if (unlink(list[i].path) == 0) {
            counters_bump(&g.counters.pruned);
            total_bytes -= (long long)list[i].size;
        }
    }
    free(list);
}

/* Write the per-event sidecar. Self-contained; fusion can ingest a
 * directory of these without an external index. */
static int write_sidecar(const char *json_path,
                         const iq_snapshot_event_t *ev,
                         uint64_t snapshot_start_idx,
                         uint64_t snapshot_sample_count)
{
    char tmp[IQ_PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp", json_path);
    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;
    /* Hand-rolled JSON to avoid pulling in a library. Floats use %.6f
     * which is plenty for SNR / sample-rate. */
    fprintf(f,
            "{\n"
            "  \"station_id\": \"%s\",\n"
            "  \"station_t_ns\": %" PRIu64 ",\n"
            "  \"station_t_acc_ns\": %u,\n"
            "  \"preset\": \"%s\",\n"
            "  \"sf\": %d,\n"
            "  \"cr\": %d,\n"
            "  \"bw_hz\": %d,\n"
            "  \"freq_hz\": %" PRIu64 ",\n"
            "  \"sample_rate_sps\": %" PRIu64 ",\n"
            "  \"preamble_lock_sample_idx\": %" PRIu64 ",\n"
            "  \"snapshot_start_sample_idx\": %" PRIu64 ",\n"
            "  \"snapshot_sample_count\": %" PRIu64 ",\n"
            "  \"snr_db_at_lock\": %.2f,\n"
            "  \"format\": \"%s\"\n"
            "}\n",
            g.cfg.station_id ? g.cfg.station_id : "",
            ev->lock_t_ns,
            g.cfg.station_t_acc_ns,
            ev->preset_name,
            ev->sf, ev->cr, ev->bw_hz,
            ev->freq_hz,
            (uint64_t)(g.cfg.sample_rate + 0.5),
            ev->lock_sample_idx,
            snapshot_start_idx,
            snapshot_sample_count,
            ev->snr_db_at_lock,
            g.ext);
    fflush(f);
    fclose(f);
    if (rename(tmp, json_path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static void writer_handle_event(const iq_snapshot_event_t *ev)
{
    uint64_t pre_samples  = (uint64_t)((double)g.cfg.window_pre_ms  *
                                       g.cfg.sample_rate / 1000.0 + 0.5);
    uint64_t post_samples = (uint64_t)((double)g.cfg.window_post_ms *
                                       g.cfg.sample_rate / 1000.0 + 0.5);
    uint64_t total        = pre_samples + post_samples;
    uint64_t start        = ev->lock_sample_idx > pre_samples
                            ? ev->lock_sample_idx - pre_samples : 0;
    uint64_t end          = start + total;

    /* Wait for the ring to advance past the post-window. Short polls
     * so we don't burn CPU; bounded total wait. The wait runs even
     * during shutdown so any already-extractable snapshots get written
     * before the writer thread joins. If the ring legitimately won't
     * advance (file replay ended past the lock + post_window), the
     * bounded WRITER_WAIT_TIMEOUT_MS budget caps the drain time. */
    int waited_ms = 0;
    for (;;) {
        uint64_t oldest, newest_plus_one;
        iq_ring_live_range(g.ring, &oldest, &newest_plus_one);
        if (newest_plus_one >= end) break;
        if (waited_ms >= WRITER_WAIT_TIMEOUT_MS) {
            counters_bump(&g.counters.wait_timeout);
            return;
        }
        struct timespec ts = {0, WRITER_POLL_SLEEP_MS * 1000000L};
        nanosleep(&ts, NULL);
        waited_ms += WRITER_POLL_SLEEP_MS;
    }

    /* Confirm pre-window hasn't aged out before we extract. */
    uint64_t oldest, newest_plus_one;
    iq_ring_live_range(g.ring, &oldest, &newest_plus_one);
    if (start < oldest) {
        counters_bump(&g.counters.missed_ring_window);
        return;
    }

    size_t bytes = (size_t)total * g.bytes_per_sample;
    void *buf = malloc(bytes);
    if (!buf) return;
    size_t got = iq_ring_get_window(g.ring, start, (size_t)total, buf);
    if (got < total) {
        counters_bump(&g.counters.missed_ring_window);
        free(buf);
        return;
    }

    /* Resolve output paths. */
    char day[16], hms[16];
    utc_yyyymmdd(ev->lock_t_ns, day);
    utc_hhmmss  (ev->lock_t_ns, hms);
    char dir[IQ_PATH_MAX];
    snprintf(dir, sizeof(dir), "%s/%s", g.cfg.dir, day);
    if (mkdir_p(dir) != 0) { free(buf); return; }

    const char *sid = g.cfg.station_id ? g.cfg.station_id : "anon";
    double freq_mhz = (double)ev->freq_hz / 1.0e6;
    /* seq disambiguates filenames when two locks share the same
     * (HHMMSS, lock_sample_idx, freq, sf, bw) -- can happen when
     * multiple PFB channels report locks for the same SDR sample
     * cursor on a leaky strong signal. Monotonic, station-local. */
    static _Atomic uint64_t s_file_seq = 0;
    uint64_t seq = atomic_fetch_add(&s_file_seq, 1);
    char base[IQ_PATH_MAX];
    snprintf(base, sizeof(base),
             "%s/%s_%s_%" PRIu64 "_%.3fMHz_SF%d_BW%d_seq%" PRIu64,
             dir, hms, sid, ev->lock_sample_idx,
             freq_mhz, ev->sf, ev->bw_hz, seq);

    char iq_path[IQ_PATH_MAX], json_path[IQ_PATH_MAX];
    snprintf(iq_path,   sizeof(iq_path),   "%s.%s",   base, g.ext);
    snprintf(json_path, sizeof(json_path), "%s.json", base);

    /* Atomic write: tmp + rename. No fsync by default per Codex. */
    char iq_tmp[IQ_PATH_MAX];
    snprintf(iq_tmp, sizeof(iq_tmp), "%s.tmp", iq_path);
    FILE *iqf = fopen(iq_tmp, "wb");
    if (!iqf) { free(buf); return; }
    size_t wrote = fwrite(buf, 1, bytes, iqf);
    free(buf);
    fflush(iqf);
    fclose(iqf);
    if (wrote != bytes) { unlink(iq_tmp); return; }
    if (rename(iq_tmp, iq_path) != 0) { unlink(iq_tmp); return; }

    if (write_sidecar(json_path, ev, start, total) != 0) {
        unlink(iq_path);
        return;
    }

    counters_bump(&g.counters.kept);
}

static void *writer_thread_main(void *arg)
{
    (void)arg;
#ifdef _GNU_SOURCE
    pthread_setname_np(pthread_self(), "iq-snapshot");
#endif
    uint64_t since_janitor = 0;
    /* Loop exits only when writer_running==0 AND the queue is empty,
     * so queued items get drained at shutdown even if the producer
     * stopped enqueuing (e.g. file replay finishing right after the
     * last preamble locks). The post-window wait inside
     * writer_handle_event() still bounds total drain time. */
    for (;;) {
        iq_snapshot_event_t ev;
        int have = 0;
        pthread_mutex_lock(&g.qmu);
        if (g.q_count == 0) {
            if (!g.writer_running) {
                pthread_mutex_unlock(&g.qmu);
                break;
            }
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += 100 * 1000000L;   /* 100 ms */
            if (ts.tv_nsec >= 1000000000L) {
                ts.tv_sec += 1; ts.tv_nsec -= 1000000000L;
            }
            pthread_cond_timedwait(&g.qcond, &g.qmu, &ts);
            pthread_mutex_unlock(&g.qmu);
            continue;
        }
        ev = g.q[g.q_head];
        g.q_head = (g.q_head + 1) % g.q_cap;
        g.q_count--;
        have = 1;
        pthread_mutex_unlock(&g.qmu);
        if (!have) continue;

        writer_handle_event(&ev);
        if (++since_janitor >= JANITOR_EVERY_N_SNAPSHOTS) {
            since_janitor = 0;
            janitor_run();
        }
    }
    return NULL;
}

int iq_snapshot_init(const iq_snapshot_cfg_t *cfg)
{
    if (g.inited) return 0;
    if (!cfg || !cfg->dir || !cfg->ring) return -1;
    if (cfg->sample_rate <= 0.0) return -1;
    if (mkdir_p(cfg->dir) != 0) return -1;

    g.cfg = *cfg;
    g.ring = cfg->ring;
    int fmt = iq_ring_format(cfg->ring);
    g.bytes_per_sample = iq_ring_bytes_per_sample(fmt);
    g.ext = (fmt == SAMPLE_FMT_FLOAT) ? "cf32" : "cs8";

    if (g.cfg.window_pre_ms  <= 0) g.cfg.window_pre_ms  = 50;
    if (g.cfg.window_post_ms <= 0) g.cfg.window_post_ms = 100;
    if (g.cfg.disk_cap_mb    <  0) g.cfg.disk_cap_mb    = 0;
    if (g.cfg.age_cap_seconds<  0) g.cfg.age_cap_seconds= 0;
    if (g.cfg.queue_capacity <= 0) g.cfg.queue_capacity = QUEUE_CAP_DEFAULT;

    g.q_cap = g.cfg.queue_capacity;
    g.q = calloc((size_t)g.q_cap, sizeof(*g.q));
    if (!g.q) return -1;
    g.q_head = g.q_tail = g.q_count = 0;
    pthread_mutex_init(&g.qmu, NULL);
    pthread_cond_init(&g.qcond, NULL);
    pthread_mutex_init(&g.counters_mu, NULL);
    memset(&g.counters, 0, sizeof(g.counters));

    g.writer_running = 1;
    g.shutdown = 0;
    if (pthread_create(&g.writer_tid, NULL, writer_thread_main, NULL) != 0) {
        free(g.q); g.q = NULL;
        pthread_mutex_destroy(&g.qmu);
        pthread_cond_destroy(&g.qcond);
        pthread_mutex_destroy(&g.counters_mu);
        g.writer_running = 0;
        return -1;
    }
    g.inited = 1;
    return 0;
}

void iq_snapshot_shutdown(void)
{
    if (!g.inited) return;
    pthread_mutex_lock(&g.qmu);
    g.writer_running = 0;
    pthread_cond_broadcast(&g.qcond);
    pthread_mutex_unlock(&g.qmu);
    pthread_join(g.writer_tid, NULL);
    free(g.q); g.q = NULL;
    pthread_mutex_destroy(&g.qmu);
    pthread_cond_destroy(&g.qcond);
    pthread_mutex_destroy(&g.counters_mu);
    g.inited = 0;
}

int iq_snapshot_enabled(void) { return g.inited ? 1 : 0; }

void iq_snapshot_enqueue(const iq_snapshot_event_t *ev)
{
    if (!g.inited || !ev) return;
    counters_bump(&g.counters.enqueued_total);
    if (ev->snr_db_at_lock < g.cfg.min_snr_db) {
        counters_bump(&g.counters.dropped_below_snr);
        return;
    }
    pthread_mutex_lock(&g.qmu);
    if (g.q_count >= g.q_cap) {
        pthread_mutex_unlock(&g.qmu);
        counters_bump(&g.counters.dropped_queue_full);
        return;
    }
    g.q[g.q_tail] = *ev;
    g.q_tail = (g.q_tail + 1) % g.q_cap;
    g.q_count++;
    pthread_cond_signal(&g.qcond);
    pthread_mutex_unlock(&g.qmu);
}

void iq_snapshot_get_counters(iq_snapshot_counters_t *out)
{
    if (!out) return;
    pthread_mutex_lock(&g.counters_mu);
    *out = g.counters;
    pthread_mutex_unlock(&g.counters_mu);
}
