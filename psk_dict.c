/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: PSK dictionary attack.
 *
 * Background thread tries each wordlist entry as a candidate PSK
 * against undecrypted frames. To reuse the existing decode validation
 * (AES-CTR, channel-hash dispatch, protobuf parse) without inventing
 * a parallel verifier, each attempt builds a temporary single-entry
 * keyset and calls mesh_packet_decode_with_radio() with it. If the
 * callback fires with decrypted=true, we know the candidate is right.
 *
 * The discovered key is then promoted to the live runtime keyset (so
 * the next frame on that channel decrypts normally), and a
 * PSK_DISCOVERED JSON event is emitted to feed/stdout/web for operator
 * visibility. The frame that triggered discovery itself stays
 * undecrypted in the public output -- the candidate path runs in the
 * background after the hot path has already moved on.
 */

#include "psk_dict.h"

#include "keyset.h"
#include "mesh_packet.h"
#include "meshtastic.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Forwards from main.c / web.c so we can publish the discovery event. */
extern keyset_t *app_get_keyset(void);
extern void      web_publish_line(const char *json, size_t len);
extern void      webhook_publish(const char *event_name, const char *json, size_t len,
                                 const char *summary);

#define PSK_QUEUE_SIZE       128
#define PSK_FRAME_MAX_BYTES  256
#define PSK_MAX_CANDIDATES   32768

typedef struct {
    uint8_t  bytes[PSK_FRAME_MAX_BYTES];
    size_t   len;
    float    rssi_db, snr_db;
    int      sf, cr, bw_hz;
} psk_frame_t;

typedef struct {
    char    *spec;          /* original wordlist line, for reporting */
    uint8_t  psk[KEYSET_MAX_PSK_BYTES];
    size_t   psk_len;
} candidate_t;

static psk_frame_t   g_queue[PSK_QUEUE_SIZE];
static int           g_q_head = 0, g_q_tail = 0; /* head=write, tail=read */
static pthread_mutex_t g_q_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_q_cv = PTHREAD_COND_INITIALIZER;

static candidate_t  *g_candidates = NULL;
static size_t        g_candidate_count = 0;

static pthread_t     g_thread;
static volatile int  g_run = 0;
static int           g_started = 0;

/* Track which (channel_hash, spec) pairs have already been discovered to
 * suppress duplicate alerts -- a long capture would otherwise re-fire on
 * every frame for channels we already cracked. */
static uint8_t g_cracked_hashes[256] = {0};

/* ---- Wordlist parsing ---- */

/* Same grammar as keyset_parse_spec. Returns 0 + fills `out_psk` /
 * `out_len` on success. The optional 'Name=' prefix is stripped (we
 * don't need it -- the attack works without knowing the channel name). */
static int parse_psk_spec(const char *line, uint8_t *out_psk, size_t *out_len)
{
    /* Strip leading whitespace */
    while (*line == ' ' || *line == '\t') ++line;

    /* Skip optional 'Name=' prefix */
    const char *eq = strchr(line, '=');
    if (eq) line = eq + 1;

    /* Trim trailing whitespace / CR */
    char buf[256];
    size_t n = 0;
    while (line[n] && line[n] != '\n' && line[n] != '\r' &&
           line[n] != '#' && n < sizeof(buf) - 1) {
        buf[n] = line[n]; ++n;
    }
    while (n > 0 && (buf[n-1] == ' ' || buf[n-1] == '\t')) --n;
    buf[n] = 0;
    if (n == 0) return -1;

    /* Reuse keyset_parse_spec by routing through a tiny throwaway keyset.
     * That gets us 'default', 'simpleN', 'hex:...', 'base64:...', and
     * bare hex/base64 fallback for free. */
    keyset_t *tmp = keyset_create();
    if (!tmp) return -1;
    int rc = keyset_parse_spec(tmp, buf);
    if (rc < 0 || tmp->n_entries < 1) { keyset_destroy(tmp); return -1; }
    const keyset_entry_t *e = keyset_get(tmp, 0);
    if (!e || e->psk_len == 0 || e->psk_len > KEYSET_MAX_PSK_BYTES) {
        keyset_destroy(tmp);
        return -1;
    }
    memcpy(out_psk, e->psk, e->psk_len);
    *out_len = e->psk_len;
    keyset_destroy(tmp);
    return 0;
}

static int load_wordlist(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "psk-dict: cannot open %s\n", path);
        return -1;
    }
    g_candidates = calloc(PSK_MAX_CANDIDATES, sizeof(candidate_t));
    if (!g_candidates) { fclose(f); return -1; }

    char line[512];
    size_t line_no = 0;
    while (fgets(line, sizeof(line), f) && g_candidate_count < PSK_MAX_CANDIDATES) {
        ++line_no;
        if (line[0] == '#' || line[0] == '\n' || line[0] == 0) continue;
        candidate_t *c = &g_candidates[g_candidate_count];
        if (parse_psk_spec(line, c->psk, &c->psk_len) < 0) continue;
        /* Strip newline + cache the original spec for reporting. */
        size_t L = strlen(line);
        while (L > 0 && (line[L-1] == '\n' || line[L-1] == '\r' ||
                         line[L-1] == ' '  || line[L-1] == '\t')) {
            line[--L] = 0;
        }
        c->spec = strdup(line);
        ++g_candidate_count;
    }
    fclose(f);
    fprintf(stderr, "psk-dict: loaded %zu candidates from %s\n",
            g_candidate_count, path);
    if (g_candidate_count == 0) return -1;
    return 0;
}

/* ---- Discovery ---- */

/* Per-candidate decode-attempt callback. We just record whether a
 * decrypted result fired; we don't republish the frame here -- the
 * runtime-keyset add we do on success means the *next* frame on the
 * same channel will route through normal feed_publish_event. */
typedef struct {
    int decrypted;
    char channel_name[32];
} attempt_ctx_t;

static void attempt_cb(const mesh_event_t *ev, void *user)
{
    attempt_ctx_t *a = (attempt_ctx_t *)user;
    if (ev->decrypted) {
        a->decrypted = 1;
        if (ev->channel_name[0]) {
            strncpy(a->channel_name, ev->channel_name,
                    sizeof(a->channel_name) - 1);
        }
    }
}

static void emit_discovery(uint8_t channel_hash, const candidate_t *c,
                           const char *channel_name)
{
    /* Find the channel-hash byte in the frame to report. */
    char line[384];
    int n = snprintf(line, sizeof(line),
        "{\"event\":\"PSK_DISCOVERED\",\"channel\":%u,"
        "\"channel_name\":\"%s\",\"psk_bytes\":%zu,\"spec\":\"%s\"}\n",
        (unsigned)channel_hash,
        channel_name[0] ? channel_name : "(unknown)",
        c->psk_len, c->spec ? c->spec : "(unspecified)");
    if (n <= 0) return;
    fwrite(line, 1, (size_t)n, stdout); fflush(stdout);
    web_publish_line(line, (size_t)n);
    char sum[160];
    snprintf(sum, sizeof(sum),
             "PSK discovered: channel 0x%02x (%s) via %s",
             channel_hash,
             channel_name[0] ? channel_name : "unknown",
             c->spec ? c->spec : "unspecified");
    webhook_publish("PSK_DISCOVERED", line, (size_t)n, sum);
    fprintf(stderr, "[psk-dict] discovered key for channel 0x%02x via '%s' "
                    "(channel_name=%s)\n",
            channel_hash, c->spec ? c->spec : "?",
            channel_name[0] ? channel_name : "(unknown)");
}

/* Try each wordlist candidate against the given frame. On first match
 * that decrypts successfully, install the candidate into the live
 * runtime keyset under the recovered channel name and emit the
 * discovery event. */
static void try_candidates(const psk_frame_t *f)
{
    if (f->len < 16) return; /* too short for a mesh header + cipher */
    uint8_t channel_hash = f->bytes[13];
    if (g_cracked_hashes[channel_hash]) return;

    for (size_t i = 0; i < g_candidate_count; ++i) {
        if (!g_run) return; /* shutting down */
        const candidate_t *c = &g_candidates[i];

        /* Build a one-entry trial keyset registered under the observed
         * channel hash byte directly (not derived from name). The
         * channel name is unknown at this point and irrelevant for AES
         * decrypt -- only the PSK bytes matter. If the candidate is
         * the right PSK, parse_data_envelope will succeed and the
         * decoded payload may include a channel_name field that we can
         * use for the live keyset entry's display label. */
        keyset_t *tmp = keyset_create();
        if (!tmp) continue;
        if (keyset_add_raw(tmp, channel_hash, c->psk, c->psk_len, "(trial)") < 0) {
            keyset_destroy(tmp);
            continue;
        }
        attempt_ctx_t ctx = {0};
        mesh_packet_decode_with_radio(f->bytes, f->len, f->rssi_db, f->snr_db,
                                       f->sf, f->cr, f->bw_hz, tmp,
                                       attempt_cb, &ctx);
        keyset_destroy(tmp);
        if (ctx.decrypted) {
            /* Promote to the live keyset under the observed hash byte
             * so future frames on this channel route to this entry
             * regardless of what the channel name actually is. */
            keyset_t *live = app_get_keyset();
            if (live) {
                keyset_add_raw(live, channel_hash, c->psk, c->psk_len,
                               ctx.channel_name[0] ? ctx.channel_name : "(discovered)");
            }
            g_cracked_hashes[channel_hash] = 1;
            emit_discovery(channel_hash, c, ctx.channel_name);
            return;
        }
    }
}

/* ---- Worker thread ---- */

static void *psk_thread(void *arg)
{
    (void)arg;
#ifdef _GNU_SOURCE
    pthread_setname_np(pthread_self(), "psk-dict");
#endif
    while (g_run) {
        psk_frame_t f;
        pthread_mutex_lock(&g_q_mu);
        while (g_run && g_q_head == g_q_tail) {
            pthread_cond_wait(&g_q_cv, &g_q_mu);
        }
        if (!g_run) { pthread_mutex_unlock(&g_q_mu); break; }
        f = g_queue[g_q_tail];
        g_q_tail = (g_q_tail + 1) % PSK_QUEUE_SIZE;
        pthread_mutex_unlock(&g_q_mu);

        try_candidates(&f);
    }
    return NULL;
}

/* ---- Public API ---- */

bool psk_dict_init(const char *path)
{
    if (g_started) return true;
    if (!path) return false;
    if (load_wordlist(path) < 0) return false;
    g_run = 1;
    if (pthread_create(&g_thread, NULL, psk_thread, NULL) != 0) {
        g_run = 0;
        return false;
    }
    g_started = 1;
    return true;
}

void psk_dict_shutdown(void)
{
    if (!g_started) return;
    pthread_mutex_lock(&g_q_mu);
    g_run = 0;
    pthread_cond_broadcast(&g_q_cv);
    pthread_mutex_unlock(&g_q_mu);
    pthread_join(g_thread, NULL);
    if (g_candidates) {
        for (size_t i = 0; i < g_candidate_count; ++i) free(g_candidates[i].spec);
        free(g_candidates);
        g_candidates = NULL;
    }
    g_candidate_count = 0;
    g_started = 0;
}

void psk_dict_enqueue(const uint8_t *frame_bytes, size_t frame_len,
                      float rssi_db, float snr_db,
                      int sf, int cr, int bw_hz)
{
    if (!g_started || !frame_bytes || frame_len == 0) return;
    if (frame_len > PSK_FRAME_MAX_BYTES) frame_len = PSK_FRAME_MAX_BYTES;
    /* Pre-filter: only enqueue if we haven't already cracked this hash. */
    if (frame_len >= 14 && g_cracked_hashes[frame_bytes[13]]) return;

    pthread_mutex_lock(&g_q_mu);
    int next = (g_q_head + 1) % PSK_QUEUE_SIZE;
    if (next == g_q_tail) {
        /* Queue full; drop oldest by advancing tail. The work backlog
         * has bounded latency at the cost of dropping some samples for
         * very busy mesh environments. */
        g_q_tail = (g_q_tail + 1) % PSK_QUEUE_SIZE;
    }
    psk_frame_t *e = &g_queue[g_q_head];
    memcpy(e->bytes, frame_bytes, frame_len);
    e->len = frame_len;
    e->rssi_db = rssi_db; e->snr_db = snr_db;
    e->sf = sf; e->cr = cr; e->bw_hz = bw_hz;
    g_q_head = next;
    pthread_cond_signal(&g_q_cv);
    pthread_mutex_unlock(&g_q_mu);
}
