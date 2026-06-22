/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Opt-in webhook sink. See webhook.h.
 */

#include "webhook.h"

#include <curl/curl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WEBHOOK_QUEUE_CAP    256
#define WEBHOOK_MAX_EVENTS    32
#define WEBHOOK_NAME_MAX      48

/* Default event allowlist when --webhook-on is not given. Tuned to
 * "alerts an operator wants to know about right now" -- excludes
 * REPLAY_SUSPECTED (too noisy on busy meshes) and STATS / CHAN_SNR
 * (heartbeats, not events). */
static const char *DEFAULT_EVENTS[] = {
    "PSK_DISCOVERED",
    "OFF_GRID_LORA",
    "GEOFENCE_ENTRY",
    "GEOFENCE_EXIT",
    NULL,
};

typedef struct {
    char  *body;
    size_t len;
} qitem_t;

static const char       *g_url           = NULL;
static int               g_timeout_ms    = 1000;
static webhook_format_t  g_format        = WEBHOOK_FORMAT_RAW;
static char              g_allow[WEBHOOK_MAX_EVENTS][WEBHOOK_NAME_MAX];
static int               g_allow_n       = 0;

static qitem_t         g_queue[WEBHOOK_QUEUE_CAP];
static int             g_head           = 0;   /* next pop slot */
static int             g_tail           = 0;   /* next push slot */
static int             g_count          = 0;
static pthread_mutex_t g_mu             = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cv             = PTHREAD_COND_INITIALIZER;
static atomic_bool     g_run            = false;
static pthread_t       g_tid;
static bool            g_started        = false;

static _Atomic uint64_t g_queued_total  = 0;
static _Atomic uint64_t g_sent_total    = 0;
static _Atomic uint64_t g_dropped_total = 0;
static _Atomic uint64_t g_failed_total  = 0;

static bool event_allowed(const char *name)
{
    for (int i = 0; i < g_allow_n; ++i)
        if (strcmp(g_allow[i], name) == 0) return true;
    return false;
}

/* libcurl write-callback that drops the response body. We do not
 * surface server replies to the operator; the request either succeeded
 * (HTTP 2xx) or counted as a failure. */
static size_t drop_body(void *ptr, size_t size, size_t nmemb, void *user)
{
    (void)ptr; (void)user;
    return size * nmemb;
}

static void post_one(CURL *curl, qitem_t *q)
{
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, "User-Agent: meshtastic-sniffer/webhook");

    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, g_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, q->body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)q->len);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)g_timeout_ms);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, (long)g_timeout_ms);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, drop_body);
    /* Do not follow redirects. The webhook URL is the operator's exact
     * intended destination; if Slack/Discord/etc. ever returned a 3xx
     * to a third party, we would silently leak the alert payload. */
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

    CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (rc == CURLE_OK && status >= 200 && status < 300) {
        atomic_fetch_add(&g_sent_total, 1);
    } else {
        atomic_fetch_add(&g_failed_total, 1);
    }
    curl_slist_free_all(hdrs);
}

static void *webhook_thread(void *arg)
{
    (void)arg;
    CURL *curl = curl_easy_init();
    if (!curl) {
        /* Mark the sink as not-running so webhook_publish() stops
         * enqueueing; otherwise events silently pile up to the queue
         * cap and then start counting as drops with no clue why. */
        fprintf(stderr, "webhook: curl_easy_init failed; webhook disabled\n");
        atomic_store(&g_run, false);
        return NULL;
    }
    pthread_mutex_lock(&g_mu);
    while (atomic_load(&g_run)) {
        while (g_count == 0 && atomic_load(&g_run))
            pthread_cond_wait(&g_cv, &g_mu);
        if (!atomic_load(&g_run)) break;
        qitem_t item = g_queue[g_head];
        g_head = (g_head + 1) % WEBHOOK_QUEUE_CAP;
        --g_count;
        pthread_mutex_unlock(&g_mu);

        post_one(curl, &item);
        free(item.body);

        pthread_mutex_lock(&g_mu);
    }
    pthread_mutex_unlock(&g_mu);

    /* Drain remaining (but do not block forever; we are at shutdown). */
    pthread_mutex_lock(&g_mu);
    while (g_count > 0) {
        qitem_t item = g_queue[g_head];
        g_head = (g_head + 1) % WEBHOOK_QUEUE_CAP;
        --g_count;
        free(item.body);
    }
    pthread_mutex_unlock(&g_mu);

    curl_easy_cleanup(curl);
    return NULL;
}

webhook_format_t webhook_format_parse(const char *s)
{
    if (!s || !*s) return WEBHOOK_FORMAT_RAW;
    if (strcasecmp(s, "raw")     == 0) return WEBHOOK_FORMAT_RAW;
    if (strcasecmp(s, "slack")   == 0) return WEBHOOK_FORMAT_SLACK;
    if (strcasecmp(s, "discord") == 0) return WEBHOOK_FORMAT_DISCORD;
    /* Unknown value -- complain loudly. Without this an operator
     * who typo'd 'slcak' would silently post raw JSON to a Slack URL
     * and wonder why Slack swallowed the messages. */
    fprintf(stderr, "webhook: unknown --webhook-format '%s'; expected one of raw, slack, discord. "
                    "Falling back to raw.\n", s);
    return WEBHOOK_FORMAT_RAW;
}

/* Build a privacy-safe view of `url` for the startup log. Webhook URLs
 * frequently encode a bearer-equivalent secret in the path (Slack:
 * /services/T../B../<secret>; Discord: /api/webhooks/<id>/<token>), so
 * the full URL belongs in the operator's config, not in journald. We
 * keep the scheme + host visible (so operators can see WHERE we are
 * about to post) and replace the path component with '<redacted>'. */
static void redacted_url(const char *url, char *out, size_t out_cap)
{
    if (!url || !out || out_cap == 0) return;
    out[0] = 0;
    const char *scheme_end = strstr(url, "://");
    if (!scheme_end) {
        snprintf(out, out_cap, "<redacted>");
        return;
    }
    const char *host = scheme_end + 3;
    const char *path = strchr(host, '/');
    if (!path) path = host + strlen(host);
    snprintf(out, out_cap, "%.*s/<redacted>",
             (int)(path - url), url);
}

/* JSON-escape `src` into `dst`. Returns bytes written (not counting
 * the NUL). Caller sizes dst at >= 6*srclen + 1 in the worst case
 * (every byte escapes to \uXXXX). At normal alphanumeric input the
 * inflation is zero. */
static size_t json_escape(const char *src, size_t srclen,
                          char *dst, size_t dstcap)
{
    size_t w = 0;
    for (size_t i = 0; i < srclen; ++i) {
        unsigned char c = (unsigned char)src[i];
        const char *esc = NULL;
        char ubuf[8];
        switch (c) {
        case '"':  esc = "\\\""; break;
        case '\\': esc = "\\\\"; break;
        case '\n': esc = "\\n";  break;
        case '\r': esc = "\\r";  break;
        case '\t': esc = "\\t";  break;
        case '\b': esc = "\\b";  break;
        case '\f': esc = "\\f";  break;
        default:
            if (c < 0x20) {
                snprintf(ubuf, sizeof(ubuf), "\\u%04x", c);
                esc = ubuf;
            }
            break;
        }
        if (esc) {
            size_t n = strlen(esc);
            if (w + n + 1 > dstcap) break;
            memcpy(dst + w, esc, n);
            w += n;
        } else {
            if (w + 2 > dstcap) break;
            dst[w++] = (char)c;
        }
    }
    if (w < dstcap) dst[w] = 0;
    return w;
}

int webhook_init(const char *url, const char *event_csv,
                 int timeout_ms, webhook_format_t format)
{
    if (!url || !*url) return 0;  /* not configured; quiet no-op */
    if (g_started) return 0;

    if (timeout_ms < 100) timeout_ms = 100;
    if (timeout_ms > 30000) timeout_ms = 30000;
    g_timeout_ms = timeout_ms;
    g_url        = url;
    g_format     = format;

    if (event_csv && *event_csv) {
        /* Parse the comma-separated allowlist. Whitespace either side
         * of an entry is trimmed. Anything longer than WEBHOOK_NAME_MAX
         * is truncated; anything past WEBHOOK_MAX_EVENTS is dropped
         * with a stderr warning. */
        const char *p = event_csv;
        while (*p && g_allow_n < WEBHOOK_MAX_EVENTS) {
            while (*p == ',' || *p == ' ' || *p == '\t') ++p;
            const char *start = p;
            while (*p && *p != ',') ++p;
            const char *e = p;
            while (e > start && (e[-1] == ' ' || e[-1] == '\t')) --e;
            size_t n = (size_t)(e - start);
            if (n == 0) continue;
            if (n >= WEBHOOK_NAME_MAX) n = WEBHOOK_NAME_MAX - 1;
            memcpy(g_allow[g_allow_n], start, n);
            g_allow[g_allow_n][n] = 0;
            ++g_allow_n;
        }
        if (*p) fprintf(stderr,
            "webhook: more than %d --webhook-on entries; remainder ignored\n",
            WEBHOOK_MAX_EVENTS);
    } else {
        for (int i = 0; DEFAULT_EVENTS[i] && i < WEBHOOK_MAX_EVENTS; ++i) {
            strncpy(g_allow[i], DEFAULT_EVENTS[i], WEBHOOK_NAME_MAX - 1);
            g_allow[i][WEBHOOK_NAME_MAX - 1] = 0;
            ++g_allow_n;
        }
    }

    /* libcurl global init is idempotent; if some other subsystem
     * already called it, this is a no-op. */
    curl_global_init(CURL_GLOBAL_DEFAULT);

    atomic_store(&g_run, true);
    if (pthread_create(&g_tid, NULL, webhook_thread, NULL) != 0) {
        fprintf(stderr, "webhook: pthread_create failed; webhook disabled\n");
        atomic_store(&g_run, false);
        return -1;
    }
    g_started = true;
    const char *fmt_name =
        (g_format == WEBHOOK_FORMAT_SLACK)   ? "slack"   :
        (g_format == WEBHOOK_FORMAT_DISCORD) ? "discord" : "raw";
    char safe_url[256];
    redacted_url(g_url, safe_url, sizeof(safe_url));
    fprintf(stderr, "webhook: enabled, url=%s, format=%s, allowlist=%d events, timeout=%d ms\n",
            safe_url, fmt_name, g_allow_n, g_timeout_ms);
    return 0;
}

void webhook_stop(void)
{
    if (!g_started) return;
    atomic_store(&g_run, false);
    pthread_mutex_lock(&g_mu);
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
    pthread_join(g_tid, NULL);
    g_started = false;
}

void webhook_publish(const char *event_name,
                     const char *json, size_t len,
                     const char *summary)
{
    if (!g_started || !event_name) return;
    if (!event_allowed(event_name)) return;

    /* Build the body in the wire shape requested by --webhook-format.
     * RAW posts the sniffer's own JSON line verbatim. SLACK and
     * DISCORD wrap the summary in their expected envelope so the URL
     * can be a hosted incoming-webhook directly. Falls back to the
     * event_name if no summary was supplied for an event. */
    char *body = NULL;
    size_t body_len = 0;

    if (g_format == WEBHOOK_FORMAT_RAW) {
        if (!json || len == 0) return;
        body = malloc(len);
        if (!body) { atomic_fetch_add(&g_dropped_total, 1); return; }
        memcpy(body, json, len);
        body_len = len;
    } else {
        const char *text = (summary && *summary) ? summary : event_name;
        size_t tlen = strlen(text);
        /* worst-case 6x inflation per char if everything escapes. */
        size_t cap = tlen * 6 + 64;
        char *esc = malloc(cap);
        if (!esc) { atomic_fetch_add(&g_dropped_total, 1); return; }
        size_t elen = json_escape(text, tlen, esc, cap);
        const char *key = (g_format == WEBHOOK_FORMAT_SLACK) ? "text" : "content";
        size_t out_cap = elen + 32;
        body = malloc(out_cap);
        if (!body) { free(esc); atomic_fetch_add(&g_dropped_total, 1); return; }
        int wn = snprintf(body, out_cap, "{\"%s\":\"%.*s\"}", key, (int)elen, esc);
        free(esc);
        if (wn < 0) { free(body); atomic_fetch_add(&g_dropped_total, 1); return; }
        body_len = (size_t)wn;
    }

    pthread_mutex_lock(&g_mu);
    if (g_count >= WEBHOOK_QUEUE_CAP) {
        pthread_mutex_unlock(&g_mu);
        free(body);
        atomic_fetch_add(&g_dropped_total, 1);
        return;
    }
    g_queue[g_tail].body = body;
    g_queue[g_tail].len  = body_len;
    g_tail = (g_tail + 1) % WEBHOOK_QUEUE_CAP;
    ++g_count;
    pthread_cond_signal(&g_cv);
    pthread_mutex_unlock(&g_mu);
    atomic_fetch_add(&g_queued_total, 1);
}

uint64_t webhook_queued_total(void)  { return atomic_load(&g_queued_total); }
uint64_t webhook_sent_total(void)    { return atomic_load(&g_sent_total); }
uint64_t webhook_dropped_total(void) { return atomic_load(&g_dropped_total); }
uint64_t webhook_failed_total(void)  { return atomic_load(&g_failed_total); }
