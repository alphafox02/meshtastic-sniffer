/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Opt-in webhook sink. POSTs event notifications to an operator-
 * configured URL on a background thread so it cannot stall decode or
 * dashboard publishing.
 *
 * Enabled with --webhook-url=URL. Default event allowlist is a small
 * curated set (PSK_DISCOVERED, OFF_GRID_LORA, GEOFENCE_ENTRY,
 * GEOFENCE_EXIT). Override with --webhook-on=A,B,C. Per-publish timeout
 * is --webhook-timeout-ms=N (default 1000).
 *
 * Wire format is --webhook-format={raw|slack|discord}:
 *   raw     -- POST the sniffer's own event JSON verbatim. For custom
 *              receivers / bridges / n8n / Zapier.
 *   slack   -- POST {"text":"<summary>"} so the URL can be a Slack
 *              incoming-webhook directly.
 *   discord -- POST {"content":"<summary>"} for Discord webhooks.
 *
 * Bounded queue: webhook_publish() drops when the queue is full and
 * bumps a counter the dashboard can read. The decode path never blocks
 * on HTTP.
 */

#ifndef WEBHOOK_H
#define WEBHOOK_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    WEBHOOK_FORMAT_RAW = 0,
    WEBHOOK_FORMAT_SLACK,
    WEBHOOK_FORMAT_DISCORD,
} webhook_format_t;

/* Parse the --webhook-format= value. NULL/empty/unknown returns RAW. */
webhook_format_t webhook_format_parse(const char *s);

/* Start the worker thread. `url` must outlive the program (we store
 * the pointer, no copy). `event_csv` is a comma-separated list of
 * event names to allow; NULL or "" means use the safe default
 * allowlist. `timeout_ms` is the per-POST timeout (clamped 100..30000).
 * `format` selects the wire shape. Returns 0 on success.
 * Safe to call once at startup. */
int  webhook_init(const char *url, const char *event_csv,
                  int timeout_ms, webhook_format_t format);

/* Stop the worker thread. Drains nothing; in-flight requests time
 * out per their existing timeout. Safe to call at shutdown. */
void webhook_stop(void);

/* Non-blocking enqueue. `event_name` is checked against the allowlist;
 * if it doesn't match, returns silently and counts nothing.
 *
 * `summary` is a short human-readable description of the event used
 * only when the wire format is slack/discord. Pass NULL when no
 * summary is available; the slack/discord paths fall back to the
 * event_name. The `json` buffer is what gets posted under the raw
 * format. */
void webhook_publish(const char *event_name,
                     const char *json, size_t len,
                     const char *summary);

/* Counters for the dashboard / stats heartbeat. */
uint64_t webhook_queued_total(void);
uint64_t webhook_sent_total(void);
uint64_t webhook_dropped_total(void);
uint64_t webhook_failed_total(void);  /* enqueued but POST failed */

#endif
