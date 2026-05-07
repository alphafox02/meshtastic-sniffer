/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: JSON output sink.
 *
 * Serialises decoded packets to newline-delimited JSON. Writes to:
 *   - stdout (always, when feed_init is called)
 *   - UDP endpoints (any number from --feed=HOST:PORT)
 *   - MQTT (if enabled)
 *   - ZMQ PUB (if enabled)
 *
 * Per-packet output is non-blocking on every sink: a stalled
 * downstream consumer drops a message rather than freezing decode.
 *
 */

#ifndef FEED_H
#define FEED_H

#include "mesh_packet.h"
#include "mesh_decoders.h"

void feed_init(void);
void feed_shutdown(void);

/* Hand a fully-decoded mesh_event to the feed. The feed reruns
 * per-port decoders to populate POSITION/USER/TELEMETRY/etc fields
 * before serialising. Callable from any thread. */
void feed_publish_event(const mesh_event_t *ev);

#endif
