/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: built-in web dashboard.
 *
 * HTTP server on port opt_web_port. Endpoints:
 *   GET /              -- embedded HTML+JS dashboard with Leaflet map
 *   GET /events        -- Server-Sent Events (text/event-stream) feed
 *
 * web_publish_line() pushes one event to all connected SSE clients
 * non-blocking; slow clients drop messages.
 *
 */

#ifndef WEB_H
#define WEB_H

#include <stddef.h>

void web_init(int port);
void web_publish_line(const char *json, size_t len);
void web_shutdown(void);

#endif
