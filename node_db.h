/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: in-memory node-info cache.
 *
 * Tiny map from from-node id (uint32) to last-seen long/short name and
 * hardware-model. Populated by NODEINFO packets, queried by POSITION
 * packets so CoT republish can label markers with a real callsign.
 *
 */

#ifndef NODE_DB_H
#define NODE_DB_H

#include <stdbool.h>
#include <stdint.h>

#define NODE_DB_LONG_NAME 64
#define NODE_DB_SHORT_NAME 8

typedef struct node_record {
    uint32_t id;
    char     long_name[NODE_DB_LONG_NAME];
    char     short_name[NODE_DB_SHORT_NAME];
    uint32_t hw_model;
    uint32_t role;
} node_record_t;

void node_db_remember(uint32_t id, const char *long_name,
                      const char *short_name, uint32_t hw_model, uint32_t role);

/* Returns true and fills *out if known; returns false otherwise. */
bool node_db_lookup(uint32_t id, node_record_t *out);

#endif
