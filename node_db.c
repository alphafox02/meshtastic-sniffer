/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: in-memory node-info cache.
 *
 */

#include "node_db.h"

#include <pthread.h>
#include <string.h>

#define NODE_DB_CAP 1024

static node_record_t  g_nodes[NODE_DB_CAP];
static int            g_count = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static node_record_t *find_locked(uint32_t id)
{
    for (int i = 0; i < g_count; ++i)
        if (g_nodes[i].id == id) return &g_nodes[i];
    return NULL;
}

void node_db_remember(uint32_t id, const char *long_name,
                      const char *short_name, uint32_t hw_model, uint32_t role)
{
    pthread_mutex_lock(&g_lock);
    node_record_t *n = find_locked(id);
    if (!n) {
        if (g_count >= NODE_DB_CAP) {
            /* Evict oldest entry: simple FIFO ring. */
            memmove(&g_nodes[0], &g_nodes[1], sizeof(g_nodes[0]) * (NODE_DB_CAP - 1));
            g_count = NODE_DB_CAP - 1;
        }
        n = &g_nodes[g_count++];
        memset(n, 0, sizeof(*n));
        n->id = id;
    }
    if (long_name && *long_name)
        strncpy(n->long_name, long_name, sizeof(n->long_name) - 1);
    if (short_name && *short_name)
        strncpy(n->short_name, short_name, sizeof(n->short_name) - 1);
    if (hw_model) n->hw_model = hw_model;
    if (role)     n->role     = role;
    pthread_mutex_unlock(&g_lock);
}

bool node_db_lookup(uint32_t id, node_record_t *out)
{
    bool ok = false;
    pthread_mutex_lock(&g_lock);
    node_record_t *n = find_locked(id);
    if (n) { *out = *n; ok = true; }
    pthread_mutex_unlock(&g_lock);
    return ok;
}
