/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: CoT (Cursor-on-Target) XML multicast republish.
 *
 * Converts decoded packets with positional data into standard
 * Cursor-on-Target XML and broadcasts to a multicast group (default
 * 239.2.3.1:6969). ATAK-CIV / WinTAK / iTAK on the same LAN pick them
 * up automatically -- no TAK Server needed.
 *
 * Two emission paths:
 *   - cot_publish_atak()     -- ATAK port 72 packets, with full
 *                               team/role/battery and either PLI or
 *                               GeoChat. Role gets mapped to a richer
 *                               CoT type (medic/sniper/HQ).
 *   - cot_publish_position() -- regular Meshtastic POSITION port 3
 *                               packets, labelled with the node's
 *                               long_name from node_db (NODEINFO).
 *
 * Endpoint can be set at startup via --cot-multicast and changed at
 * runtime via cot_set_endpoint() (called from the web /api/cot-multicast
 * handler).
 *
 */

#ifndef COT_H
#define COT_H

#include "mesh_decoders.h"
#include "mesh_packet.h"

void cot_init(void);
void cot_shutdown(void);

/* Reconfigure the multicast destination at runtime. host=NULL or
 * port=0 disables CoT output. */
int  cot_set_endpoint(const char *host, int port);

void cot_publish_atak    (const mesh_event_t *ev, const mesh_atak_t *atak);
void cot_publish_position(const mesh_event_t *ev, const mesh_position_t *pos);

#endif
