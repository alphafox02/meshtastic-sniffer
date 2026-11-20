/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * meshtastic-sniffer: transmit path for the dashboard send box.
 *
 * POST /api/tx takes a URL-encoded form (kind, text, to, reply_id, ack,
 * channel, psk, preset, slot, gain, amp, hop, long_name, short_name).
 * kind=text (default) sends a text message, a reply when reply_id is set;
 * kind=position|nodeinfo|telemetry|traceroute sends the matching request
 * (want_response) to the node in `to`. The band is --tx-region, else
 * --region. The frame is built and
 * modulated in C (mesh_tx.c + lora_tx.c; tools/meshtastic_tx.py with
 * --tx-tool) into int8 IQ, then:
 *   - with --hackrf: played on the sniffer's own HackRF (RX pauses), or
 *   - with a player set by the host app (Android): on its HackRF, or
 *   - otherwise: played on a separate HackRF via hackrf_transfer.
 *
 * Disabled unless the sniffer was started with --tx.
 */

#ifndef TX_H
#define TX_H

#include "c2.h"

#include <stddef.h>
#include <stdint.h>

/* Set up the TX node identity (node number + PKI key pair, --tx-key).
 * Call once at startup when --tx is given. Returns 0, or -1 on a bad
 * key file. */
int tx_init(void);

/* Play int8 I/Q on a HackRF owned by the host app (Android: hackrf_android
 * over USB). Same contract as hackrf_tx_play: returns 0 once the samples
 * are on the air, and resumes reception afterwards. With a player set,
 * --ppm applies to TX too (the same HackRF receives). */
typedef int (*tx_player_fn)(const int8_t *iq, size_t n, uint64_t lo_hz, uint32_t rate,
                            int gain, int amp, char *err, size_t errlen);
void tx_set_player(tx_player_fn fn, const char *name);

/* JSON describing whether TX is available, for GET /api/tx. */
void tx_status_json(char *out, size_t cap);

/* Handle a POST /api/tx body. Blocks until the packet(s) are on the air. */
void tx_send(const char *body, c2_response_t *out);

#endif /* TX_H */
