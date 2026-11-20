/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * meshtastic-sniffer: transmit path for the dashboard send box.
 *
 * POST /api/tx takes a URL-encoded form (text, to, channel, psk, preset,
 * slot, gain, amp, hop, long_name, short_name). The frame is built and
 * modulated by tools/meshtastic_tx.py (gr-lora_sdr) into int8 IQ, then:
 *   - with --hackrf: played on the sniffer's own HackRF (RX pauses), or
 *   - otherwise: played on a separate HackRF via hackrf_transfer.
 *
 * Disabled unless the sniffer was started with --tx.
 */

#ifndef TX_H
#define TX_H

#include "c2.h"

#include <stddef.h>

/* JSON describing whether TX is available, for GET /api/tx. */
void tx_status_json(char *out, size_t cap);

/* Handle a POST /api/tx body. Blocks until the packet(s) are on the air. */
void tx_send(const char *body, c2_response_t *out);

#endif /* TX_H */
