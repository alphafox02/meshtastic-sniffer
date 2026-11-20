/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * meshtastic-sniffer: samples pushed in by a host application.
 *
 * With --external-source the sniffer opens no SDR itself: the host (the
 * Android app, which reaches the HackRF through hackrf_android over USB)
 * tunes the radio and pushes interleaved int8 I/Q with ext_src_push().
 * Transmitting goes back to the host through tx_set_player() (tx.h).
 */

#ifndef EXT_SRC_H
#define EXT_SRC_H

#include <stddef.h>
#include <stdint.h>

/* Backend thread for start_input(): stays alive while the sniffer runs. */
void *ext_src_thread(void *arg);

/* Feed nbytes of interleaved int8 I/Q (nbytes/2 complex samples). Returns
 * 0 if queued, -1 if the sniffer isn't running yet / any more or input is
 * paused. Copies the data; safe from any thread. */
int ext_src_push(const int8_t *iq, size_t nbytes);

/* Drop pushed samples while the host's HackRF transmits. */
void ext_src_set_paused(int paused);

/* Library entry points (the host runs sniffer_main on its own thread). */
int  sniffer_main(int argc, char **argv);
void sniffer_request_stop(void);

#endif /* EXT_SRC_H */
