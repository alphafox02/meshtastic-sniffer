/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * meshtastic-sniffer: LoRa transmit chain in C, so the sniffer can
 * transmit without python/gr-lora_sdr (and on Android).
 *
 * A port of gr-lora_sdr's TX blocks (Tapparel/EPFL), same order and same
 * bit layout:
 *   whitening -> header (explicit) -> add_crc -> hamming_enc ->
 *   interleaver -> gray_demap -> modulate
 * tests/tx/lora_tx_check.py holds it symbol-for-symbol against the real
 * gr-lora_sdr blocks and the sniffer's own demodulator decodes its IQ.
 */

#ifndef LORA_TX_H
#define LORA_TX_H

#include <complex.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Symbols for one explicit-header, CRC-on frame. cr is 1..4 (4/5..4/8).
 * ldro: low data rate optimisation (gr-lora_sdr "auto" = symbol > 16 ms,
 * see lora_tx_ldro_auto). Returns the symbol count, or -1 if cap is too
 * small / arguments are invalid. */
int lora_tx_symbols(const uint8_t *payload, size_t len, int sf, int cr, bool ldro,
                    uint32_t *syms, size_t cap);

bool lora_tx_ldro_auto(int sf, int bw_hz);

/* Number of complex samples lora_tx_modulate writes. */
size_t lora_tx_num_samples(int nsyms, int sf, int os, int preamble_len, size_t pad);

/* Baseband IQ: preamble_len upchirps, two sync-word chirps (sync_word
 * nibbles << 3, e.g. 0x2B for Meshtastic), 2.25 downchirps, the payload
 * symbols, then pad zero samples. os = sample_rate / bandwidth (integer).
 * Returns the sample count, 0 if cap is too small. */
size_t lora_tx_modulate(const uint32_t *syms, int nsyms, int sf, int os, int preamble_len,
                        uint8_t sync_word, size_t pad, float complex *out, size_t cap);

#endif /* LORA_TX_H */
