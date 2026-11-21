/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * meshtastic-sniffer: public-key (PKI) direct messages, as in Meshtastic
 * firmware 2.5+ (src/mesh/CryptoEngine.cpp):
 *
 *   shared = SHA-256(X25519(our_private, their_public))
 *   nonce  = LE32(packet_id) | LE32(extra_nonce) | LE32(from_node) | 0x00  (13 bytes)
 *   body   = AES-256-CCM(shared, nonce, tag 8 bytes)(Data)
 *            | tag (8) | LE32(extra_nonce)                    (+12 bytes)
 *   header channel-hash byte = 0
 *
 * The transmit tool encrypts our outgoing DMs; this module holds the TX
 * node's key pair, caches peers' public keys (learned from NodeInfo or
 * supplied by the operator) and decrypts PKI packets addressed to the TX
 * node, so the answers to our DMs and requests show up decoded.
 */

#ifndef PKI_H
#define PKI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PKI_KEY_LEN   32
#define PKI_OVERHEAD  12   /* CCM tag (8) + extra nonce (4) */

/* Load the private key from path (base64, as the Meshtastic apps show it),
 * creating the file (mode 0600) with a new key if it doesn't exist.
 * path == NULL: a new key that lives only as long as the process.
 * Returns 0 on success, -1 (with a message on stderr) on failure. */
int  pki_init(const char *path);
bool pki_enabled(void);

void     pki_set_own_node(uint32_t node);
uint32_t pki_own_node(void);
void     pki_public_key(uint8_t out[PKI_KEY_LEN]);
void     pki_private_key(uint8_t out[PKI_KEY_LEN]);

/* Peer public keys, by node number. An all-zero key is ignored. */
void pki_note_peer(uint32_t node, const uint8_t key[PKI_KEY_LEN]);
bool pki_peer_key(uint32_t node, uint8_t out[PKI_KEY_LEN]);

/* Base64 of exactly 32 bytes (44 chars + NUL). */
void pki_b64_encode(const uint8_t in[PKI_KEY_LEN], char out[45]);
/* Returns 0 if s is base64 (standard or URL-safe, padding optional) of
 * exactly 32 bytes. Hex (64 chars) is accepted too. */
int  pki_key_decode(const char *s, uint8_t out[PKI_KEY_LEN]);

/* Pure crypto, for any key pair (also used by the tests).
 * pki_shared_key: 0 on success, -1 for a weak / invalid public key. */
int pki_shared_key(const uint8_t priv[PKI_KEY_LEN], const uint8_t peer_pub[PKI_KEY_LEN],
                   uint8_t shared[32]);
/* Decrypt a PKI body (ciphertext | tag | extra nonce) sent by from_node.
 * Returns the plaintext length, or -1 when authentication fails. */
int pki_decrypt_body(const uint8_t shared[32], uint32_t from_node, uint32_t packet_id,
                     const uint8_t *body, size_t n, uint8_t *out, size_t cap);
/* Encrypt plaintext into out (n + PKI_OVERHEAD bytes). Returns that
 * length or -1. */
int pki_encrypt_body(const uint8_t shared[32], uint32_t from_node, uint32_t packet_id,
                     uint32_t extra_nonce, const uint8_t *plain, size_t n,
                     uint8_t *out, size_t cap);

/* mesh_packet decrypt hook: decrypts PKI packets sent to our TX node by a
 * peer whose public key we know. Same contract as pki_decrypt_body. */
int pki_mesh_hook(uint32_t from, uint32_t to, uint32_t packet_id,
                  const uint8_t *body, size_t n, uint8_t *out, size_t cap);

#endif /* PKI_H */
