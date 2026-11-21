/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * meshtastic-sniffer: public-key (PKI) direct messages. See pki.h.
 */

#define _GNU_SOURCE
#include "pki.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PKI_PEERS 1024

typedef struct {
    uint32_t node;
    uint8_t  key[PKI_KEY_LEN];
} pki_peer_t;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static bool       g_enabled;
static uint32_t   g_own_node;
static uint8_t    g_priv[PKI_KEY_LEN], g_pub[PKI_KEY_LEN];
static pki_peer_t g_peers[PKI_PEERS];
static int        g_npeers, g_next_evict;

static bool all_zero(const uint8_t *k, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; ++i) acc |= k[i];
    return acc == 0;
}

/* ---- base64 / hex ---- */

void pki_b64_encode(const uint8_t in[PKI_KEY_LEN], char out[45])
{
    EVP_EncodeBlock((unsigned char *)out, in, PKI_KEY_LEN);  /* 44 chars + NUL */
}

int pki_key_decode(const char *s, uint8_t out[PKI_KEY_LEN])
{
    if (!s) return -1;
    while (isspace((unsigned char)*s)) ++s;
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1])) --n;

    if (n == 64) {  /* hex, as the sniffer's JSON feed prints it */
        bool hex = true;
        for (size_t i = 0; i < 64 && hex; ++i) hex = isxdigit((unsigned char)s[i]) != 0;
        if (hex) {
            for (size_t i = 0; i < PKI_KEY_LEN; ++i) {
                unsigned v;
                if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
                out[i] = (uint8_t)v;
            }
            return 0;
        }
    }
    /* base64: map URL-safe to standard and restore padding. */
    char buf[48];
    if (n < 43 || n > 44) return -1;
    for (size_t i = 0; i < n; ++i) {
        char c = s[i];
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
        if (!isalnum((unsigned char)c) && c != '+' && c != '/' && !(c == '=' && i == 43))
            return -1;
        buf[i] = c;
    }
    if (n == 43) buf[n++] = '=';
    buf[n] = 0;
    unsigned char tmp[36];
    int got = EVP_DecodeBlock(tmp, (const unsigned char *)buf, (int)n);
    if (got != 33) return -1;  /* 44 chars with one '=' decode to 33 incl. padding */
    memcpy(out, tmp, PKI_KEY_LEN);
    return 0;
}

/* ---- key pair ---- */

static int derive_public(const uint8_t priv[PKI_KEY_LEN], uint8_t pub[PKI_KEY_LEN])
{
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, PKI_KEY_LEN);
    if (!k) return -1;
    size_t len = PKI_KEY_LEN;
    int ok = EVP_PKEY_get_raw_public_key(k, pub, &len) == 1 && len == PKI_KEY_LEN;
    EVP_PKEY_free(k);
    return ok ? 0 : -1;
}

static int new_private(uint8_t priv[PKI_KEY_LEN])
{
    if (RAND_bytes(priv, PKI_KEY_LEN) != 1) return -1;
    priv[0] &= 248;            /* X25519 clamping, as the apps store it */
    priv[31] &= 127;
    priv[31] |= 64;
    return 0;
}

int pki_init(const char *path)
{
    uint8_t priv[PKI_KEY_LEN];
    if (!path) {
        if (new_private(priv) != 0) {
            fprintf(stderr, "pki: RAND_bytes failed\n");
            return -1;
        }
    } else {
        FILE *f = fopen(path, "r");
        if (f) {
            char line[128] = "";
            if (!fgets(line, sizeof(line), f)) line[0] = 0;
            fclose(f);
            if (pki_key_decode(line, priv) != 0 || all_zero(priv, PKI_KEY_LEN)) {
                fprintf(stderr, "pki: %s does not hold a base64 32-byte private key\n", path);
                return -1;
            }
        } else if (errno == ENOENT) {
            if (new_private(priv) != 0) {
                fprintf(stderr, "pki: RAND_bytes failed\n");
                return -1;
            }
            int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (fd < 0) {
                fprintf(stderr, "pki: cannot create %s: %s\n", path, strerror(errno));
                return -1;
            }
            char b64[45];
            pki_b64_encode(priv, b64);
            dprintf(fd, "%s\n", b64);
            if (close(fd) != 0) {
                fprintf(stderr, "pki: cannot write %s: %s\n", path, strerror(errno));
                return -1;
            }
            fprintf(stderr, "pki: created a new TX private key in %s\n", path);
        } else {
            fprintf(stderr, "pki: cannot read %s: %s\n", path, strerror(errno));
            return -1;
        }
    }
    uint8_t pub[PKI_KEY_LEN];
    if (derive_public(priv, pub) != 0) {
        fprintf(stderr, "pki: cannot derive the public key\n");
        return -1;
    }
    pthread_mutex_lock(&g_lock);
    memcpy(g_priv, priv, PKI_KEY_LEN);
    memcpy(g_pub, pub, PKI_KEY_LEN);
    g_enabled = true;
    pthread_mutex_unlock(&g_lock);
    return 0;
}

bool pki_enabled(void)
{
    pthread_mutex_lock(&g_lock);
    bool e = g_enabled;
    pthread_mutex_unlock(&g_lock);
    return e;
}

void pki_set_own_node(uint32_t node)
{
    pthread_mutex_lock(&g_lock);
    g_own_node = node;
    pthread_mutex_unlock(&g_lock);
}

uint32_t pki_own_node(void)
{
    pthread_mutex_lock(&g_lock);
    uint32_t n = g_own_node;
    pthread_mutex_unlock(&g_lock);
    return n;
}

void pki_public_key(uint8_t out[PKI_KEY_LEN])
{
    pthread_mutex_lock(&g_lock);
    memcpy(out, g_pub, PKI_KEY_LEN);
    pthread_mutex_unlock(&g_lock);
}

void pki_private_key(uint8_t out[PKI_KEY_LEN])
{
    pthread_mutex_lock(&g_lock);
    memcpy(out, g_priv, PKI_KEY_LEN);
    pthread_mutex_unlock(&g_lock);
}

/* ---- peers ---- */

void pki_note_peer(uint32_t node, const uint8_t key[PKI_KEY_LEN])
{
    if (!node || node == 0xFFFFFFFFu || all_zero(key, PKI_KEY_LEN)) return;
    pthread_mutex_lock(&g_lock);
    int slot = -1;
    for (int i = 0; i < g_npeers; ++i)
        if (g_peers[i].node == node) { slot = i; break; }
    if (slot < 0) {
        if (g_npeers < PKI_PEERS) slot = g_npeers++;
        else { slot = g_next_evict; g_next_evict = (g_next_evict + 1) % PKI_PEERS; }
    }
    g_peers[slot].node = node;
    memcpy(g_peers[slot].key, key, PKI_KEY_LEN);
    pthread_mutex_unlock(&g_lock);
}

bool pki_peer_key(uint32_t node, uint8_t out[PKI_KEY_LEN])
{
    bool found = false;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_npeers; ++i)
        if (g_peers[i].node == node) {
            memcpy(out, g_peers[i].key, PKI_KEY_LEN);
            found = true;
            break;
        }
    pthread_mutex_unlock(&g_lock);
    return found;
}

/* ---- crypto ---- */

int pki_shared_key(const uint8_t priv[PKI_KEY_LEN], const uint8_t peer_pub[PKI_KEY_LEN],
                   uint8_t shared[32])
{
    int rc = -1;
    EVP_PKEY *me = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, PKI_KEY_LEN);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, PKI_KEY_LEN);
    EVP_PKEY_CTX *ctx = me ? EVP_PKEY_CTX_new(me, NULL) : NULL;
    uint8_t secret[32];
    size_t len = sizeof(secret);
    if (ctx && peer && EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
        EVP_PKEY_derive(ctx, secret, &len) == 1 && len == 32 &&
        !all_zero(secret, sizeof(secret))) {   /* weak point -> all-zero secret */
        unsigned int hl = 0;
        if (EVP_Digest(secret, sizeof(secret), shared, &hl, EVP_sha256(), NULL) == 1 && hl == 32)
            rc = 0;
    }
    memset(secret, 0, sizeof(secret));
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(me);
    return rc;
}

static void make_nonce(uint8_t nonce[13], uint32_t packet_id, uint32_t extra, uint32_t from)
{
    for (int i = 0; i < 4; ++i) {
        nonce[i]     = (uint8_t)(packet_id >> (8 * i));
        nonce[4 + i] = (uint8_t)(extra     >> (8 * i));
        nonce[8 + i] = (uint8_t)(from      >> (8 * i));
    }
    nonce[12] = 0;
}

int pki_decrypt_body(const uint8_t shared[32], uint32_t from_node, uint32_t packet_id,
                     const uint8_t *body, size_t n, uint8_t *out, size_t cap)
{
    if (!body || n <= PKI_OVERHEAD || n - PKI_OVERHEAD > cap) return -1;
    size_t ct_len = n - PKI_OVERHEAD;
    const uint8_t *tag = body + ct_len, *xn = tag + 8;
    uint32_t extra = (uint32_t)xn[0] | (uint32_t)xn[1] << 8 |
                     (uint32_t)xn[2] << 16 | (uint32_t)xn[3] << 24;
    uint8_t nonce[13];
    make_nonce(nonce, packet_id, extra, from_node);

    int rc = -1, len = 0;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (c &&
        EVP_DecryptInit_ex(c, EVP_aes_256_ccm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_CCM_SET_IVLEN, 13, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_CCM_SET_TAG, 8, (void *)tag) == 1 &&
        EVP_DecryptInit_ex(c, NULL, NULL, shared, nonce) == 1 &&
        EVP_DecryptUpdate(c, NULL, &len, NULL, (int)ct_len) == 1 &&
        EVP_DecryptUpdate(c, out, &len, body, (int)ct_len) == 1)  /* fails on a bad tag */
        rc = len;
    EVP_CIPHER_CTX_free(c);
    return rc;
}

int pki_encrypt_body(const uint8_t shared[32], uint32_t from_node, uint32_t packet_id,
                     uint32_t extra_nonce, const uint8_t *plain, size_t n,
                     uint8_t *out, size_t cap)
{
    if (n + PKI_OVERHEAD > cap) return -1;
    uint8_t nonce[13];
    make_nonce(nonce, packet_id, extra_nonce, from_node);
    int rc = -1, len = 0, fin = 0;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (c &&
        EVP_EncryptInit_ex(c, EVP_aes_256_ccm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_CCM_SET_IVLEN, 13, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_CCM_SET_TAG, 8, NULL) == 1 &&
        EVP_EncryptInit_ex(c, NULL, NULL, shared, nonce) == 1 &&
        EVP_EncryptUpdate(c, NULL, &len, NULL, (int)n) == 1 &&
        EVP_EncryptUpdate(c, out, &len, plain, (int)n) == 1 &&
        EVP_EncryptFinal_ex(c, out + len, &fin) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_CCM_GET_TAG, 8, out + n) == 1) {
        for (int i = 0; i < 4; ++i) out[n + 8 + i] = (uint8_t)(extra_nonce >> (8 * i));
        rc = (int)(n + PKI_OVERHEAD);
    }
    EVP_CIPHER_CTX_free(c);
    return rc;
}

int pki_mesh_hook(uint32_t from, uint32_t to, uint32_t packet_id,
                  const uint8_t *body, size_t n, uint8_t *out, size_t cap)
{
    uint8_t priv[PKI_KEY_LEN], peer[PKI_KEY_LEN], shared[32];
    pthread_mutex_lock(&g_lock);
    bool mine = g_enabled && g_own_node && to == g_own_node;
    if (mine) memcpy(priv, g_priv, PKI_KEY_LEN);
    pthread_mutex_unlock(&g_lock);
    if (!mine || !pki_peer_key(from, peer)) return -1;
    int rc = -1;
    if (pki_shared_key(priv, peer, shared) == 0)
        rc = pki_decrypt_body(shared, from, packet_id, body, n, out, cap);
    memset(priv, 0, sizeof(priv));
    memset(shared, 0, sizeof(shared));
    return rc;
}
