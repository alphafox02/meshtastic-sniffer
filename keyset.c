/*
 * meshtastic-sniffer: multi-key dispatch.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "keyset.h"
#include "meshtastic.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ---- helpers ---- */

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *hex, uint8_t *out, size_t max_out)
{
    size_t hl = strlen(hex);
    if (hl % 2) return -1;
    size_t n = hl / 2;
    if (n > max_out) return -1;
    for (size_t i = 0; i < n; ++i) {
        int hi = hex_nibble(hex[2*i]);
        int lo = hex_nibble(hex[2*i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)n;
}

static int b64_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

static int b64_decode(const char *b64, uint8_t *out, size_t max_out)
{
    size_t len = strlen(b64);
    /* trim padding */
    while (len > 0 && (b64[len-1] == '=' || b64[len-1] == '\n' || b64[len-1] == '\r' || b64[len-1] == ' '))
        --len;
    size_t out_idx = 0;
    int    bits = 0;
    uint32_t accum = 0;
    for (size_t i = 0; i < len; ++i) {
        int v = b64_value(b64[i]);
        if (v < 0) return -1;
        accum = (accum << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out_idx >= max_out) return -1;
            out[out_idx++] = (uint8_t)((accum >> bits) & 0xff);
        }
    }
    return (int)out_idx;
}

static uint8_t xor_bytes(const uint8_t *p, size_t n)
{
    uint8_t h = 0;
    for (size_t i = 0; i < n; ++i) h ^= p[i];
    return h;
}

/* ---- API ---- */

keyset_t *keyset_create(void)
{
    keyset_t *k = calloc(1, sizeof(*k));
    if (!k) return NULL;
    /* mark all bucket entries as -1 (empty) */
    memset(k->buckets, -1, sizeof(k->buckets));
    pthread_rwlock_init(&k->lock, NULL);
    return k;
}

void keyset_destroy(keyset_t *k) {
    if (!k) return;
    pthread_rwlock_destroy(&k->lock);
    free(k);
}

static int bucket_push(keyset_t *k, uint8_t hash, int8_t idx)
{
    int8_t *bucket = k->buckets[hash];
    for (int i = 0; i < (int)(sizeof(k->buckets[0]) - 1); ++i) {
        if (bucket[i] == -1) {
            bucket[i] = idx;
            bucket[i+1] = -1;
            return 0;
        }
    }
    return -1;  /* bucket full (>=8 collisions on one hash byte) */
}

int keyset_add(keyset_t *k, const char *channel_name,
               const uint8_t *psk, size_t psk_len)
{
    if (!k) return -1;
    if (psk_len != 0 && psk_len != 16 && psk_len != 32) return -1;
    if (psk_len > KEYSET_MAX_PSK_BYTES) return -1;

    pthread_rwlock_wrlock(&k->lock);
    if (k->n_entries >= KEYSET_MAX_ENTRIES) {
        pthread_rwlock_unlock(&k->lock);
        return -1;
    }

    keyset_entry_t *e = &k->entries[k->n_entries];
    memset(e, 0, sizeof(*e));
    if (channel_name && *channel_name) {
        strncpy(e->channel_name, channel_name, KEYSET_MAX_NAME - 1);
    } else {
        strncpy(e->channel_name, "LongFast", KEYSET_MAX_NAME - 1);
    }
    if (psk && psk_len) memcpy(e->psk, psk, psk_len);
    e->psk_len      = psk_len;
    e->channel_hash = xor_bytes((const uint8_t *)e->channel_name,
                                strlen(e->channel_name)) ^
                      xor_bytes(e->psk, e->psk_len);

    int idx = k->n_entries++;
    if (bucket_push(k, e->channel_hash, (int8_t)idx) < 0) {
        --k->n_entries;
        pthread_rwlock_unlock(&k->lock);
        return -1;
    }
    pthread_rwlock_unlock(&k->lock);
    return 0;
}

/* simpleN keys: bytes [d4..f0..bc..ff..ab..cf..4e..69..N] -- last byte is N. */
static void make_simple_psk(int n, uint8_t out[16])
{
    memcpy(out, MESH_DEFAULT_PSK, 16);
    out[15] = (uint8_t)n;
}

int keyset_parse_spec(keyset_t *k, const char *spec)
{
    if (!k || !spec) return -1;
    /* Trim leading whitespace. */
    while (*spec == ' ' || *spec == '\t') ++spec;
    if (!*spec) return 0;

    /* Optional ChannelName= prefix. */
    char  name[KEYSET_MAX_NAME] = {0};
    const char *eq = strchr(spec, '=');
    const char *value = spec;
    if (eq) {
        size_t nlen = (size_t)(eq - spec);
        if (nlen >= sizeof(name)) nlen = sizeof(name) - 1;
        memcpy(name, spec, nlen);
        name[nlen] = 0;
        /* trim trailing whitespace from name */
        while (nlen > 0 && (name[nlen-1] == ' ' || name[nlen-1] == '\t'))
            name[--nlen] = 0;
        value = eq + 1;
        while (*value == ' ' || *value == '\t') ++value;
    }

    uint8_t psk[32]; int psk_len = 0;

    if (!strcasecmp(value, "default")) {
        make_simple_psk(1, psk); psk_len = 16;
    } else if (!strcasecmp(value, "none") || !strcasecmp(value, "unencrypted")) {
        psk_len = 0;
    } else if (!strncasecmp(value, "simple", 6) && isdigit((unsigned char)value[6])) {
        int n = atoi(value + 6);
        if (n < 0 || n > 255) return -1;
        if (n == 0) { psk_len = 0; }
        else        { make_simple_psk(n, psk); psk_len = 16; }
    } else if (!strncasecmp(value, "hex:", 4)) {
        psk_len = hex_decode(value + 4, psk, sizeof(psk));
        if (psk_len <= 0) return -1;
    } else if (!strncasecmp(value, "base64:", 7)) {
        psk_len = b64_decode(value + 7, psk, sizeof(psk));
        if (psk_len <= 0) return -1;
    } else {
        /* Bare hex shorthand? Try base64 first then hex. */
        psk_len = b64_decode(value, psk, sizeof(psk));
        if (psk_len <= 0) psk_len = hex_decode(value, psk, sizeof(psk));
        if (psk_len <= 0) return -1;
    }

    return keyset_add(k, eq ? name : NULL, psk, (size_t)psk_len);
}

int keyset_parse_csv(keyset_t *k, const char *csv)
{
    if (!csv) return 0;
    char *dup = strdup(csv);
    if (!dup) return -1;
    int ok = 0;
    char *save = NULL;
    for (char *tok = strtok_r(dup, ",;\n", &save); tok; tok = strtok_r(NULL, ",;\n", &save)) {
        while (*tok == ' ' || *tok == '\t') ++tok;
        if (!*tok) continue;
        if (keyset_parse_spec(k, tok) == 0) ++ok;
    }
    free(dup);
    return ok;
}

const int8_t *keyset_lookup(const keyset_t *k, uint8_t channel_hash)
{
    if (!k) return NULL;
    return k->buckets[channel_hash];
}

const keyset_entry_t *keyset_get(const keyset_t *k, int index)
{
    if (!k || index < 0 || index >= k->n_entries) return NULL;
    return &k->entries[index];
}

void keyset_rdlock  (keyset_t *k) { if (k) pthread_rwlock_rdlock(&k->lock); }
void keyset_rdunlock(keyset_t *k) { if (k) pthread_rwlock_unlock(&k->lock); }

void keyset_print(const keyset_t *k)
{
    if (!k) { fprintf(stderr, "keyset: NULL\n"); return; }
    fprintf(stderr, "keyset: %d entries\n", k->n_entries);
    for (int i = 0; i < k->n_entries; ++i) {
        const keyset_entry_t *e = &k->entries[i];
        fprintf(stderr, "  [%d] channel='%s' psk_len=%zu hash=0x%02x\n",
                i, e->channel_name, e->psk_len, e->channel_hash);
    }
}
