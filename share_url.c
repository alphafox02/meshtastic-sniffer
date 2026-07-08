/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Meshtastic channel-share URL decoder shared by CLI startup import and the
 * runtime web/API handlers.
 */

#include "share_url.h"
#include "meshtastic.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int b64v(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

static int share_skip(const uint8_t **pp, const uint8_t *end, uint32_t wt)
{
    const uint8_t *p = *pp;
    if (wt == 0) {
        while (p < end && (*p++ & 0x80)) {}
    } else if (wt == 1) {
        if (end - p < 8) return -1;
        p += 8;
    } else if (wt == 2) {
        uint64_t l = 0; int sh = 0;
        while (p < end) {
            uint8_t b = *p++;
            l |= (uint64_t)(b & 0x7f) << sh;
            if (!(b & 0x80)) break;
            sh += 7;
        }
        if ((uint64_t)(end - p) < l) return -1;
        p += (size_t)l;
    } else if (wt == 5) {
        if (end - p < 4) return -1;
        p += 4;
    } else {
        return -1;
    }
    *pp = p;
    return 0;
}

static void copy_name(char *dst, size_t dst_sz,
                      const uint8_t *src, uint64_t src_len)
{
    if (!dst || dst_sz == 0 || !src) return;
    if (src_len >= dst_sz) src_len = dst_sz - 1;
    memcpy(dst, src, (size_t)src_len);
    dst[src_len] = 0;
}

static void parse_channel_settings_legacy(const uint8_t *buf, size_t len,
                                          uint8_t *psk, size_t *psk_len,
                                          char *name, size_t name_sz)
{
    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint64_t tag = 0; int shift = 0;
        while (p < end) {
            uint8_t b = *p++;
            tag |= (uint64_t)(b & 0x7f) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }
        uint32_t fld = (uint32_t)(tag >> 3);
        uint32_t wt  = (uint32_t)(tag & 0x7);
        if (wt != 2) {
            if (share_skip(&p, end, wt) < 0) return;
            continue;
        }

        uint64_t l = 0; shift = 0;
        while (p < end) {
            uint8_t b = *p++;
            l |= (uint64_t)(b & 0x7f) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }
        if ((uint64_t)(end - p) < l) return;

        if (fld == 2 && (l == 1 || l == 16 || l == 32) && *psk_len == 0) {
            memcpy(psk, p, (size_t)l);
            *psk_len = (size_t)l;
        } else if (fld == 3 && name && !name[0]) {
            copy_name(name, name_sz, p, l);
        }
        p += l;
    }
}

static int parse_channel_message(keyset_t *ks, const uint8_t *buf, size_t len)
{
    uint8_t psk[32];
    size_t  psk_len = 0;
    char    name[32];
    name[0] = 0;

    const uint8_t *p = buf, *end = buf + len;
    while (p < end) {
        uint64_t tag = 0; int shift = 0;
        while (p < end) {
            uint8_t b = *p++;
            tag |= (uint64_t)(b & 0x7f) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }
        uint32_t fld = (uint32_t)(tag >> 3);
        uint32_t wt  = (uint32_t)(tag & 0x7);

        if (wt != 2) {
            if (share_skip(&p, end, wt) < 0) return -1;
            continue;
        }

        uint64_t l = 0; shift = 0;
        while (p < end) {
            uint8_t b = *p++;
            l |= (uint64_t)(b & 0x7f) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }
        if ((uint64_t)(end - p) < l) return -1;

        if (fld == 2) {
            if ((l == 1 || l == 16 || l == 32) && psk_len == 0) {
                memcpy(psk, p, (size_t)l);
                psk_len = (size_t)l;
            } else {
                parse_channel_settings_legacy(p, (size_t)l,
                                              psk, &psk_len, name, sizeof(name));
            }
        } else if (fld == 3 && !name[0]) {
            copy_name(name, sizeof(name), p, l);
        }
        p += l;
    }

    if (psk_len == 0) return 0;

    if (psk_len == 1) {
        uint8_t expanded[16];
        memcpy(expanded, MESH_DEFAULT_PSK, 16);
        expanded[15] = psk[0];
        return keyset_add(ks, name[0] ? name : NULL, expanded, 16) == 0 ? 1 : -1;
    }
    if (psk_len == 16 || psk_len == 32)
        return keyset_add(ks, name[0] ? name : NULL, psk, psk_len) == 0 ? 1 : -1;

    return 0;
}

int decode_channel_share(keyset_t *ks, const char *url_or_b64)
{
    if (!ks || !url_or_b64) return -1;

    const char *p = url_or_b64;
    const char *hash = strchr(p, '#');
    if (hash) p = hash + 1;
    const char *eq = strchr(p, '=');
    if (eq && eq[1] && eq[1] != '=' && eq[1] != '&' &&
        eq[1] != ' ' && eq[1] != '\r' && eq[1] != '\n')
        p = eq + 1;

    size_t enc_len = 0;
    while (p[enc_len] &&
           p[enc_len] != '=' &&
           p[enc_len] != '&' &&
           p[enc_len] != ' ' &&
           p[enc_len] != '\r' &&
           p[enc_len] != '\n') {
        ++enc_len;
    }
    if (enc_len == 0) return -1;

    size_t buf_cap = (enc_len * 3) / 4 + 4;
    uint8_t *buf = malloc(buf_cap);
    if (!buf) return -1;

    size_t out = 0;
    uint32_t accum = 0; int bits = 0;
    for (size_t i = 0; i < enc_len; ++i) {
        int v = b64v(p[i]);
        if (v < 0) {
            free(buf);
            return -1;
        }
        accum = (accum << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out >= buf_cap) {
                free(buf);
                return -1;
            }
            buf[out++] = (uint8_t)((accum >> bits) & 0xff);
        }
    }
    if (out == 0) {
        free(buf);
        return -1;
    }

    int added = 0;
    const uint8_t *bp = buf, *bend = buf + out;
    while (bp < bend) {
        uint64_t tag = 0; int shift = 0;
        while (bp < bend) {
            uint8_t b = *bp++;
            tag |= (uint64_t)(b & 0x7f) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }
        uint32_t fld = (uint32_t)(tag >> 3);
        uint32_t wt  = (uint32_t)(tag & 0x7);

        if (wt != 2) {
            if (share_skip(&bp, bend, wt) < 0) { added = -1; break; }
            continue;
        }

        uint64_t l = 0; shift = 0;
        while (bp < bend) {
            uint8_t b = *bp++;
            l |= (uint64_t)(b & 0x7f) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }
        if ((uint64_t)(bend - bp) < l) { added = -1; break; }

        if (fld == 1) {
            int rc = parse_channel_message(ks, bp, (size_t)l);
            if (rc < 0) { added = -1; break; }
            added += rc;
        }
        bp += l;
    }

    free(buf);
    return added;
}
