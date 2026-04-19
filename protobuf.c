/*
 * meshtastic-sniffer: minimal protobuf wire-format reader.
 *
 * Copyright (c) 2026 CEMAXECUTER LLC
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "protobuf.h"

#include <string.h>

bool pb_read_varint(const uint8_t **cur, const uint8_t *end, uint64_t *out)
{
    uint64_t v = 0;
    int shift = 0;
    while (*cur < end) {
        uint8_t b = *(*cur)++;
        v |= (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) { *out = v; return true; }
        shift += 7;
        if (shift > 63) return false;
    }
    return false;
}

bool pb_read_tag(const uint8_t **cur, const uint8_t *end,
                 uint32_t *field_number, uint32_t *wire_type)
{
    uint64_t tag;
    if (!pb_read_varint(cur, end, &tag)) return false;
    *wire_type    = (uint32_t)(tag & 0x7);
    *field_number = (uint32_t)(tag >> 3);
    return true;
}

bool pb_read_fixed32(const uint8_t **cur, const uint8_t *end, uint32_t *out)
{
    if (end - *cur < 4) return false;
    uint32_t v;
    memcpy(&v, *cur, 4);  /* protobuf fixed32 is little-endian */
    *cur += 4;
    *out = v;
    return true;
}

bool pb_read_fixed64(const uint8_t **cur, const uint8_t *end, uint64_t *out)
{
    if (end - *cur < 8) return false;
    uint64_t v;
    memcpy(&v, *cur, 8);
    *cur += 8;
    *out = v;
    return true;
}

bool pb_read_length(const uint8_t **cur, const uint8_t *end,
                    const uint8_t **bytes, size_t *len)
{
    uint64_t l;
    if (!pb_read_varint(cur, end, &l)) return false;
    if ((uint64_t)(end - *cur) < l) return false;
    *bytes = *cur;
    *len   = (size_t)l;
    *cur  += l;
    return true;
}

bool pb_skip_value(const uint8_t **cur, const uint8_t *end, uint32_t wire_type)
{
    uint64_t dummy;
    const uint8_t *bytes;
    size_t len;
    switch (wire_type) {
        case PB_WIRE_VARINT:  return pb_read_varint(cur, end, &dummy);
        case PB_WIRE_FIXED64: return pb_read_fixed64(cur, end, &dummy);
        case PB_WIRE_LENGTH:  return pb_read_length(cur, end, &bytes, &len);
        case PB_WIRE_FIXED32: { uint32_t d; return pb_read_fixed32(cur, end, &d); }
        default: return false;
    }
}
