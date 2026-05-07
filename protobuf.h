/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: minimal protobuf wire-format reader.
 *
 * No code generation -- we walk the wire format directly. Every read
 * returns false on malformed input or buffer overrun, never reads past
 * `end`, and updates *cur in place.
 *
 */

#ifndef PROTOBUF_H
#define PROTOBUF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PB_WIRE_VARINT   0
#define PB_WIRE_FIXED64  1
#define PB_WIRE_LENGTH   2
#define PB_WIRE_FIXED32  5

bool pb_read_varint(const uint8_t **cur, const uint8_t *end, uint64_t *out);
bool pb_read_tag   (const uint8_t **cur, const uint8_t *end,
                    uint32_t *field_number, uint32_t *wire_type);

bool pb_read_fixed32(const uint8_t **cur, const uint8_t *end, uint32_t *out);
bool pb_read_fixed64(const uint8_t **cur, const uint8_t *end, uint64_t *out);
bool pb_read_length (const uint8_t **cur, const uint8_t *end,
                     const uint8_t **bytes, size_t *len);

/* Skip the value of any field whose tag was just read. */
bool pb_skip_value(const uint8_t **cur, const uint8_t *end, uint32_t wire_type);

/* zig-zag decode (sint32/sint64) */
static inline int32_t pb_zigzag32(uint32_t v) { return (int32_t)((v >> 1) ^ -(int32_t)(v & 1)); }
static inline int64_t pb_zigzag64(uint64_t v) { return (int64_t)((v >> 1) ^ -(int64_t)(v & 1)); }

#endif
