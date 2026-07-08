/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Regression test for Meshtastic channel-share URL parsing. The fixture is a
 * synthetic multi-channel share payload that matches the flat Channel wire
 * shape emitted by Meshtastic channel-share URLs, but uses test-only names and
 * PSKs.
 */

#include "../keyset.h"
#include "../meshtastic.h"
#include "../share_url.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;

#define CHECK(cond, fmt, ...) do {                                    \
    if (!(cond)) {                                                    \
        fprintf(stderr, "FAIL [%s:%d]  " fmt "\n",                    \
                __FILE__, __LINE__, ##__VA_ARGS__);                   \
        fails++;                                                      \
    }                                                                 \
} while (0)

/* Synthetic channel-share fixture, encoded as a normal meshtastic.org/e URL.
 *
 * Decoded protobuf layout:
 *   top-level field 1: Channel
 *     field 2 = one-byte PSK value 7   (simple7 -> default PSK w/ last byte 7)
 *     field 3 = "AlphaNet"
 *     field 4 = fixed32 metadata       (ignored by the parser)
 *   top-level field 1: Channel
 *     field 2 = 32-byte PSK 0x01..0x20
 *     field 3 = "BravoOps"
 *     field 4 = fixed32 metadata       (ignored by the parser)
 *   top-level field 2: auxiliary submessage that should be skipped
 *
 * The exact bytes are synthetic and test-only; the point is to preserve the
 * real share-URL wire shape without embedding live channel credentials.
 */
static const char *FIXTURE_URL =
    "https://meshtastic.org/e/?add=true#"
    "ChISAQcaCEFscGhhTmV0JQQDAgEKMRIgAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAaCEJyYXZvT3BzJQ0MCwoSBAgBEAQ";

static void check_entry(const keyset_t *ks, int idx, const char *name,
                        const uint8_t *psk, size_t psk_len)
{
    const keyset_entry_t *e = keyset_get(ks, idx);
    CHECK(e != NULL, "entry %d missing", idx);
    if (!e) return;
    CHECK(strcmp(e->channel_name, name) == 0,
          "entry %d name got '%s' want '%s'", idx, e->channel_name, name);
    CHECK(e->psk_len == psk_len,
          "entry %d psk_len got %zu want %zu", idx, e->psk_len, psk_len);
    CHECK(memcmp(e->psk, psk, psk_len) == 0,
          "entry %d psk mismatch", idx);
}

static void test_multi_channel_fixture(void)
{
    keyset_t *ks = keyset_create();
    CHECK(ks != NULL, "keyset_create failed");
    if (!ks) return;

    int added = decode_channel_share(ks, FIXTURE_URL);
    CHECK(added == 2, "decode_channel_share added %d entries, want 2", added);
    CHECK(ks->n_entries == 2, "keyset entries=%d want 2", ks->n_entries);

    uint8_t bravoops_psk[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    uint8_t default_psk[16];
    memcpy(default_psk, MESH_DEFAULT_PSK, sizeof(default_psk));
    default_psk[15] = 0x07;

    check_entry(ks, 0, "AlphaNet", default_psk, sizeof(default_psk));
    check_entry(ks, 1, "BravoOps", bravoops_psk, sizeof(bravoops_psk));

    keyset_destroy(ks);
}

int main(void)
{
    test_multi_channel_fixture();
    if (fails) {
        fprintf(stderr, "test_share_url: FAIL (%d failures)\n", fails);
        return 1;
    }
    fprintf(stderr, "test_share_url: PASS\n");
    return 0;
}
