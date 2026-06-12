/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Regression tests for the meshtastic.* protobuf decoders touched in the
 * recent upstream-alignment sweep. Each fixture is a hand-encoded
 * protobuf payload that exercises a specific wire-format or label table
 * fix; if a future upstream proto drift breaks the decoder again, the
 * mismatch surfaces here before reaching the JSON / CoT / TDOA paths.
 */
#include "../mesh_decoders.h"

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

#define CHECK_STR(got, want) \
    CHECK(strcmp((got), (want)) == 0, "got \"%s\" want \"%s\"", (got), (want))

/* ------------------------------------------------------------------ */
/* 1. NeighborInfo with one Neighbor whose last_rx_time is fixed32.    */
/*    Validates that the 4-byte fixed read consumes the right number   */
/*    of bytes so node_broadcast_interval_secs (field 4) is reached.   */
/* ------------------------------------------------------------------ */
static const uint8_t NEIGHBORINFO_FIXTURE[] = {
    0x08, 0x64, 0x22, 0x10, 0x08, 0xC8, 0x01, 0x15, 0x00, 0x00, 0x48, 0x41,
    0x1D, 0x10, 0x20, 0x30, 0x40, 0x20, 0xD8, 0x04,
};

static void test_neighborinfo_last_rx_time_fixed32(void)
{
    mesh_neighborinfo_t ni;
    bool ok = mesh_decode_neighborinfo(NEIGHBORINFO_FIXTURE,
                                       sizeof(NEIGHBORINFO_FIXTURE), &ni);
    CHECK(ok, "mesh_decode_neighborinfo returned false");
    CHECK(ni.node_id == 100u,
          "outer NeighborInfo.node_id: got %u want 100", ni.node_id);
    CHECK(ni.n_neighbors == 1,
          "n_neighbors: got %d want 1", ni.n_neighbors);

    const mesh_neighbor_t *n = &ni.neighbors[0];
    CHECK(n->node_id == 200u,
          "Neighbor.node_id: got %u want 200", n->node_id);
    CHECK(n->last_rx_time == 0x40302010u,
          "Neighbor.last_rx_time: got 0x%08x want 0x40302010 "
          "(varint read would desync this and the next field)",
          n->last_rx_time);
    CHECK(n->node_broadcast_interval_secs == 600u,
          "Neighbor.node_broadcast_interval_secs: got %u want 600 "
          "(non-zero proves field 3 was consumed as 4 bytes)",
          n->node_broadcast_interval_secs);
}

/* ------------------------------------------------------------------ */
/* 2. ATAK MemberRole table alignment.                                */
/* ------------------------------------------------------------------ */
static void test_atak_role_table(void)
{
    CHECK_STR(mesh_atak_role_name(0), "Unspecified");
    CHECK_STR(mesh_atak_role_name(1), "TeamMember");
    CHECK_STR(mesh_atak_role_name(2), "TeamLead");
    CHECK_STR(mesh_atak_role_name(3), "HQ");
    CHECK_STR(mesh_atak_role_name(4), "Sniper");
    CHECK_STR(mesh_atak_role_name(5), "Medic");
    CHECK_STR(mesh_atak_role_name(6), "ForwardObserver");
    CHECK_STR(mesh_atak_role_name(7), "RTO");
    CHECK_STR(mesh_atak_role_name(8), "K9");
}

/* ------------------------------------------------------------------ */
/* 3. StoreAndForward rr labels 8/9 match upstream direction.         */
/* ------------------------------------------------------------------ */
static void test_storeforward_rr_labels(void)
{
    CHECK_STR(mesh_storeforward_rr_name(8), "ROUTER_TEXT_DIRECT");
    CHECK_STR(mesh_storeforward_rr_name(9), "ROUTER_TEXT_BROADCAST");
    CHECK(mesh_storeforward_rr_name(69) == NULL,
          "rr=69 should be unknown after dead-label removal");
}

/* ------------------------------------------------------------------ */
/* 4. Telemetry envelope dispatches LocalStats (oneof field 6).       */
/* ------------------------------------------------------------------ */
static const uint8_t TELEMETRY_LOCAL_STATS_FIXTURE[] = {
    0x32, 0x0E, 0x08, 0xB9, 0x60, 0x15, 0x00, 0x00, 0xB8, 0x40, 0x38, 0x2A,
    0x68, 0xC0, 0x84, 0x3D,
};

static void test_telemetry_local_stats(void)
{
    mesh_telemetry_t t;
    bool ok = mesh_decode_telemetry(TELEMETRY_LOCAL_STATS_FIXTURE,
                                    sizeof(TELEMETRY_LOCAL_STATS_FIXTURE), &t);
    CHECK(ok, "mesh_decode_telemetry returned false on LocalStats payload");
    CHECK(t.have_local_stats, "have_local_stats not set");
    CHECK(t.local_uptime_s == 12345u,
          "local_uptime_s: got %u want 12345", t.local_uptime_s);
    CHECK(t.local_channel_utilization > 5.74f &&
          t.local_channel_utilization < 5.76f,
          "local_channel_utilization: got %.4f want ~5.75",
          (double)t.local_channel_utilization);
    CHECK(t.local_num_online_nodes == 42u,
          "local_num_online_nodes: got %u want 42", t.local_num_online_nodes);
    CHECK(t.local_heap_free_bytes == 1000000u,
          "local_heap_free_bytes: got %u want 1000000",
          t.local_heap_free_bytes);
}

/* ------------------------------------------------------------------ */
/* 5. PowerMetrics ch8 voltage+current land in the right struct slot. */
/* ------------------------------------------------------------------ */
static const uint8_t TELEMETRY_POWER_CH8_FIXTURE[] = {
    0x2A, 0x0B, 0x7D, 0xCD, 0xCC, 0x6C, 0x40, 0x85, 0x01, 0x00, 0x00, 0xC0,
    0x3F,
};

static void test_power_metrics_ch8(void)
{
    mesh_telemetry_t t;
    bool ok = mesh_decode_telemetry(TELEMETRY_POWER_CH8_FIXTURE,
                                    sizeof(TELEMETRY_POWER_CH8_FIXTURE), &t);
    CHECK(ok, "mesh_decode_telemetry returned false on PowerMetrics payload");
    CHECK(t.have_power, "have_power not set");
    CHECK(t.ch8_voltage > 3.69f && t.ch8_voltage < 3.71f,
          "ch8_voltage: got %.4f want ~3.7", (double)t.ch8_voltage);
    CHECK(t.ch8_current > 1.49f && t.ch8_current < 1.51f,
          "ch8_current: got %.4f want ~1.5", (double)t.ch8_current);
    /* Channels not present must stay zero so the JSON 'if (...)' guards
     * don't emit stale data. */
    CHECK(t.ch1_voltage == 0.0f, "ch1_voltage leaked: %.4f", (double)t.ch1_voltage);
    CHECK(t.ch7_voltage == 0.0f, "ch7_voltage leaked: %.4f", (double)t.ch7_voltage);
}

/* ------------------------------------------------------------------ */
/* 6. TAKPacket wrapping GeoChat surfaces receipt_for_uid +           */
/*    receipt_type so receipts are distinguishable from regular chat. */
/* ------------------------------------------------------------------ */
static const uint8_t ATAK_GEOCHAT_RECEIPT_FIXTURE[] = {
    0x32, 0x28, 0x0A, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x12, 0x05, 0x42,
    0x4F, 0x42, 0x2D, 0x31, 0x1A, 0x03, 0x42, 0x6F, 0x62, 0x22, 0x11, 0x65,
    0x76, 0x74, 0x2D, 0x75, 0x75, 0x69, 0x64, 0x2D, 0x6F, 0x72, 0x69, 0x67,
    0x69, 0x6E, 0x61, 0x6C, 0x28, 0x02,
};

static void test_atak_geochat_receipt(void)
{
    mesh_atak_t a;
    bool ok = mesh_decode_atak(ATAK_GEOCHAT_RECEIPT_FIXTURE,
                               sizeof(ATAK_GEOCHAT_RECEIPT_FIXTURE), &a);
    CHECK(ok, "mesh_decode_atak returned false on GeoChat-with-receipt");
    CHECK(a.kind == MESH_ATAK_CHAT,
          "kind: got %d want MESH_ATAK_CHAT (%d)", (int)a.kind, (int)MESH_ATAK_CHAT);
    CHECK_STR(a.chat_message, "hello");
    CHECK_STR(a.chat_to, "BOB-1");
    CHECK_STR(a.chat_to_callsign, "Bob");
    CHECK_STR(a.chat_receipt_for_uid, "evt-uuid-original");
    CHECK(a.chat_receipt_type == 2u,
          "chat_receipt_type: got %u want 2 (Read)", a.chat_receipt_type);
}

int main(void)
{
    test_neighborinfo_last_rx_time_fixed32();
    test_atak_role_table();
    test_storeforward_rr_labels();
    test_telemetry_local_stats();
    test_power_metrics_ch8();
    test_atak_geochat_receipt();

    if (fails) {
        fprintf(stderr, "%d check(s) failed\n", fails);
        return 1;
    }
    printf("OK\n");
    return 0;
}
