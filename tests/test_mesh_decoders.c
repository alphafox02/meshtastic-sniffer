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
/* AirQualityMetrics: Telemetry envelope dispatches field 4.          */
/* ------------------------------------------------------------------ */
static const uint8_t TELEMETRY_AIR_QUALITY_FIXTURE[] = {
    0x22, 0x12, 0x10, 0x0C, 0x28, 0x0A, 0x68, 0xE0, 0x03, 0x75, 0x00, 0x00,
    0xB4, 0x41, 0xBD, 0x01, 0x00, 0x00, 0xBF, 0x42,
};

static void test_telemetry_air_quality(void)
{
    mesh_telemetry_t t;
    bool ok = mesh_decode_telemetry(TELEMETRY_AIR_QUALITY_FIXTURE,
                                    sizeof(TELEMETRY_AIR_QUALITY_FIXTURE), &t);
    CHECK(ok, "mesh_decode_telemetry returned false on AirQuality payload");
    CHECK(t.have_air_quality, "have_air_quality not set");
    CHECK(t.aq_pm25_standard == 12u, "aq_pm25_standard: got %u want 12", t.aq_pm25_standard);
    CHECK(t.aq_pm25_env == 10u,      "aq_pm25_env: got %u want 10",      t.aq_pm25_env);
    CHECK(t.aq_co2 == 480u,          "aq_co2: got %u want 480",          t.aq_co2);
    CHECK(t.aq_co2_temperature_c > 22.49f && t.aq_co2_temperature_c < 22.51f,
          "aq_co2_temperature_c: got %.4f want ~22.5", (double)t.aq_co2_temperature_c);
    CHECK(t.aq_pm_voc_idx > 95.49f && t.aq_pm_voc_idx < 95.51f,
          "aq_pm_voc_idx: got %.4f want ~95.5 (field 23 -> 2-byte tag path)",
          (double)t.aq_pm_voc_idx);
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
/* HealthMetrics: Telemetry envelope dispatches field 7.              */
/* ------------------------------------------------------------------ */
static const uint8_t TELEMETRY_HEALTH_FIXTURE[] = {
    0x3A, 0x09, 0x08, 0x48, 0x10, 0x61, 0x1D, 0x66, 0x66, 0x12, 0x42,
};

static void test_telemetry_health(void)
{
    mesh_telemetry_t t;
    bool ok = mesh_decode_telemetry(TELEMETRY_HEALTH_FIXTURE,
                                    sizeof(TELEMETRY_HEALTH_FIXTURE), &t);
    CHECK(ok, "mesh_decode_telemetry returned false on Health payload");
    CHECK(t.have_health, "have_health not set");
    CHECK(t.health_heart_bpm == 72u, "heart_bpm: got %u want 72", t.health_heart_bpm);
    CHECK(t.health_spo2 == 97u,      "spo2: got %u want 97",      t.health_spo2);
    CHECK(t.health_temperature_c > 36.59f && t.health_temperature_c < 36.61f,
          "health_temperature_c: got %.4f want ~36.6",
          (double)t.health_temperature_c);
}

/* ------------------------------------------------------------------ */
/* HostMetrics: Telemetry envelope dispatches field 8.                */
/* ------------------------------------------------------------------ */
static const uint8_t TELEMETRY_HOST_FIXTURE[] = {
    0x42, 0x15, 0x08, 0x90, 0x1C, 0x10, 0xCD, 0xD7, 0xA6, 0xBC, 0xD6, 0xE8,
    0x48, 0x30, 0x19, 0x4A, 0x06, 0x72, 0x70, 0x69, 0x2D, 0x35, 0x62,
};

static void test_telemetry_host(void)
{
    mesh_telemetry_t t;
    bool ok = mesh_decode_telemetry(TELEMETRY_HOST_FIXTURE,
                                    sizeof(TELEMETRY_HOST_FIXTURE), &t);
    CHECK(ok, "mesh_decode_telemetry returned false on Host payload");
    CHECK(t.have_host, "have_host not set");
    CHECK(t.host_uptime_s == 3600u, "uptime_s: got %u want 3600", t.host_uptime_s);
    CHECK(t.host_freemem_bytes == 0x123456789ABCDULL,
          "freemem 64-bit: got %llu want 320255973501901 (proves u64 varint path)",
          (unsigned long long)t.host_freemem_bytes);
    CHECK(t.host_load1_x100 == 25u, "load1_x100: got %u want 25", t.host_load1_x100);
    CHECK_STR(t.host_user_string, "rpi-5b");
}

/* ------------------------------------------------------------------ */
/* TrafficManagementStats: Telemetry envelope dispatches field 9.     */
/* ------------------------------------------------------------------ */
static const uint8_t TELEMETRY_TRAFFIC_FIXTURE[] = {
    0x4A, 0x09, 0x08, 0x88, 0x27, 0x10, 0x0C, 0x20, 0x03, 0x38, 0x11,
};

static void test_telemetry_traffic(void)
{
    mesh_telemetry_t t;
    bool ok = mesh_decode_telemetry(TELEMETRY_TRAFFIC_FIXTURE,
                                    sizeof(TELEMETRY_TRAFFIC_FIXTURE), &t);
    CHECK(ok, "mesh_decode_telemetry returned false on TrafficManagement payload");
    CHECK(t.have_traffic_mgmt, "have_traffic_mgmt not set");
    CHECK(t.tm_packets_inspected == 5000u,    "inspected: got %u want 5000",  t.tm_packets_inspected);
    CHECK(t.tm_position_dedup_drops == 12u,   "pos_dedup_drops: got %u want 12", t.tm_position_dedup_drops);
    CHECK(t.tm_rate_limit_drops == 3u,        "rate_limit_drops: got %u want 3", t.tm_rate_limit_drops);
    CHECK(t.tm_router_hops_preserved == 17u,  "router_hops_kept: got %u want 17", t.tm_router_hops_preserved);
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
/* Traceroute decoder accepts UNPACKED repeated scalars.              */
/* proto3 lets a sender encode `repeated uint32 route` as one         */
/* tag+varint per element; the decoder used to assume wt=2 (packed)   */
/* only and silently misparsed unpacked traces.                       */
/* ------------------------------------------------------------------ */
static const uint8_t TRACEROUTE_UNPACKED_FIXTURE[] = {
    0x08, 0x0A, 0x08, 0x14, 0x08, 0x1E, 0x10, 0xFB, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x10, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0x01, 0x18, 0x1E, 0x18, 0x14, 0x18, 0x0A, 0x20, 0xFD,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
};

static void test_traceroute_unpacked(void)
{
    mesh_traceroute_t t;
    bool ok = mesh_decode_traceroute(TRACEROUTE_UNPACKED_FIXTURE,
                                     sizeof(TRACEROUTE_UNPACKED_FIXTURE), &t);
    CHECK(ok, "mesh_decode_traceroute returned false on unpacked form");
    CHECK(t.route_len == 3, "route_len: got %d want 3", t.route_len);
    CHECK(t.route[0] == 10 && t.route[1] == 20 && t.route[2] == 30,
          "route bytes desync'd: got %u,%u,%u want 10,20,30",
          t.route[0], t.route[1], t.route[2]);
    CHECK(t.snr_towards_len == 2,
          "snr_towards_len: got %d want 2", t.snr_towards_len);
    CHECK(t.snr_towards[0] == -5 && t.snr_towards[1] == -2,
          "snr_towards: got %d,%d want -5,-2",
          (int)t.snr_towards[0], (int)t.snr_towards[1]);
    CHECK(t.route_back_len == 3, "route_back_len: got %d want 3", t.route_back_len);
    CHECK(t.route_back[0] == 30 && t.route_back[1] == 20 && t.route_back[2] == 10,
          "route_back: got %u,%u,%u want 30,20,10",
          t.route_back[0], t.route_back[1], t.route_back[2]);
    CHECK(t.snr_back_len == 1 && t.snr_back[0] == -3,
          "snr_back: got len=%d val=%d want 1,-3",
          t.snr_back_len, (int)t.snr_back[0]);
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
    test_telemetry_air_quality();
    test_telemetry_local_stats();
    test_telemetry_health();
    test_telemetry_host();
    test_telemetry_traffic();
    test_power_metrics_ch8();
    test_traceroute_unpacked();
    test_atak_geochat_receipt();

    if (fails) {
        fprintf(stderr, "%d check(s) failed\n", fails);
        return 1;
    }
    printf("OK\n");
    return 0;
}
