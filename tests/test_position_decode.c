/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Regression test for the meshtastic.Position protobuf decoder. The fixture
 * is hand-encoded against the current upstream proto so a future field
 * shift or wire-type drift surfaces here instead of silently reaching the
 * JSON / CoT / TDOA paths.
 *
 * Catches:
 *   - lat/lon decoded as anything other than sfixed32 (the original bug
 *     was varint+zigzag, which always produced 0,0 on real packets)
 *   - off-by-one or shifted field numbers (a prior version had cases
 *     12/15/16/17/18 wired to the wrong semantic fields, so HDOP came out
 *     as sats_in_view and ground_track came out as ground_speed_mps)
 *   - missing have_* flags so consumers can tell present-but-zero from
 *     not-present
 */
#include "../mesh_decoders.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Hand-encoded protobuf payload. Field tags include both wire type and
 * field number; per VITA spec each multi-byte tag (field >= 16) is itself
 * a varint. Comments give the source value and any encoding notes. */
static const uint8_t POSITION_FIXTURE[] = {
    /* field  1 sfixed32 latitude_i  =  381234560  ( 38.1234560 deg)
     *         tag (1<<3)|5 = 0x0D, then 4-byte LE  381234560 = 0x16B92D80 */
    0x0D, 0x80, 0x2D, 0xB9, 0x16,

    /* field  2 sfixed32 longitude_i = -987654320  (-98.7654320 deg)
     *         tag (2<<3)|5 = 0x15, then 4-byte LE  -987654320 = 0xC5219750 */
    0x15, 0x50, 0x97, 0x21, 0xC5,

    /* field  3 int32 altitude = 250 (varint)
     *         tag (3<<3)|0 = 0x18, value 250 = 0xFA 0x01 */
    0x18, 0xFA, 0x01,

    /* field  4 fixed32 time = 1733000000
     *         tag (4<<3)|5 = 0x25, then 4-byte LE  1733000000 = 0x674B7B40 */
    0x25, 0x40, 0x7B, 0x4B, 0x67,

    /* field  5 enum location_source = 2 (LOC_INTERNAL)
     *         tag (5<<3)|0 = 0x28, value 0x02 */
    0x28, 0x02,

    /* field  9 sint32 altitude_hae = 245
     *         tag (9<<3)|0 = 0x48, zigzag(245) = 490 = 0xEA 0x03 */
    0x48, 0xEA, 0x03,

    /* field 11 uint32 PDOP = 150 (== 1.50 after /100)
     *         tag (11<<3)|0 = 0x58, varint 150 = 0x96 0x01 */
    0x58, 0x96, 0x01,

    /* field 12 uint32 HDOP = 75 (== 0.75 after /100)
     *         tag (12<<3)|0 = 0x60, varint 75 = 0x4B */
    0x60, 0x4B,

    /* field 15 uint32 ground_speed = 12 (m/s)
     *         tag (15<<3)|0 = 0x78, value 0x0C */
    0x78, 0x0C,

    /* field 16 uint32 ground_track = 18000 (== 180.00 after /100)
     *         tag (16<<3)|0 = 128, written as varint 0x80 0x01
     *         value 18000 in varint = 0xD0 0x8C 0x01 */
    0x80, 0x01, 0xD0, 0x8C, 0x01,

    /* field 19 uint32 sats_in_view = 8
     *         tag (19<<3)|0 = 152, written as varint 0x98 0x01
     *         value 8 */
    0x98, 0x01, 0x08,
};

static int fails = 0;
#define CHECK(cond, fmt, ...) do {                                    \
    if (!(cond)) {                                                    \
        fprintf(stderr, "FAIL [%s:%d]  " fmt "\n",                    \
                __FILE__, __LINE__, ##__VA_ARGS__);                   \
        fails++;                                                      \
    }                                                                 \
} while (0)

#define CHECK_FLOAT_NEAR(got, want, eps, label) \
    CHECK(fabs((got) - (want)) < (eps), label ": got %.10f want %.10f", (got), (want))

int main(void)
{
    mesh_position_t p;
    bool ok = mesh_decode_position(POSITION_FIXTURE, sizeof(POSITION_FIXTURE), &p);
    CHECK(ok, "mesh_decode_position returned false");

    /* lat/lon must decode as sfixed32, not varint+zigzag. A bug where this
     * went through varint would have collapsed both to ~0 here. */
    CHECK(p.have_lat, "have_lat flag not set");
    CHECK(p.have_lon, "have_lon flag not set");
    CHECK_FLOAT_NEAR(p.lat_deg,  38.1234560, 1e-7, "lat_deg");
    CHECK_FLOAT_NEAR(p.lon_deg, -98.7654320, 1e-7, "lon_deg");

    /* altitude and altitude_hae (sint32 zigzag) */
    CHECK(p.have_alt, "have_alt flag not set");
    CHECK(p.altitude_m == 250, "altitude_m: got %d want 250", p.altitude_m);
    CHECK(p.have_alt_hae, "have_alt_hae flag not set");
    CHECK(p.altitude_hae_m == 245,
          "altitude_hae_m: got %d want 245 (sint32 zigzag round-trip)", p.altitude_hae_m);

    /* fixed32 time + location_source enum */
    CHECK(p.have_time, "have_time flag not set");
    CHECK(p.time == 1733000000u, "time: got %u want 1733000000", p.time);
    CHECK(p.location_source == 2u, "location_source: got %u want 2", p.location_source);

    /* PDOP and HDOP land on their CORRECT fields. The prior bug parked
     * HDOP into sats_in_view and ground_speed into pdop_x100. */
    CHECK(p.pdop_x100 == 150u, "pdop_x100: got %u want 150", p.pdop_x100);
    CHECK(p.hdop_x100 ==  75u, "hdop_x100: got %u want 75 (was leaking into sats)", p.hdop_x100);
    CHECK(p.vdop_x100 ==   0u, "vdop_x100: got %u want 0 (not present)", p.vdop_x100);

    /* ground_speed = 12 m/s. The old bug read this into pdop_x100 and
     * reported "1000s of MPH" because ground_track (1/100 degrees) was
     * landing in ground_speed_mps. */
    CHECK(p.have_ground_speed, "have_ground_speed flag not set");
    CHECK(p.ground_speed_mps == 12u,
          "ground_speed_mps: got %u want 12 (must NOT be ~18000 from track field)",
          p.ground_speed_mps);

    /* ground_track = 18000 (180.00 degrees in 1/100). */
    CHECK(p.have_ground_track, "have_ground_track flag not set");
    CHECK(p.ground_track_x100 == 18000u,
          "ground_track_x100: got %u want 18000", p.ground_track_x100);

    /* sats_in_view = 8. Prior bug placed HDOP here. */
    CHECK(p.sats_in_view == 8u,
          "sats_in_view: got %u want 8 (must NOT be 75 from HDOP)", p.sats_in_view);

    /* Fields not present must stay zero with their have_* flag false. */
    CHECK(!p.have_timestamp, "have_timestamp set without a field 7 in the fixture");
    CHECK(!p.have_alt_geosep, "have_alt_geosep set without a field 10 in the fixture");
    CHECK(p.gps_accuracy_mm == 0u, "gps_accuracy_mm should be 0");
    CHECK(p.precision_bits == 0u, "precision_bits should be 0 (not the old field 18 -> precision wire)");

    if (fails) {
        fprintf(stderr, "%d check(s) failed\n", fails);
        return 1;
    }
    printf("OK\n");
    return 0;
}
