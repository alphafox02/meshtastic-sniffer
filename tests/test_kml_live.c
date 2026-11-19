/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * Tests for the live Google Earth KML cache + renderer (kml_live.c).
 */

#include "../kml_live.h"
#include "../node_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, fmt, ...) do {                                    \
    if (!(cond)) {                                                    \
        fprintf(stderr, "FAIL %s:%d: " fmt "\n", __FILE__, __LINE__,  \
                ##__VA_ARGS__);                                       \
        ++fails;                                                      \
    }                                                                 \
} while (0)

static int count_of(const char *hay, const char *needle)
{
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)); p += strlen(needle)) ++n;
    return n;
}

static void note(uint32_t id, double lat, double lon, time_t when, const char *label)
{
    kml_live_obs_t o = { .id = id, .lat = lat, .lon = lon, .have_alt = true, .alt_m = 120.0,
                         .label = label, .channel = "LongFast", .snr_db = 7.5f,
                         .rssi_db = -101.0f, .freq_hz = 906875000ULL, .when = when };
    kml_live_note(&o);
}

static void test_network_link(void)
{
    size_t len = 0;
    char *d = kml_live_network_link("http://10.0.0.2:8888/live_feed.kml?a=1&b=2", 7, &len);
    CHECK(d && len == strlen(d), "network link allocated");
    CHECK(strstr(d, "<href>http://10.0.0.2:8888/live_feed.kml?a=1&amp;b=2</href>"), "href escaped:\n%s", d);
    CHECK(strstr(d, "<refreshMode>onInterval</refreshMode>"), "refresh mode");
    CHECK(strstr(d, "<refreshInterval>7</refreshInterval>"), "refresh interval");
    free(d);
    d = kml_live_network_link("http://x/live_feed.kml", 0, NULL);
    CHECK(strstr(d, "<refreshInterval>1</refreshInterval>"), "refresh clamped to >= 1");
    free(d);
}

static void test_empty_and_rejects(void)
{
    kml_live_reset();
    note(0x1, 0.0, 0.0, 1000, NULL);       /* no-fix sentinel */
    note(0x2, 95.0, 10.0, 1000, NULL);     /* out of range */
    note(0x3, 10.0, -181.0, 1000, NULL);   /* out of range */
    char *d = kml_live_feed(NULL, 1000, NULL);
    CHECK(d && strstr(d, "0 node(s)"), "rejected positions not stored:\n%s", d);
    CHECK(count_of(d, "<Folder") == 0, "no folders");
    CHECK(strstr(d, "</kml>"), "document closed");
    free(d);
}

static void test_track_and_labels(void)
{
    kml_live_reset();
    node_db_remember(0xa1b2c3d4, "Base <Camp> & Co", "BC", 0, 0);
    note(0xa1b2c3d4, 45.1, 9.1, 1000, NULL);
    note(0xa1b2c3d4, 45.1, 9.1, 1010, NULL);   /* same spot: no new track point */
    note(0xa1b2c3d4, 45.2, 9.2, 1020, NULL);
    note(0xa1b2c3d4, 45.3, 9.3, 1030, NULL);
    note(0x00000042, 46.0, 10.0, 1025, "ATAK-\"Eagle\"");

    char *d = kml_live_feed(NULL, 1040, NULL);
    CHECK(strstr(d, "2 node(s)"), "two nodes");
    CHECK(strstr(d, "<name>Base &lt;Camp&gt; &amp; Co</name>"), "node_db name escaped:\n%s", d);
    CHECK(strstr(d, "<name>ATAK-&quot;Eagle&quot;</name>"), "ATAK label escaped");
    CHECK(strstr(d, "Position reports: 4, track points: 3"), "dup point skipped, reports counted");
    /* Track is oldest -> newest, lon,lat,alt. */
    const char *t = strstr(d, "<name>Track</name>");
    CHECK(t, "track placemark present");
    if (t) {
        const char *a = strstr(t, "9.100000,45.100000,120.0");
        const char *b = strstr(t, "9.200000,45.200000,120.0");
        const char *c = strstr(t, "9.300000,45.300000,120.0");
        CHECK(a && b && c && a < b && b < c, "track order");
    }
    /* Single-point node gets no track. */
    CHECK(count_of(d, "<name>Track</name>") == 1, "only one track");
    /* Most recently heard first. */
    CHECK(strstr(d, "node_a1b2c3d4") < strstr(d, "node_00000042"), "sorted by last heard");
    CHECK(strstr(d, "<altitudeMode>absolute</altitudeMode><coordinates>9.300000,45.300000,120.0"),
          "latest point absolute altitude");
    CHECK(strstr(d, "Frequency: 906.875 MHz"), "frequency in description");
    CHECK(strstr(d, "Channel: LongFast&lt;br&gt;"), "channel in description, HTML line break");
    CHECK(!strstr(d, "<TimeStamp>"), "no TimeStamp (keeps Google Earth's time slider off)");
    CHECK(!strstr(d, "LOS"), "no LOS without station");
    free(d);

    /* Remote channel name with markup: double-escaped in the HTML
     * description, single-escaped elsewhere. */
    kml_live_obs_t o = { .id = 0x77, .lat = 1.0, .lon = 2.0, .channel = "<b>x</b>&", .when = 1050 };
    kml_live_note(&o);
    d = kml_live_feed(NULL, 1050, NULL);
    CHECK(strstr(d, "Channel: &amp;lt;b&amp;gt;x&amp;lt;/b&amp;gt;&amp;amp;&lt;br&gt;"),
          "channel double-escaped in description:\n%s", d);
    CHECK(!strstr(d, "<b>"), "no raw markup");
    free(d);
}

static void test_unknown_name_stale_station(void)
{
    kml_live_reset();
    note(0xdeadbeef, -33.9, 151.2, 1000, NULL);
    kml_live_station_t st = { .name = NULL, .lat = -33.8, .lon = 151.0, .alt_m = 30.0 };
    char *d = kml_live_feed(&st, 1000 + KML_LIVE_STALE_S + 5, NULL);
    CHECK(strstr(d, "<name>!deadbeef</name>"), "falls back to !id");
    CHECK(strstr(d, "<styleUrl>#node-stale</styleUrl>"), "stale style after an hour");
    CHECK(strstr(d, "<name>RX station</name>"), "station placemark");
    CHECK(strstr(d, "<name>LOS</name>"), "LOS line");
    CHECK(strstr(d, "151.000000,-33.800000,30.0"), "LOS starts at station");
    free(d);
}

static void test_eviction(void)
{
    kml_live_reset();
    for (uint32_t i = 0; i < KML_LIVE_MAX_NODES; ++i)
        note(0x1000 + i, 10.0 + i * 0.001, 20.0, 2000 + (time_t)i, NULL);
    note(0x9999, 11.0, 21.0, 9000, NULL);      /* evicts 0x1000 (oldest) */
    char *d = kml_live_feed(NULL, 9000, NULL);
    char want[64];
    snprintf(want, sizeof(want), "%d node(s)", KML_LIVE_MAX_NODES);
    CHECK(strstr(d, want), "capped at max nodes");
    CHECK(!strstr(d, "node_00001000"), "oldest evicted");
    CHECK(strstr(d, "node_00001001") && strstr(d, "node_00009999"), "others kept");
    free(d);
}

int main(void)
{
    test_network_link();
    test_empty_and_rejects();
    test_track_and_labels();
    test_unknown_name_stale_station();
    test_eviction();
    if (fails) { fprintf(stderr, "%d failure(s)\n", fails); return 1; }
    printf("test_kml_live: all passed\n");
    return 0;
}
