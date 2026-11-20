/* Reads lines "KEYSPEC<TAB>HEX" and prints what the sniffer decodes. */
#include "mesh_packet.h"
#include "keyset.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fired;

static void cb(const mesh_event_t *ev, void *user)
{
    (void)user;
    g_fired = 1;
    printf("from=%08x to=%08x id=%08x hop_limit=%d hop_start=%d want_ack=%d "
           "relay=%02x dec=%d chan=%s port=%u payload=",
           ev->header.from, ev->header.to, ev->header.packet_id,
           ev->hop_limit, ev->hop_start, ev->want_ack, ev->header.relay_node,
           ev->decrypted, ev->channel_name[0] ? ev->channel_name : "-", ev->portnum);
    for (size_t i = 0; i < ev->payload_len; ++i) printf("%02x", ev->payload[i]);
    printf("\n");
}

int main(void)
{
    char line[4096];
    while (fgets(line, sizeof(line), stdin)) {
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = 0;
        char *hex = tab + 1;
        hex[strcspn(hex, "\r\n")] = 0;
        uint8_t frame[512];
        size_t n = strlen(hex) / 2;
        for (size_t i = 0; i < n; ++i) sscanf(hex + 2 * i, "%2hhx", &frame[i]);
        keyset_t *ks = keyset_create();
        if (strcmp(line, "-")) keyset_parse_csv(ks, line);
        g_fired = 0;
        int rc = mesh_packet_decode(frame, n, ks, cb, NULL);
        if (!g_fired) printf("NO_EVENT rc=%d\n", rc);
        fflush(stdout);
        keyset_destroy(ks);
    }
    return 0;
}
