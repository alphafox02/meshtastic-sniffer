/* The Android data path on the desktop: run the sniffer as a library
 * (sniffer_main on a thread, --external-source), push int8 I/Q into it from
 * another thread in hackrf_android-sized chunks, stop it with
 * sniffer_request_stop(). The IQ is a Meshtastic packet built by the C TX
 * engine (mesh_tx.c), so this also closes the loop TX engine -> RX decoder. */
#define _GNU_SOURCE
#include "ext_src.h"
#include "mesh_tx.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *g_argv[32];
static int   g_argc;
static int   g_rc = -1;

static void *run(void *a) { (void)a; g_rc = sniffer_main(g_argc, g_argv); return NULL; }

int main(void)
{
    /* the packet: EU_868 MediumFast broadcast text, LO 500 kHz below the channel */
    mesh_tx_req_t r;
    memset(&r, 0, sizeof(r));
    r.region = "EU_868"; r.preset = "MEDIUM_FAST"; r.psk = "AQ=="; r.slot = -1;
    r.from = 0x12345678; r.to = 0xFFFFFFFFu; r.hop_limit = 3;
    r.kind = MESH_TX_TEXT; r.text = "hello from the android path";
    mesh_tx_packet_t pk[2];
    char err[160];
    if (mesh_tx_build(&r, pk, 2, err, sizeof(err)) != 1) { fprintf(stderr, "build: %s\n", err); return 2; }

    char out_path[] = "/tmp/ext_src_out_XXXXXX";
    int fd = mkstemp(out_path);
    fflush(stdout);
    int saved = dup(1);
    dup2(fd, 1);   /* the sniffer's JSON goes to stdout */

    char center[32], rate[32];
    snprintf(center, sizeof(center), "--center=%llu", (unsigned long long)pk[0].lo_hz);
    snprintf(rate, sizeof(rate), "--rate=%u", pk[0].rate);
    const char *args[] = { "meshtastic-sniffer", "--external-source", rate, center, "--region=EU_868",
                           "--presets=MediumFast", "--keys=default", NULL };
    for (g_argc = 0; args[g_argc]; ++g_argc) g_argv[g_argc] = (char *)args[g_argc];
    pthread_t th;
    pthread_create(&th, NULL, run, NULL);

    /* wait until the backend accepts samples, then stream: 0.5 s of quiet, the packet, 1 s of quiet */
    const size_t CHUNK = 262144;     /* hackrf_android packet size */
    int8_t *quiet = calloc(1, CHUNK);
    int waited = 0;
    while (ext_src_push(quiet, CHUNK) != 0 && waited++ < 200) usleep(50000);
    int pushed_ok = waited < 200;
    for (int i = 0; i < 4; ++i) ext_src_push(quiet, CHUNK);
    for (size_t off = 0; off < pk[0].iq_bytes; off += CHUNK) {
        size_t n = pk[0].iq_bytes - off < CHUNK ? pk[0].iq_bytes - off : CHUNK;
        ext_src_push(pk[0].iq + off, n);
        usleep(1000);
    }
    for (int i = 0; i < 8; ++i) { ext_src_push(quiet, CHUNK); usleep(1000); }
    ext_src_set_paused(1);
    int paused_rejects = ext_src_push(quiet, CHUNK) != 0;
    ext_src_set_paused(0);
    sleep(3);
    sniffer_request_stop();
    pthread_join(th, NULL);
    fflush(stdout);
    dup2(saved, 1);

    char buf[1 << 16] = "";
    FILE *f = fopen(out_path, "r");
    size_t n = f ? fread(buf, 1, sizeof(buf) - 1, f) : 0;
    buf[n] = 0;
    if (f) fclose(f);
    unlink(out_path);
    mesh_tx_free(pk, 1);
    free(quiet);

    int fails = 0;
#define CHECK(c, ...) do { printf((c) ? "ok   " : "FAIL "); printf(__VA_ARGS__); printf("\n"); if (!(c)) ++fails; } while (0)
    CHECK(pushed_ok, "backend accepted samples after start-up");
    CHECK(paused_rejects, "paused input (during TX) drops samples");
    CHECK(strstr(buf, "\"text\":\"hello from the android path\"") && strstr(buf, "\"from\":\"!12345678\""),
          "pushed C-engine packet decoded by the library");
    CHECK(g_rc == 0, "sniffer_main returned 0 after sniffer_request_stop (rc=%d)", g_rc);
    printf("FAILS: %d\n", fails);
    return fails ? 1 : 0;
}
