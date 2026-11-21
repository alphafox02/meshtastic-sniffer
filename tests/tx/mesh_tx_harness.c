/* mesh_tx_harness key=value ...  -> one line per packet: "label id pki freq lo airtime hexframe"
 * Keys: region preset channel psk slot from to hop ack kind text reply long short
 *       announce priv(hex) dest(hex) ppm ids(a,b) xn frames_only out(dir: writes LABEL.s8) */
#include "mesh_tx.h"
#include "pki.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
pthread_mutex_t fftw_planner_mutex = PTHREAD_MUTEX_INITIALIZER;
int verbose;

int main(int argc, char **argv)
{
    mesh_tx_req_t r;
    memset(&r, 0, sizeof(r));
    r.slot = -1; r.to = 0xFFFFFFFFu; r.hop_limit = 3;
    const char *outdir = NULL;
    for (int i = 1; i < argc; ++i) {
        char *k = argv[i], *v = strchr(k, '=');
        if (!v) return 2;
        *v++ = 0;
        if (!strcmp(k, "region")) r.region = v;
        else if (!strcmp(k, "preset")) r.preset = v;
        else if (!strcmp(k, "channel")) r.channel = v;
        else if (!strcmp(k, "psk")) r.psk = v;
        else if (!strcmp(k, "slot")) r.slot = atoi(v);
        else if (!strcmp(k, "from")) r.from = (uint32_t)strtoul(v, NULL, 16);
        else if (!strcmp(k, "to")) r.to = (uint32_t)strtoul(v, NULL, 16);
        else if (!strcmp(k, "hop")) r.hop_limit = atoi(v);
        else if (!strcmp(k, "ack")) r.want_ack = atoi(v);
        else if (!strcmp(k, "kind")) { for (int j = 0; j < MESH_TX_NKINDS; ++j) if (!strcmp(v, mesh_tx_kind_name(j))) r.kind = j; }
        else if (!strcmp(k, "text")) r.text = v;
        else if (!strcmp(k, "reply")) r.reply_id = (uint32_t)strtoul(v, NULL, 16);
        else if (!strcmp(k, "long")) r.long_name = v;
        else if (!strcmp(k, "short")) r.short_name = v;
        else if (!strcmp(k, "announce")) r.announce_dest = atoi(v);
        else if (!strcmp(k, "priv")) { r.has_identity = pki_key_decode(v, r.our_priv) == 0; }
        else if (!strcmp(k, "dest")) { r.has_dest_key = pki_key_decode(v, r.dest_pub) == 0; }
        else if (!strcmp(k, "ppm")) r.ppm = atof(v);
        else if (!strcmp(k, "ids")) sscanf(v, "%x,%x", &r.fixed_ids[0], &r.fixed_ids[1]);
        else if (!strcmp(k, "xn")) r.fixed_extra_nonce = (uint32_t)strtoul(v, NULL, 16);
        else if (!strcmp(k, "frames_only")) r.frames_only = atoi(v);
        else if (!strcmp(k, "out")) outdir = v;
        else return 2;
    }
    mesh_tx_packet_t pk[2];
    char err[160];
    int n = mesh_tx_build(&r, pk, 2, err, sizeof(err));
    if (n < 0) { printf("ERROR %s\n", err); return 1; }
    for (int i = 0; i < n; ++i) {
        printf("%s %08x %d %llu %llu %u ", pk[i].label, pk[i].id, pk[i].pki,
               (unsigned long long)pk[i].freq_hz, (unsigned long long)pk[i].lo_hz, pk[i].airtime_ms);
        for (size_t j = 0; j < pk[i].frame_len; ++j) printf("%02x", pk[i].frame[j]);
        printf("\n");
        if (outdir && pk[i].iq) {
            char p[1024];
            snprintf(p, sizeof(p), "%s/%s.s8", outdir, pk[i].label);
            FILE *f = fopen(p, "wb");
            fwrite(pk[i].iq, 1, pk[i].iq_bytes, f);
            fclose(f);
        }
    }
    mesh_tx_free(pk, n);
    return 0;
}
