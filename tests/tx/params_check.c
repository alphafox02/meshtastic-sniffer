/* Dump the receiver's LoRa/Meshtastic parameters as JSON, so
 * params_check.py can compare them with what tools/meshtastic_tx.py
 * transmits. Everything here comes from the sniffer's own RX code:
 *   - presets (SF, CR, BW, preamble, default channel name): MESH_PRESETS
 *   - regions and every channel slot frequency: mesh_channel_count/_freq_hz
 *   - channel hash for "Name=SPEC" key specs: keyset_parse_spec
 *   - ppm tuning: hackrf_ppm_tune_hz
 * Usage: params_check SPEC [SPEC...]   (SPECs as for --keys) */
#define _GNU_SOURCE
#include "meshtastic.h"
#include "keyset.h"
#include "hackrf.h"

#include <stdio.h>

int main(int argc, char **argv)
{
    printf("{\"presets\":[");
    for (int p = 0; p < MESH_PRESET_COUNT; ++p) {
        const mesh_preset_def_t *d = &MESH_PRESETS[p];
        printf("%s{\"key\":\"%s\",\"name\":\"%s\",\"sf\":%d,\"cr\":%d,\"bw\":%d,\"preamble\":%d}",
               p ? "," : "", d->name, d->channel_name, d->spread_factor, d->coding_rate,
               d->bw_hz_narrow, d->preamble_sub);
    }
    printf("],\"regions\":[");
    for (int r = 0; r < MESH_REGION_COUNT; ++r) {
        const mesh_region_t *rg = &MESH_REGIONS[r];
        printf("%s{\"name\":\"%s\",\"f_lo\":%.6f,\"f_hi\":%.6f,\"wide\":%s,\"plans\":{",
               r ? "," : "", rg->name, rg->f_lo_mhz, rg->f_hi_mhz, rg->wide_lora ? "true" : "false");
        for (int p = 0; p < MESH_PRESET_COUNT; ++p) {
            int bw = rg->wide_lora ? MESH_PRESETS[p].bw_hz_wide : MESH_PRESETS[p].bw_hz_narrow;
            int n = mesh_channel_count(rg, bw);
            printf("%s\"%s\":{\"bw\":%d,\"n\":%d,\"freqs\":[", p ? "," : "", MESH_PRESETS[p].name, bw, n);
            for (int s = 0; s < n; ++s)
                printf("%s%llu", s ? "," : "", (unsigned long long)mesh_channel_freq_hz(rg, bw, s));
            printf("]}");
        }
        printf("}}");
    }
    printf("],\"hashes\":[");
    keyset_t *ks = keyset_create();
    for (int i = 1; i < argc; ++i) {
        int before = ks->n_entries;
        int rc = keyset_parse_spec(ks, argv[i]);
        const keyset_entry_t *e = (rc == 0 && ks->n_entries > before) ? keyset_get(ks, before) : NULL;
        printf("%s{\"spec\":\"%s\",\"ok\":%s", i > 1 ? "," : "", argv[i], e ? "true" : "false");
        if (e) {
            printf(",\"hash\":%u,\"key\":\"", e->channel_hash);
            for (size_t j = 0; j < e->psk_len; ++j) printf("%02x", e->psk[j]);
            printf("\"");
        }
        printf("}");
    }
    keyset_destroy(ks);
    printf("],\"tune\":[");
    const double fs[] = { 433875000.0, 869525000.0, 906875000.0, 869025000.0 };
    const double ppms[] = { 0.0, 1.5, -2.25, 10.0, -37.7, 0.333 };
    int first = 1;
    for (size_t i = 0; i < sizeof(fs) / sizeof(fs[0]); ++i)
        for (size_t j = 0; j < sizeof(ppms) / sizeof(ppms[0]); ++j) {
            printf("%s{\"f\":%.1f,\"ppm\":%g,\"hz\":%llu}", first ? "" : ",", fs[i], ppms[j],
                   (unsigned long long)hackrf_ppm_tune_hz(fs[i], ppms[j]));
            first = 0;
        }
    printf("]}\n");
    return 0;
}
