/* lora_tx_harness HEXPAYLOAD SF CR(1..4) BW RATE OUT.cf32
 * Prints the symbols, writes the modulated IQ (preamble 16, sync 0x2B,
 * pad 20 symbols' worth, as tools/meshtastic_tx.py asks gr-lora_sdr for). */
#include "lora_tx.h"
#include <pthread.h>
pthread_mutex_t fftw_planner_mutex = PTHREAD_MUTEX_INITIALIZER;  /* lora.c needs these */
int verbose;
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 7) return 2;
    uint8_t p[255];
    size_t n = strlen(argv[1]) / 2;
    for (size_t i = 0; i < n; ++i) sscanf(argv[1] + 2 * i, "%2hhx", &p[i]);
    int sf = atoi(argv[2]), cr = atoi(argv[3]), bw = atoi(argv[4]), rate = atoi(argv[5]);
    uint32_t syms[2048];
    int ns = lora_tx_symbols(p, n, sf, cr, lora_tx_ldro_auto(sf, bw), syms, 2048);
    if (ns < 0) return 1;
    for (int i = 0; i < ns; ++i) printf("%u%c", syms[i], i + 1 < ns ? ' ' : '\n');
    int os = rate / bw;
    size_t pad = (size_t)(20 * (1 << sf) * (double)rate / bw);
    size_t cap = lora_tx_num_samples(ns, sf, os, 16, pad);
    float complex *iq = malloc(cap * sizeof(*iq));
    size_t got = lora_tx_modulate(syms, ns, sf, os, 16, 0x2B, pad, iq, cap);
    FILE *f = fopen(argv[6], "wb");
    fwrite(iq, sizeof(*iq), got, f);
    fclose(f);
    free(iq);
    return got ? 0 : 1;
}
