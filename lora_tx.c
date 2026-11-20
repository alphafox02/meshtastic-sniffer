/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Original work Copyright 2022 Tapparel Joachim @EPFL,TCL (gr-lora_sdr,
 * GPL-3.0-or-later): lib/whitening_impl.cc, header_impl.cc, add_crc_impl.cc,
 * hamming_enc_impl.cc, interleaver_impl.cc, gray_demap_impl.cc,
 * modulate_impl.cc and utilities.h (build_upchirp).
 * Ported to C for meshtastic-sniffer. See lora_tx.h.
 */

#include "lora_tx.h"
#include "lora.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#define LDRO_MAX_DURATION_MS 16

bool lora_tx_ldro_auto(int sf, int bw_hz)
{
    return (float)(1u << sf) * 1e3f / (float)bw_hz > LDRO_MAX_DURATION_MS;
}

/* add_crc_impl::crc16: CRC-CCITT (poly 0x1021, init 0) one byte at a time. */
static uint16_t crc16_byte(uint16_t crc, uint8_t b)
{
    for (int i = 0; i < 8; ++i) {
        if (((crc & 0x8000) >> 8) ^ (b & 0x80)) crc = (uint16_t)((crc << 1) ^ 0x1021);
        else crc = (uint16_t)(crc << 1);
        b = (uint8_t)(b << 1);
    }
    return crc;
}

int lora_tx_symbols(const uint8_t *payload, size_t len, int sf, int cr, bool ldro,
                    uint32_t *syms, size_t cap)
{
    if (!payload || len == 0 || len > 255 || sf < 7 || sf > 12 || cr < 1 || cr > 4 || !syms)
        return -1;

    /* nibble stream: 5 header nibbles + 2 per payload byte (whitened, low
     * nibble first) + 4 CRC nibbles */
    size_t n_nib = 5 + 2 * len + 4;
    uint8_t *nib = malloc(n_nib);
    if (!nib) return -1;

    /* header_impl: length, cr|crc flag, 5-bit checksum */
    uint8_t h0 = (uint8_t)(len >> 4), h1 = (uint8_t)(len & 0x0F), h2 = (uint8_t)((cr << 1) | 1);
#define B(x, n) (((x) >> (n)) & 1)
    int c4 = B(h0, 3) ^ B(h0, 2) ^ B(h0, 1) ^ B(h0, 0);
    int c3 = B(h0, 3) ^ B(h1, 3) ^ B(h1, 2) ^ B(h1, 1) ^ B(h2, 0);
    int c2 = B(h0, 2) ^ B(h1, 3) ^ B(h1, 0) ^ B(h2, 3) ^ B(h2, 1);
    int c1 = B(h0, 1) ^ B(h1, 2) ^ B(h1, 0) ^ B(h2, 2) ^ B(h2, 1) ^ B(h2, 0);
    int c0 = B(h0, 0) ^ B(h1, 1) ^ B(h2, 3) ^ B(h2, 2) ^ B(h2, 1) ^ B(h2, 0);
#undef B
    nib[0] = h0; nib[1] = h1; nib[2] = h2;
    nib[3] = (uint8_t)c4;
    nib[4] = (uint8_t)(c3 << 3 | c2 << 2 | c1 << 1 | c0);

    /* whitening_impl */
    uint8_t white[255];
    memcpy(white, payload, len);
    lora_dewhiten(white, len);  /* XOR with the whitening sequence: its own inverse */
    for (size_t i = 0; i < len; ++i) {
        nib[5 + 2 * i]     = white[i] & 0x0F;
        nib[5 + 2 * i + 1] = white[i] >> 4;
    }

    /* add_crc_impl: CRC over the first len-2 (unwhitened) bytes, XOR the last two */
    uint16_t crc = 0;
    for (size_t i = 0; i + 2 < len; ++i) crc = crc16_byte(crc, payload[i]);
    if (len >= 2) crc = (uint16_t)(crc ^ payload[len - 1] ^ (payload[len - 2] << 8));
    else          crc = (uint16_t)(crc ^ payload[len - 1]);   /* len 1: never used by Meshtastic */
    size_t o = 5 + 2 * len;
    nib[o] = crc & 0x0F; nib[o + 1] = (crc >> 4) & 0x0F;
    nib[o + 2] = (crc >> 8) & 0x0F; nib[o + 3] = (crc >> 12) & 0x0F;

    /* hamming_enc_impl: first sf-2 nibbles at 4/8, the rest at cr */
    uint8_t *cw = malloc(n_nib);
    if (!cw) { free(nib); return -1; }
    for (size_t i = 0; i < n_nib; ++i) {
        int cr_app = ((int)i < sf - 2) ? 4 : cr;
        /* gr's data_bin = int2bool(nibble, 4) is MSB first, so its
         * data_bin[3] is bit 0: d3..d0 below are bit 0..bit 3. */
        int d3 = nib[i] & 1, d2 = (nib[i] >> 1) & 1, d1 = (nib[i] >> 2) & 1, d0 = (nib[i] >> 3) & 1;
        if (cr_app != 1) {
            int p0 = d3 ^ d2 ^ d1, p1 = d2 ^ d1 ^ d0, p2 = d3 ^ d2 ^ d0, p3 = d3 ^ d1 ^ d0;
            cw[i] = (uint8_t)((d3 << 7 | d2 << 6 | d1 << 5 | d0 << 4 |
                               p0 << 3 | p1 << 2 | p2 << 1 | p3) >> (4 - cr_app));
        } else {
            int p4 = d0 ^ d1 ^ d2 ^ d3;
            cw[i] = (uint8_t)(d3 << 4 | d2 << 3 | d1 << 2 | d0 << 1 | p4);
        }
    }
    free(nib);

    /* interleaver_impl: blocks of sf_app codewords -> cw_len symbols */
    size_t ns = 0, cw_cnt = 0;
    int rc = 0;
    while (cw_cnt < n_nib) {
        bool first = (int)cw_cnt < sf - 2;
        int cw_len = 4 + (first ? 4 : cr);
        int sf_app = (first || ldro) ? sf - 2 : sf;
        if (ns + (size_t)cw_len > cap) { rc = -1; break; }
        uint8_t blk[12];
        for (int i = 0; i < sf_app; ++i)
            blk[i] = (cw_cnt + (size_t)i < n_nib) ? cw[cw_cnt + i] : 0;
        cw_cnt += (size_t)sf_app;
        for (int i = 0; i < cw_len; ++i) {
            /* row i: bit j (MSB first) = bit i (MSB first, of cw_len) of
             * codeword (i - j - 1) mod sf_app */
            uint32_t row = 0;
            int ones = 0;
            for (int j = 0; j < sf; ++j) {
                int bit = 0;
                if (j < sf_app) {
                    int k = ((i - j - 1) % sf_app + sf_app) % sf_app;
                    bit = (blk[k] >> (cw_len - 1 - i)) & 1;
                }
                ones += bit;
                row = (row << 1) | (uint32_t)bit;
            }
            /* first block (or LDRO): parity bit after the data bits */
            if ((int)cw_cnt == sf - 2 || ldro)
                if (ones & 1) row |= 1u << (sf - 1 - sf_app);
            /* gray_demap_impl: inverse Gray, then +1 */
            uint32_t g = row;
            for (int j = 1; j < sf; ++j) g ^= row >> j;
            syms[ns++] = (g + 1) & ((1u << sf) - 1);
        }
    }
    free(cw);
    return rc < 0 ? -1 : (int)ns;
}

/* utilities.h build_upchirp */
static void build_upchirp(float complex *chirp, uint32_t id, int sf, int os)
{
    double N = (double)(1 << sf);
    int n_fold = (int)(N * os - (double)id * os);
    for (int n = 0; n < (int)N * os; ++n) {
        double ph;
        if (n < n_fold) ph = 2.0 * M_PI * ((double)n * n / (2 * N) / pow(os, 2) + ((double)id / N - 0.5) * n / os);
        else            ph = 2.0 * M_PI * ((double)n * n / (2 * N) / pow(os, 2) + ((double)id / N - 1.5) * n / os);
        float p = (float)ph;   /* gr_expj takes a float phase */
        chirp[n] = cosf(p) + I * sinf(p);
    }
}

size_t lora_tx_num_samples(int nsyms, int sf, int os, int preamble_len, size_t pad)
{
    size_t sps = (size_t)(1u << sf) * (size_t)os;
    return (size_t)preamble_len * sps + 2 * sps + 2 * sps + sps / 4 + (size_t)nsyms * sps + pad;
}

size_t lora_tx_modulate(const uint32_t *syms, int nsyms, int sf, int os, int preamble_len,
                        uint8_t sync_word, size_t pad, float complex *out, size_t cap)
{
    size_t sps = (size_t)(1u << sf) * (size_t)os;
    size_t total = lora_tx_num_samples(nsyms, sf, os, preamble_len, pad);
    if (!out || cap < total || os < 1) return 0;
    float complex *up = malloc(sps * sizeof(*up));
    if (!up) return 0;
    build_upchirp(up, 0, sf, os);

    size_t o = 0;
    for (int i = 0; i < preamble_len; ++i, o += sps) memcpy(out + o, up, sps * sizeof(*up));
    build_upchirp(out + o, (uint32_t)(((sync_word & 0xF0) >> 4) << 3), sf, os); o += sps;
    build_upchirp(out + o, (uint32_t)((sync_word & 0x0F) << 3), sf, os);        o += sps;
    for (int k = 0; k < 2; ++k, o += sps)
        for (size_t n = 0; n < sps; ++n) out[o + n] = conjf(up[n]);
    for (size_t n = 0; n < sps / 4; ++n) out[o + n] = conjf(up[n]);
    o += sps / 4;
    for (int i = 0; i < nsyms; ++i, o += sps) build_upchirp(out + o, syms[i], sf, os);
    memset(out + o, 0, pad * sizeof(*out));
    o += pad;
    free(up);
    return o;
}
