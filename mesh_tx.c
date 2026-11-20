/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * meshtastic-sniffer: Meshtastic packets + HackRF IQ in C. See mesh_tx.h.
 * Mirrors tools/meshtastic_tx.py function by function.
 */

#define _GNU_SOURCE
#include "mesh_tx.h"
#include "lora_tx.h"
#include "meshtastic.h"
#include "pki.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <complex.h>
#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define BROADCAST   0xFFFFFFFFu
#define SYNC_WORD   0x2B
#define HEADER_LEN  16
#define MAX_PAYLOAD 255

enum { PORT_TEXT = 1, PORT_POSITION = 3, PORT_NODEINFO = 4, PORT_ROUTING = 5,
       PORT_TELEMETRY = 67, PORT_TRACEROUTE = 70 };

static const char *const KIND_NAMES[MESH_TX_NKINDS] = {
    "text", "position", "nodeinfo", "telemetry", "traceroute" };
static const int KIND_PORTS[MESH_TX_NKINDS] = {
    PORT_TEXT, PORT_POSITION, PORT_NODEINFO, PORT_TELEMETRY, PORT_TRACEROUTE };

const char *mesh_tx_kind_name(int kind)
{
    return (kind >= 0 && kind < MESH_TX_NKINDS) ? KIND_NAMES[kind] : NULL;
}

static int fail(char *err, size_t errlen, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
    return -1;
}

uint32_t mesh_tx_djb2(const char *s)
{
    uint32_t h = 5381;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) h = h * 33 + *p;
    return h;
}

/* ---- protobuf (minimal writer) ---- */

typedef struct { uint8_t b[512]; size_t n; bool overflow; } pb_t;

static void pb_byte(pb_t *p, uint8_t v) { if (p->n < sizeof(p->b)) p->b[p->n++] = v; else p->overflow = true; }
static void pb_varint(pb_t *p, uint64_t v)
{
    do { uint8_t c = v & 0x7F; v >>= 7; pb_byte(p, (uint8_t)(c | (v ? 0x80 : 0))); } while (v);
}
static void pb_f_varint(pb_t *p, int num, uint64_t v) { pb_varint(p, (uint64_t)num << 3); pb_varint(p, v); }
static void pb_f_bytes(pb_t *p, int num, const void *d, size_t n)
{
    pb_varint(p, ((uint64_t)num << 3) | 2);
    pb_varint(p, n);
    for (size_t i = 0; i < n; ++i) pb_byte(p, ((const uint8_t *)d)[i]);
}
static void pb_f_fixed32(pb_t *p, int num, uint32_t v)
{
    pb_varint(p, ((uint64_t)num << 3) | 5);
    for (int i = 0; i < 4; ++i) pb_byte(p, (uint8_t)(v >> (8 * i)));
}

/* meshtastic.Data { portnum=1; payload=2; want_response=3; request_id=6; reply_id=7 } */
static void data_envelope(pb_t *out, int port, const uint8_t *payload, size_t n,
                          bool want_response, uint32_t reply_id)
{
    pb_f_varint(out, 1, (uint64_t)port);
    pb_f_bytes(out, 2, payload, n);
    if (want_response) pb_f_varint(out, 3, 1);
    if (reply_id) pb_f_fixed32(out, 7, reply_id);
}

/* meshtastic.User { id=1; long_name=2; short_name=3; hw_model=5; public_key=8 } */
static void user_protobuf(pb_t *out, uint32_t node, const char *long_name, const char *short_name,
                          const uint8_t *pub)
{
    char id[16];
    snprintf(id, sizeof(id), "!%08x", node);
    pb_f_bytes(out, 1, id, strlen(id));
    pb_f_bytes(out, 2, long_name, strlen(long_name));
    pb_f_bytes(out, 3, short_name, strlen(short_name));
    pb_f_varint(out, 5, 255);                       /* HardwareModel.PRIVATE_HW */
    if (pub) pb_f_bytes(out, 8, pub, 32);
}

/* ---- keys ---- */

static int expand_psk(const char *arg, uint8_t key[32], size_t *key_len, char *err, size_t errlen)
{
    *key_len = 0;
    if (!arg || !*arg || !strcasecmp(arg, "none")) return 0;
    if (!strcasecmp(arg, "default")) arg = "AQ==";
    size_t n = strlen(arg);
    if (n > 64) return fail(err, errlen, "PSK longer than 32 bytes");
    char buf[72];
    memcpy(buf, arg, n);
    while (n % 4) buf[n++] = '=';
    buf[n] = 0;
    uint8_t raw[54];
    int got = EVP_DecodeBlock(raw, (const unsigned char *)buf, (int)n);
    if (got < 0) return fail(err, errlen, "PSK is not base64");
    for (size_t i = n; i > 0 && buf[i - 1] == '='; --i) --got;   /* padding */
    if (got > 32) return fail(err, errlen, "PSK longer than 32 bytes");
    if (got == 0) return 0;
    if (got == 1) {
        if (raw[0] == 0) return 0;
        memcpy(key, MESH_DEFAULT_PSK, 16);
        key[15] = (uint8_t)(key[15] + raw[0] - 1);
        *key_len = 16;
        return 0;
    }
    memset(key, 0, 32);
    memcpy(key, raw, (size_t)got);
    *key_len = got <= 16 ? 16 : 32;    /* firmware zero-pads to AES-128 / AES-256 */
    return 0;
}

static uint8_t xor_hash(const uint8_t *p, size_t n)
{
    uint8_t h = 0;
    for (size_t i = 0; i < n; ++i) h ^= p[i];
    return h;
}

static int aes_ctr(const uint8_t *key, size_t key_len, uint32_t packet_id, uint32_t from,
                   const uint8_t *in, size_t n, uint8_t *out)
{
    uint8_t nonce[16] = {0};
    for (int i = 0; i < 4; ++i) {
        nonce[i]     = (uint8_t)(packet_id >> (8 * i));   /* LE64 packet id */
        nonce[8 + i] = (uint8_t)(from >> (8 * i));        /* LE32 from */
    }
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int len = 0, fin = 0, ok = c &&
        EVP_EncryptInit_ex(c, key_len == 32 ? EVP_aes_256_ctr() : EVP_aes_128_ctr(), NULL, key, nonce) == 1 &&
        EVP_EncryptUpdate(c, out, &len, in, (int)n) == 1 &&
        EVP_EncryptFinal_ex(c, out + len, &fin) == 1;
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

static uint32_t random_u32(void)
{
    uint32_t v = 0;
    while (v == 0) RAND_bytes((unsigned char *)&v, sizeof(v));
    return v;
}

/* ---- airtime (Semtech formula, explicit header, CRC on) ---- */

static double airtime_s(size_t n_bytes, int sf, int cr, int bw, int preamble)
{
    double t_sym = (double)(1 << sf) / bw;
    int de = t_sym > 0.016 ? 1 : 0;
    double num = 8.0 * (double)n_bytes - 4.0 * sf + 28 + 16;
    double n_payload = 8 + fmax(ceil(num / (4.0 * (sf - 2 * de))) * cr, 0);
    return (preamble + 4.25 + n_payload) * t_sym;
}

/* ---- int8 IQ for the HackRF (tool's to_hackrf_int8) ---- */

static int to_hackrf_int8(const float complex *iq, size_t n, uint32_t rate, double if_offset,
                          int8_t **out, size_t *out_bytes)
{
    size_t lead = (size_t)(0.02 * rate);
    float complex *sh = malloc(n * sizeof(*sh));
    int8_t *o = malloc((lead + n) * 2);
    if (!sh || !o) { free(sh); free(o); return -1; }
    float peak = 0;
    for (size_t i = 0; i < n; ++i) {
        double ph = 2.0 * M_PI * if_offset * (double)i / rate;
        float complex rot = (float)cos(ph) + I * (float)sin(ph);
        sh[i] = iq[i] * rot;
        float a = cabsf(sh[i]);
        if (a > peak) peak = a;
    }
    if (peak == 0) peak = 1;
    memset(o, 0, lead * 2);
    for (size_t i = 0; i < n; ++i) {
        float complex v = sh[i] / peak * 0.95f;
        float re = nearbyintf(crealf(v) * 127), im = nearbyintf(cimagf(v) * 127);  /* half-even, as np.round */
        o[2 * (lead + i)]     = (int8_t)fmaxf(-127, fminf(127, re));
        o[2 * (lead + i) + 1] = (int8_t)fmaxf(-127, fminf(127, im));
    }
    free(sh);
    *out = o;
    *out_bytes = (lead + n) * 2;
    return 0;
}

/* ---- one packet ---- */

typedef struct {
    const mesh_preset_def_t *preset;
    const char *channel;
    uint8_t key[32];
    size_t key_len;
    uint64_t freq, lo;
    uint32_t rate;
    double if_offset;
} plan_t;

static int build_packet(const mesh_tx_req_t *r, const plan_t *pl, const char *label,
                        const uint8_t *inner, size_t inner_len, uint32_t dest, bool want_ack,
                        const uint8_t *pki_shared, uint32_t packet_id,
                        mesh_tx_packet_t *pk, char *err, size_t errlen)
{
    memset(pk, 0, sizeof(*pk));
    snprintf(pk->label, sizeof(pk->label), "%s", label);
    pk->id = packet_id ? packet_id : random_u32();
    uint8_t *f = pk->frame;
    size_t body_len;
    if (HEADER_LEN + inner_len + (pki_shared ? PKI_OVERHEAD : 0) > MAX_PAYLOAD)
        return fail(err, errlen, "frame would be %zu bytes; max is %d (shorten the text)",
                    HEADER_LEN + inner_len + (pki_shared ? PKI_OVERHEAD : 0), MAX_PAYLOAD);
    if (pki_shared) {
        uint32_t xn = r->fixed_extra_nonce ? r->fixed_extra_nonce : random_u32();
        int n = pki_encrypt_body(pki_shared, r->from, pk->id, xn, inner, inner_len,
                                 f + HEADER_LEN, sizeof(pk->frame) - HEADER_LEN);
        if (n < 0) return fail(err, errlen, "PKI encryption failed");
        body_len = (size_t)n;
        pk->pki = true;
    } else if (pl->key_len) {
        if (aes_ctr(pl->key, pl->key_len, pk->id, r->from, inner, inner_len, f + HEADER_LEN) != 0)
            return fail(err, errlen, "AES failed");
        body_len = inner_len;
    } else {
        memcpy(f + HEADER_LEN, inner, inner_len);
        body_len = inner_len;
    }
    int hop = r->hop_limit & 7;
    uint8_t flags = (uint8_t)(hop | (want_ack ? 0x08 : 0) | (hop << 5));
    uint8_t chan_hash = pki_shared ? 0 :
        (uint8_t)(xor_hash((const uint8_t *)pl->channel, strlen(pl->channel)) ^ xor_hash(pl->key, pl->key_len));
    for (int i = 0; i < 4; ++i) {
        f[i]     = (uint8_t)(dest >> (8 * i));
        f[4 + i] = (uint8_t)(r->from >> (8 * i));
        f[8 + i] = (uint8_t)(pk->id >> (8 * i));
    }
    f[12] = flags; f[13] = chan_hash; f[14] = 0; f[15] = (uint8_t)(r->from & 0xFF);
    pk->frame_len = HEADER_LEN + body_len;

    const mesh_preset_def_t *ps = pl->preset;
    pk->freq_hz = pl->freq;
    pk->lo_hz = pl->lo;
    pk->rate = pl->rate;
    pk->airtime_ms = (uint32_t)(airtime_s(pk->frame_len, ps->spread_factor, ps->coding_rate,
                                          ps->bw_hz_narrow, ps->preamble_sub) * 1000);
    if (r->frames_only) return 0;

    int sf = ps->spread_factor, bw = ps->bw_hz_narrow, os = (int)(pl->rate / (uint32_t)bw);
    uint32_t syms[1024];
    int ns = lora_tx_symbols(pk->frame, pk->frame_len, sf, ps->coding_rate - 4,
                             lora_tx_ldro_auto(sf, bw), syms, 1024);
    if (ns < 0) return fail(err, errlen, "LoRa encoding failed");
    size_t pad = (size_t)(20.0 * (1 << sf) * pl->rate / bw);
    size_t cap = lora_tx_num_samples(ns, sf, os, ps->preamble_sub, pad);
    float complex *iq = malloc(cap * sizeof(*iq));
    if (!iq) return fail(err, errlen, "out of memory");
    size_t got = lora_tx_modulate(syms, ns, sf, os, ps->preamble_sub, SYNC_WORD, pad, iq, cap);
    int rc = got ? to_hackrf_int8(iq, got, pl->rate, pl->if_offset, &pk->iq, &pk->iq_bytes) : -1;
    free(iq);
    return rc == 0 ? 0 : fail(err, errlen, "modulation failed");
}

int mesh_tx_build(const mesh_tx_req_t *r, mesh_tx_packet_t *out, int max, char *err, size_t errlen)
{
    if (!r || !out || max < 2) return fail(err, errlen, "bad arguments");
    if (r->kind < 0 || r->kind >= MESH_TX_NKINDS) return fail(err, errlen, "unknown kind");

    plan_t pl;
    memset(&pl, 0, sizeof(pl));
    const mesh_region_t *region = mesh_lookup_region(r->region ? r->region : "US");
    if (!region || region->wide_lora) return fail(err, errlen, "unknown or 2.4 GHz region");
    pl.preset = mesh_lookup_preset(r->preset ? r->preset : "LONG_FAST");
    if (!pl.preset) return fail(err, errlen, "unknown preset");
    pl.channel = (r->channel && *r->channel) ? r->channel : pl.preset->channel_name;
    if (expand_psk(r->psk ? r->psk : "AQ==", pl.key, &pl.key_len, err, errlen) != 0) return -1;

    int bw = pl.preset->bw_hz_narrow;
    int n_slots = mesh_channel_count(region, bw);
    if (n_slots <= 0) return fail(err, errlen, "region %s is narrower than %d Hz", region->name, bw);
    int slot = r->slot;
    if (slot < 0) slot = (int)(mesh_tx_djb2(pl.channel) % (uint32_t)n_slots);
    else if (slot >= n_slots) return fail(err, errlen, "slot must be 0..%d", n_slots - 1);
    /* f = f_lo + bw/2 + slot*bw, rounded like the tool */
    pl.freq = (uint64_t)llround(region->f_lo_mhz * 1e6 + bw / 2.0 + (double)slot * bw);
    pl.rate = r->rate ? r->rate : 2000000;
    pl.if_offset = r->if_offset != 0 ? r->if_offset : 500e3;
    if (pl.rate % (uint32_t)bw) return fail(err, errlen, "rate must be a multiple of the bandwidth");
    pl.lo = (uint64_t)floor(((double)pl.freq - pl.if_offset) * (1.0 - r->ppm * 1e-6) + 0.5);

    uint32_t to = r->to;
    if (r->kind == MESH_TX_TEXT) {
        if (!r->text || !*r->text) return fail(err, errlen, "text is required");
    } else {
        if (to == BROADCAST) return fail(err, errlen, "requests need a destination node");
        if (r->text && *r->text) return fail(err, errlen, "text only goes with kind text");
        if (r->reply_id) return fail(err, errlen, "reply_id only goes with kind text");
    }
    if (r->announce_dest && to == BROADCAST) return fail(err, errlen, "announce needs a destination");
    if (r->has_dest_key && to == BROADCAST) return fail(err, errlen, "PKI DMs are unicast");

    uint8_t pub[32];
    bool have_pub = false;
    if (r->has_identity) {
        EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, r->our_priv, 32);
        size_t len = 32;
        have_pub = k && EVP_PKEY_get_raw_public_key(k, pub, &len) == 1 && len == 32;
        EVP_PKEY_free(k);
        if (!have_pub) return fail(err, errlen, "bad private key");
    }

    char long_name[48], short_name[8];
    if (r->long_name && *r->long_name) snprintf(long_name, sizeof(long_name), "%s", r->long_name);
    else snprintf(long_name, sizeof(long_name), "Meshtastic %04x", r->from & 0xFFFF);
    if (r->short_name && *r->short_name) snprintf(short_name, sizeof(short_name), "%s", r->short_name);
    else if (r->long_name && *r->long_name) snprintf(short_name, sizeof(short_name), "%.4s", r->long_name);
    else snprintf(short_name, sizeof(short_name), "%04x", r->from & 0xFFFF);
    pb_t user = {0};
    user_protobuf(&user, r->from, long_name, short_name, have_pub ? pub : NULL);

    /* PKI only for ports the firmware encrypts that way */
    int port = KIND_PORTS[r->kind];
    uint8_t shared[32];
    bool use_pki = false;
    if (r->has_dest_key) {
        if (!r->has_identity) return fail(err, errlen, "PKI needs our private key");
        if (port != PORT_TRACEROUTE && port != PORT_NODEINFO && port != PORT_ROUTING &&
            port != PORT_POSITION) {
            if (pki_shared_key(r->our_priv, r->dest_pub, shared) != 0)
                return fail(err, errlen, "destination public key is invalid");
            use_pki = true;
        }
    }

    int n = 0, id_i = 0;
    if ((r->announce_dest || (r->long_name && *r->long_name)) && r->kind != MESH_TX_NODEINFO) {
        pb_t ni = {0};
        data_envelope(&ni, PORT_NODEINFO, user.b, user.n, false, 0);
        if (build_packet(r, &pl, "nodeinfo", ni.b, ni.n, r->announce_dest ? to : BROADCAST, false,
                         NULL, r->fixed_ids[id_i++], &out[n], err, errlen) != 0)
            return -1;
        ++n;
    }
    pb_t inner = {0};
    if (r->kind == MESH_TX_TEXT) {
        data_envelope(&inner, PORT_TEXT, (const uint8_t *)r->text, strlen(r->text), false, r->reply_id);
    } else {
        static const uint8_t telemetry_req[] = { 0x12, 0x00 };   /* Telemetry { device_metrics = {} } */
        const uint8_t *body = NULL;
        size_t body_n = 0;
        if (r->kind == MESH_TX_NODEINFO) { body = user.b; body_n = user.n; }
        else if (r->kind == MESH_TX_TELEMETRY) { body = telemetry_req; body_n = sizeof(telemetry_req); }
        data_envelope(&inner, port, body ? body : (const uint8_t *)"", body_n, true, 0);
    }
    if (user.overflow || inner.overflow) { mesh_tx_free(out, n); return fail(err, errlen, "message too long"); }
    if (build_packet(r, &pl, KIND_NAMES[r->kind], inner.b, inner.n, to, r->want_ack,
                     use_pki ? shared : NULL, r->fixed_ids[id_i], &out[n], err, errlen) != 0) {
        mesh_tx_free(out, n);
        return -1;
    }
    ++n;
    memset(shared, 0, sizeof(shared));
    return n;
}

void mesh_tx_free(mesh_tx_packet_t *p, int n)
{
    for (int i = 0; p && i < n; ++i) {
        free(p[i].iq);
        p[i].iq = NULL;
    }
}
