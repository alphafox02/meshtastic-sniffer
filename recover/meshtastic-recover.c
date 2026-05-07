/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-recover: offline PSK recovery for Meshtastic captures.
 *
 * Reads a libpcap file produced by `meshtastic-sniffer --pcap=PATH`
 * (DLT_USER0, raw on-air frames: 16-byte cleartext header + AES-CTR
 * ciphertext) and a wordlist of candidate keys, and prints any keys
 * that successfully decrypt one or more captured frames.
 *
 * Algorithm per candidate PSK:
 *   1. Compute channel-hash byte = xorHash(name) XOR xorHash(psk).
 *      Frames whose header.channel doesn't match are skipped without
 *      AES work (8-bit prefilter; ~99.6% of candidates eliminated for
 *      a given frame).
 *   2. AES-128/256-CTR decrypt the still-encrypted Data envelope using
 *      nonce = packet_id || from || zeros (matches upstream firmware).
 *   3. Run the protobuf parser. A clean parse to a Data message with a
 *      sane portnum + payload length confirms the key.
 *
 * Output is a `--keys-file=` compatible file: one
 *   name=base64:<psk-bytes>
 * line per recovered (name, psk) pair, ready to feed back to
 * meshtastic-sniffer --keys-file=.
 *
 * Why this exists: defenders auditing their own channel keys against
 * a wordlist; recovery of lost meshtastic.org/e/ URLs from a captured
 * session; education on the security model. Same dual-use posture as
 * aircrack-ng; out-of-scope to attempt anything but offline analysis
 * of bytes already on disk.
 */

#define _GNU_SOURCE

#include "../keyset.h"
#include "../mesh_packet.h"
#include "../meshtastic.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _OPENMP
#include <omp.h>
#endif

/* Thread-safe hit recording: candidate trials run in parallel, so hits
 * funnel through one mutex. Contention is irrelevant -- record_hit only
 * fires on the rare success path, not the inner loop. */
static pthread_mutex_t g_hits_mu = PTHREAD_MUTEX_INITIALIZER;

/* ---- libpcap reader (minimal, no libpcap dependency) -----------------
 *
 * Native-endian standard-magic header layout per pcap(5). We only support
 * the magic 0xa1b2c3d4 (no swap) since meshtastic-sniffer always writes
 * native-endian. Refusing to swap keeps the reader 30 lines instead of 60. */

struct pcap_global_hdr {
    uint32_t magic;
    uint16_t version_major, version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};
struct pcap_record_hdr {
    uint32_t ts_sec, ts_usec;
    uint32_t incl_len, orig_len;
};

static int read_pcap_global(FILE *f)
{
    struct pcap_global_hdr h;
    if (fread(&h, sizeof(h), 1, f) != 1) {
        fprintf(stderr, "recover: pcap header read failed\n");
        return -1;
    }
    if (h.magic != 0xa1b2c3d4) {
        fprintf(stderr, "recover: pcap magic 0x%08x unexpected (need native-LE 0xa1b2c3d4 from meshtastic-sniffer)\n", h.magic);
        return -1;
    }
    if (h.network != 147 /* DLT_USER0 */) {
        fprintf(stderr, "recover: pcap link type %u, expected 147 (DLT_USER0)\n", h.network);
        return -1;
    }
    return 0;
}

/* ---- Wordlist -> candidate-PSK iterator ------------------------------
 *
 * Each non-comment, non-empty line of the wordlist becomes one candidate.
 * We accept three shapes:
 *   1. base64:<bytes>  / hex:<bytes>  -- explicit raw key (16 or 32 bytes)
 *   2. simple<N>       -- the firmware's simpleN derivation (1..255)
 *   3. <plain text>    -- treated as a passphrase: try as 16-byte raw
 *                         (truncated/zero-padded); future: SHA256 derive */

typedef struct {
    char     name[64];      /* channel name to attribute the key under */
    uint8_t  psk[32];
    size_t   psk_len;
    char     source[80];    /* original wordlist line, for the recovery report */
} candidate_t;

static int b64_decode_byte(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int parse_b64(const char *in, uint8_t *out, size_t cap)
{
    size_t n = 0;
    while (*in && n < cap) {
        int v[4];
        int got = 0;
        while (got < 4 && *in) {
            if (*in == '=' || isspace((unsigned char)*in)) { ++in; continue; }
            int b = b64_decode_byte((unsigned char)*in++);
            if (b < 0) return -1;
            v[got++] = b;
        }
        if (got < 2) break;
        if (n < cap) out[n++] = (v[0] << 2) | (v[1] >> 4);
        if (got >= 3 && n < cap) out[n++] = ((v[1] & 0x0f) << 4) | (v[2] >> 2);
        if (got >= 4 && n < cap) out[n++] = ((v[2] & 0x03) << 6) | v[3];
    }
    return (int)n;
}

static int parse_hex(const char *in, uint8_t *out, size_t cap)
{
    size_t n = 0;
    while (*in && n < cap) {
        while (*in && (*in == ' ' || *in == ':')) ++in;
        if (!in[0] || !in[1]) break;
        int hi = (*in >= 'a') ? *in - 'a' + 10 : (*in >= 'A') ? *in - 'A' + 10 : *in - '0';
        ++in;
        int lo = (*in >= 'a') ? *in - 'a' + 10 : (*in >= 'A') ? *in - 'A' + 10 : *in - '0';
        ++in;
        if (hi < 0 || hi > 15 || lo < 0 || lo > 15) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return (int)n;
}

/* simpleN: copies the upstream firmware constant + last-byte = N. Same
 * derivation lives in keyset.c; duplicated here with a private name to
 * avoid pulling internal-linkage helpers out for the cracker. */
static void make_simple_psk(int n, uint8_t out[16])
{
    static const uint8_t base[16] = {
        0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
        0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
    };
    memcpy(out, base, 16);
    out[15] = (uint8_t)n;
}

static bool fill_candidate(const char *line, candidate_t *c)
{
    memset(c, 0, sizeof(*c));
    strncpy(c->source, line, sizeof(c->source) - 1);

    if (!strncmp(line, "base64:", 7)) {
        int n = parse_b64(line + 7, c->psk, sizeof(c->psk));
        if (n != 16 && n != 32) return false;
        c->psk_len = (size_t)n;
        snprintf(c->name, sizeof(c->name), "%s", "(wordlist)");
        return true;
    }
    if (!strncmp(line, "hex:", 4)) {
        int n = parse_hex(line + 4, c->psk, sizeof(c->psk));
        if (n != 16 && n != 32) return false;
        c->psk_len = (size_t)n;
        snprintf(c->name, sizeof(c->name), "%s", "(wordlist)");
        return true;
    }
    if (!strncmp(line, "simple", 6)) {
        int n = atoi(line + 6);
        if (n < 1 || n > 255) return false;
        make_simple_psk(n, c->psk);
        c->psk_len = 16;
        snprintf(c->name, sizeof(c->name), "simple%d", n);
        return true;
    }
    /* Plaintext passphrase: pad/truncate to 16 bytes. Many users who set a
     * "secret" via a friend texting them the channel-share URL never see the
     * raw key; they think of the phrase as the password. Try literal bytes. */
    size_t len = strlen(line);
    if (len == 0) return false;
    size_t copy = len < 16 ? len : 16;
    memcpy(c->psk, line, copy);
    c->psk_len = 16;
    snprintf(c->name, sizeof(c->name), "%s", "(wordlist)");
    return true;
}

/* ---- Per-frame trial ------------------------------------------------- */

typedef struct {
    bool     found;
    uint8_t  channel_hash;        /* the hash byte that the key recovered */
    char     name[64];
    uint8_t  psk[32];
    size_t   psk_len;
    char     source[80];
} hit_t;

#define MAX_HITS 64
static hit_t g_hits[MAX_HITS];
static int   g_n_hits = 0;

static bool already_have(uint8_t hash, const uint8_t *psk, size_t psk_len)
{
    for (int i = 0; i < g_n_hits; ++i) {
        if (g_hits[i].channel_hash == hash &&
            g_hits[i].psk_len == psk_len &&
            !memcmp(g_hits[i].psk, psk, psk_len))
            return true;
    }
    return false;
}

static void record_hit(uint8_t hash, const candidate_t *c, const char *channel_name)
{
    pthread_mutex_lock(&g_hits_mu);
    if (g_n_hits >= MAX_HITS) { pthread_mutex_unlock(&g_hits_mu); return; }
    if (already_have(hash, c->psk, c->psk_len)) { pthread_mutex_unlock(&g_hits_mu); return; }
    hit_t *h = &g_hits[g_n_hits++];
    h->found = true;
    h->channel_hash = hash;
    h->psk_len = c->psk_len;
    memcpy(h->psk, c->psk, c->psk_len);
    snprintf(h->name, sizeof(h->name), "%s",
             (channel_name && *channel_name) ? channel_name : c->name);
    snprintf(h->source, sizeof(h->source), "%s", c->source);
    fprintf(stderr, "  [hash 0x%02x] FOUND psk (%zu bytes) name='%s' from='%s'\n",
            hash, c->psk_len, h->name, c->source);
    pthread_mutex_unlock(&g_hits_mu);
}

/* Callback for mesh_packet_decode. Reject false positives: the protobuf
 * parser is forgiving enough that random garbage from a wrong-key AES
 * decrypt can occasionally produce a "valid-shape" Data message. Require
 * (a) a known port number (low values per upstream port enum or in the
 * common-application range) AND (b) some payload, OR a populated
 * channel_name. That gates out near-empty parses that fire the callback
 * without earning it. */
struct cap_state { bool fired; char name[64]; };
static void on_event_cb(const mesh_event_t *ev, void *user)
{
    struct cap_state *s = user;
    /* Reject false positives: a wrong-key AES-CTR decrypt produces
     * uniformly random bytes; once in a while those random bytes form
     * a valid-shape protobuf envelope with portnum=0 and zero-length
     * payload. Real Meshtastic traffic has a non-zero portnum (the
     * port enum starts at 1 = TEXT_MESSAGE_APP) and non-empty payload.
     * Requiring both eliminates the false-match rate to negligible. */
    if (ev->portnum == 0 || ev->portnum > 511 || ev->payload_len == 0) return;
    s->fired = true;
    if (ev->channel_name[0]) snprintf(s->name, sizeof(s->name), "%s", ev->channel_name);
}

/* Decrypt-then-protobuf-parse confirmation. Reuses the keyset machinery
 * by adding the candidate to a single-entry temporary keyset and running
 * mesh_packet_decode; on success we know the key was right. */
static bool try_candidate(const uint8_t *frame, size_t frame_len,
                          const candidate_t *c, char *recovered_name)
{
    keyset_t *ks = keyset_create();
    if (!ks) return false;
    uint8_t hash = mesh_channel_hash(c->name, c->psk, c->psk_len);
    if (keyset_add_raw(ks, hash, c->psk, c->psk_len, c->name) < 0) {
        keyset_destroy(ks);
        return false;
    }
    struct cap_state cap = { false, "" };
    bool got = false;
    if (mesh_packet_decode(frame, frame_len, ks, on_event_cb, &cap) == 0 && cap.fired) {
        got = true;
        if (recovered_name) snprintf(recovered_name, 64, "%s",
                                     cap.name[0] ? cap.name : c->name);
    }
    keyset_destroy(ks);
    return got;
}

/* ---- Main ------------------------------------------------------------ */

static const char USAGE[] =
    "Usage: meshtastic-recover --pcap=FILE --wordlist=FILE [options]\n"
    "\n"
    "Recover Meshtastic channel PSKs from a captured session by trying\n"
    "each candidate against the channel-hash byte and AES-CTR decrypt.\n"
    "Prints recovered keys in --keys-file= compatible format.\n"
    "\n"
    "Options:\n"
    "  --pcap=FILE         libpcap input (DLT_USER0) from --pcap=PATH on the sniffer\n"
    "  --wordlist=FILE     candidate PSKs, one per line; supports base64:/hex:/simpleN\n"
    "                      forms or plain passphrases (truncated/padded to 16 bytes)\n"
    "  --simple-keys       also try simple1..simple255 (the firmware default keys)\n"
    "  --output=FILE       append recovered keys here in --keys-file= format\n"
    "                      (default: stdout)\n"
    "  --max-frames=N      stop after testing N frames against each candidate (0=all)\n"
    "  --hashcat-export=FILE\n"
    "                      write each frame as a hashcat-compatible hash line:\n"
    "                          $meshtastic$1*<chash>*<packet_id>*<from_node>*<name_hex>*<ciphertext_hex>\n"
    "                      consumable by a future hashcat custom-mode plugin\n"
    "                      (work in progress; format documented in recover/README.md)\n"
    "  --channel-name=NAME populate the <name_hex> field on export. Use when the\n"
    "                      attacker knows the channel name (most realistic case --\n"
    "                      Meshtastic NodeInfo advertises names in cleartext).\n"
    "                      Empty by default; the future plugin iterates common\n"
    "                      preset names internally when this is empty.\n"
    "  -h, --help          this help\n"
    "\n"
    "Examples:\n"
    "  meshtastic-recover --pcap=session.pcap --wordlist=/usr/share/dict/words \\\n"
    "                     --simple-keys --output=recovered.keys\n"
    "  meshtastic-sniffer --file=session.pcap --keys-file=recovered.keys\n";

int main(int argc, char **argv)
{
    const char *pcap_path = NULL;
    const char *wordlist_path = NULL;
    const char *out_path = NULL;
    const char *hashcat_path = NULL;
    const char *channel_name = "";
    bool also_simple = false;
    int max_frames = 0;

    for (int i = 1; i < argc; ++i) {
        if      (!strncmp(argv[i], "--pcap=", 7))     pcap_path = argv[i] + 7;
        else if (!strncmp(argv[i], "--wordlist=", 11)) wordlist_path = argv[i] + 11;
        else if (!strncmp(argv[i], "--output=", 9))   out_path = argv[i] + 9;
        else if (!strncmp(argv[i], "--hashcat-export=", 17)) hashcat_path = argv[i] + 17;
        else if (!strncmp(argv[i], "--channel-name=", 15)) channel_name = argv[i] + 15;
        else if (!strncmp(argv[i], "--max-frames=", 13)) max_frames = atoi(argv[i] + 13);
        else if (!strcmp(argv[i], "--simple-keys"))   also_simple = true;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            fputs(USAGE, stdout); return 0;
        } else {
            fprintf(stderr, "recover: unknown arg '%s'\n", argv[i]);
            fputs(USAGE, stderr); return 2;
        }
    }
    if (!pcap_path || (!wordlist_path && !also_simple && !hashcat_path)) {
        fputs(USAGE, stderr); return 2;
    }

    /* Slurp the pcap into memory: typical session captures are tens of
     * MB at most, and we'll iterate over them once per candidate so an
     * in-memory representation is faster than re-reading from disk. */
    FILE *pf = fopen(pcap_path, "rb");
    if (!pf) { perror(pcap_path); return 1; }
    if (read_pcap_global(pf) < 0) { fclose(pf); return 1; }
    typedef struct frame_rec { size_t len; uint8_t bytes[260]; } frame_rec;
    frame_rec *frames = NULL;
    size_t n_frames = 0, cap_frames = 0;
    while (1) {
        struct pcap_record_hdr rh;
        if (fread(&rh, sizeof(rh), 1, pf) != 1) break;
        if (rh.incl_len > sizeof(((frame_rec *)0)->bytes)) {
            fseek(pf, rh.incl_len, SEEK_CUR);
            continue;
        }
        if (n_frames == cap_frames) {
            cap_frames = cap_frames ? cap_frames * 2 : 256;
            frames = realloc(frames, cap_frames * sizeof(*frames));
            if (!frames) { perror("realloc"); fclose(pf); return 1; }
        }
        if (fread(frames[n_frames].bytes, rh.incl_len, 1, pf) != 1) break;
        frames[n_frames].len = rh.incl_len;
        ++n_frames;
    }
    fclose(pf);
    fprintf(stderr, "recover: loaded %zu frames from %s\n", n_frames, pcap_path);
    if (!n_frames) {
        fprintf(stderr, "recover: empty capture, nothing to do\n");
        free(frames); return 1;
    }

    /* Hashcat export: one line per frame, hashcat-idiomatic format.
     * Modeled on mode 22400 (AES Crypt) for the dollar-tag + star-delimited
     * shape, and on mode 22000 (WPA-EAPOL) for the "expose nonce parts +
     * ESSID separately, kernel reconstructs" philosophy.
     *
     * Format v1:
     *   $meshtastic$1*<chash>*<packet_id>*<from_node>*<name_hex>*<ciphertext>
     *
     *   chash       -- 2 hex chars; channel-hash byte from frame[13]
     *   packet_id   -- 8 hex chars; uint32 LE from frame[8..11]
     *   from_node   -- 8 hex chars; uint32 LE from frame[4..7]
     *   name_hex    -- variable hex (may be empty); UTF-8 channel name when
     *                  known. Empty signals "unknown name" -- the plugin
     *                  falls back to iterating a builtin list of common
     *                  preset names per candidate PSK.
     *   ciphertext  -- variable hex; frame[16..end] (encrypted Data envelope)
     *
     * The kernel reconstructs the AES-CTR 16-byte nonce as
     *   packet_id_LE || 0x00000000 || from_node_LE || 0x00000000
     * matching build_nonce() in mesh_packet.c.
     *
     * Verifier given candidate (psk, name):
     *   1. compute xorByte(name) ^ xorByte(psk); compare to chash
     *   2. if match, AES-CTR decrypt ciphertext with (psk, reconstructed nonce)
     *   3. confirm decrypted bytes parse as a Meshtastic Data envelope
     *      with portnum > 0 and non-empty payload */
    if (hashcat_path) {
        FILE *hf = fopen(hashcat_path, "w");
        if (!hf) { perror(hashcat_path); free(frames); return 1; }
        size_t emitted = 0;
        for (size_t i = 0; i < n_frames; ++i) {
            if (frames[i].len < 16) continue;
            const uint8_t *b = frames[i].bytes;
            uint8_t chash = b[13];
            fprintf(hf, "$meshtastic$1*%02x*", chash);
            for (int k = 0; k < 4; ++k) fprintf(hf, "%02x", b[8 + k]);  /* packet_id LE */
            fputc('*', hf);
            for (int k = 0; k < 4; ++k) fprintf(hf, "%02x", b[4 + k]);  /* from LE */
            fputc('*', hf);
            for (const char *p = channel_name; *p; ++p) fprintf(hf, "%02x", (unsigned char)*p);
            fputc('*', hf);
            for (size_t k = 16; k < frames[i].len; ++k)
                fprintf(hf, "%02x", b[k]);
            fputc('\n', hf);
            ++emitted;
        }
        fclose(hf);
        fprintf(stderr, "recover: wrote %zu hashcat-format lines to %s%s%s\n",
                emitted, hashcat_path,
                channel_name && *channel_name ? " (channel_name=" : "",
                channel_name && *channel_name ? channel_name : "");
    }

    /* Channel names to pair with each candidate PSK. The Meshtastic
     * firmware computes the channel-hash byte as
     * xorHash(channel_name) XOR xorHash(psk), so a candidate PSK can
     * only match if we ALSO have the right name. The empty string
     * covers the "PSK only" case; the preset names cover the most
     * common factory-default deployments where channel name == preset
     * (e.g. "LongFast" + simple1 = the default-key default-channel
     * combination most users never change). */
    static const char *const NAME_CANDIDATES[] = {
        "",
        "LongFast", "LongSlow", "LongMod", "LongTurbo",
        "MediumFast", "MediumSlow",
        "ShortFast", "ShortSlow", "ShortTurbo",
        "Default", "Primary", "Public", "admin",
        NULL
    };

    /* Inner-loop helper: try one candidate against every frame, recording
     * the first hit. Side-effect-only (record_hit is mutex-guarded), so
     * it's safe to call from OpenMP parallel regions. */
    int frames_to_test = max_frames > 0 && (size_t)max_frames < n_frames
                         ? max_frames : (int)n_frames;

    /* Run the simple-keys pass first if requested -- catches the
     * default-channel cases instantly. Parallelized over the simpleN
     * dimension; each thread gets its own (n, name) sweep. */
    size_t tried = 0, cand_used = 0;
    time_t t_start = time(NULL);
    if (also_simple) {
        const int n_names = (int)(sizeof(NAME_CANDIDATES) / sizeof(NAME_CANDIDATES[0])) - 1;
        const int n_simple_pairs = 255 * n_names;
        cand_used += (size_t)n_simple_pairs;

        #ifdef _OPENMP
        #pragma omp parallel for schedule(static) reduction(+:tried)
        #endif
        for (int idx = 0; idx < n_simple_pairs; ++idx) {
            int n = (idx / n_names) + 1;
            int ni = idx % n_names;
            candidate_t c = {0};
            make_simple_psk(n, c.psk);
            c.psk_len = 16;
            snprintf(c.name, sizeof(c.name), "%s", NAME_CANDIDATES[ni]);
            snprintf(c.source, sizeof(c.source), "simple%d (name=\"%s\")",
                     n, NAME_CANDIDATES[ni]);
            uint8_t want = mesh_channel_hash(c.name, c.psk, c.psk_len);
            for (int i = 0; i < frames_to_test; ++i) {
                ++tried;
                if (frames[i].bytes[13] != want) continue;
                char recovered[64] = "";
                if (try_candidate(frames[i].bytes, frames[i].len, &c, recovered)) {
                    record_hit(want, &c, recovered);
                    break;
                }
            }
        }
    }

    /* Wordlist pass. Buffer all candidates first so we can parallelize
     * the trial loop the same way as simple-keys. Wordlists are typically
     * small enough (<100 MB) that holding them in memory is trivial. */
    if (wordlist_path) {
        FILE *wf = fopen(wordlist_path, "r");
        if (!wf) { perror(wordlist_path); free(frames); return 1; }

        candidate_t *cands = NULL;
        size_t n_cands = 0, cap_cands = 0;
        char line[256];
        while (fgets(line, sizeof(line), wf)) {
            size_t l = strlen(line);
            while (l && (line[l-1] == '\n' || line[l-1] == '\r' || line[l-1] == ' ')) line[--l] = 0;
            if (!l || line[0] == '#') continue;
            candidate_t c;
            if (!fill_candidate(line, &c)) continue;
            if (n_cands == cap_cands) {
                cap_cands = cap_cands ? cap_cands * 2 : 1024;
                cands = realloc(cands, cap_cands * sizeof(*cands));
                if (!cands) { perror("realloc"); fclose(wf); free(frames); return 1; }
            }
            cands[n_cands++] = c;
        }
        fclose(wf);
        cand_used += n_cands;

        #ifdef _OPENMP
        #pragma omp parallel for schedule(static) reduction(+:tried)
        #endif
        for (size_t k = 0; k < n_cands; ++k) {
            const candidate_t *c = &cands[k];
            uint8_t want = mesh_channel_hash(c->name, c->psk, c->psk_len);
            for (int i = 0; i < frames_to_test; ++i) {
                ++tried;
                if (frames[i].bytes[13] != want) continue;
                char recovered[64] = "";
                if (try_candidate(frames[i].bytes, frames[i].len, c, recovered)) {
                    record_hit(want, c, recovered);
                    break;
                }
            }
        }
        free(cands);
    }

    time_t t_end = time(NULL);
    fprintf(stderr, "recover: tested %zu candidate-frame pairs from %zu candidates in %ld s\n",
            tried, cand_used, (long)(t_end - t_start));

    /* Emit recovered keys in --keys-file= format. */
    FILE *of = out_path ? fopen(out_path, "w") : stdout;
    if (!of) { perror(out_path); free(frames); return 1; }
    for (int i = 0; i < g_n_hits; ++i) {
        fprintf(of, "%s=hex:", g_hits[i].name);
        for (size_t k = 0; k < g_hits[i].psk_len; ++k)
            fprintf(of, "%02x", g_hits[i].psk[k]);
        fprintf(of, "\n");
    }
    if (out_path) fclose(of);
    fprintf(stderr, "recover: %d key(s) recovered\n", g_n_hits);

    free(frames);
    return g_n_hits > 0 ? 0 : 1;
}
