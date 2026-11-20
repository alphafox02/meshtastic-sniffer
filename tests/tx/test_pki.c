/* pki.c against Meshtastic firmware's own crypto test vectors
 * (firmware test/test_crypto/test_main.cpp: test_DH25519, test_PKC), plus
 * key files, base64, the peer cache and the mesh_packet decrypt hook. */
#define _GNU_SOURCE
#include "pki.h"
#include "mesh_packet.h"
#include "keyset.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   "); else { printf("FAIL "); ++fails; } \
                           printf(__VA_ARGS__); printf("\n"); } while (0)

static void unhex(const char *h, uint8_t *out)
{
    for (size_t i = 0; h[2 * i]; ++i) sscanf(h + 2 * i, "%2hhx", &out[i]);
}

static mesh_event_t g_ev;
static uint8_t g_payload[256];
static int g_events;
static void cb(const mesh_event_t *ev, void *u)
{
    (void)u;
    g_ev = *ev;
    memcpy(g_payload, ev->payload, ev->payload_len < sizeof(g_payload) ? ev->payload_len : sizeof(g_payload));
    ++g_events;
}

int main(void)
{
    uint8_t priv[32], pub[32], shared[32], want[32];

    /* --- X25519 + SHA-256: firmware test_DH25519 (Wycheproof) --- */
    unhex("10300724f3bea134eb1575245ef26ff9b8ccd59849cd98ce1a59002fe1d5986c", priv);
    unhex("f7e13a1a067d2f4e1061bf9936fde5be6b0c2494a8f809cbac7f290ef719e91c", pub);
    unhex("24becd5dfed9e9289ba2e15b82b0d54f8e9aacb72f5e4248c58d8d74b451ce76", want);
    CHECK(pki_shared_key(priv, pub, shared) == 0 && !memcmp(shared, want, 32),
          "shared key = SHA-256(X25519) matches firmware test_DH25519 vector 4");
    unhex("18630f93598637c35da623a74559cf944374a559114c7937811041fc8605564a", priv);
    unhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", pub);
    CHECK(pki_shared_key(priv, pub, shared) != 0, "weak public key rejected (vector 3)");

    /* --- firmware test_PKC: decrypt a real radio packet --- */
    uint8_t radio[38];
    unhex("8c646d7a2909000062d6b2136b00000040df24abfcc30a17a3d9046726099e796a1c036a792b", radio);
    unhex("a00330633e63522f8a4d81ec6d9d1e6617f6c8ffd3a4c698229537d44e522277", priv);
    unhex("db18fc50eea47f00251cb784819a3cf5fc361882597f589f0d7ff820e8064457", pub);
    uint8_t plain[64], expect[10];
    unhex("08011204746573744800", expect);
    CHECK(pki_shared_key(priv, pub, shared) == 0 && shared[0] == 0x77 && shared[7] == 0xa2,
          "test_PKC shared key starts 777b1545c9d6f9a2");
    int n = pki_decrypt_body(shared, 0x0929, 0x13b2d662, radio + 16, 22, plain, sizeof(plain));
    CHECK(n == 10 && !memcmp(plain, expect, 10), "test_PKC packet decrypts to Data{TEXT, \"test\"} (n=%d)", n);
    radio[20] ^= 1;
    CHECK(pki_decrypt_body(shared, 0x0929, 0x13b2d662, radio + 16, 22, plain, sizeof(plain)) < 0,
          "flipped ciphertext bit -> tag check fails");
    radio[20] ^= 1;
    CHECK(pki_decrypt_body(shared, 0x092a, 0x13b2d662, radio + 16, 22, plain, sizeof(plain)) < 0,
          "wrong sender (nonce) -> tag check fails");

    /* re-encrypting with the packet's extra nonce reproduces the radio bytes */
    uint8_t body[64];
    n = pki_encrypt_body(shared, 0x0929, 0x13b2d662, 0x2b796a03, expect, 10, body, sizeof(body));
    CHECK(n == 22 && !memcmp(body, radio + 16, 22), "encrypt reproduces the firmware's bytes exactly");

    /* --- key file: created 0600, then loaded back --- */
    char dir[] = "/tmp/pkitest_XXXXXX", path[64];
    if (!mkdtemp(dir)) return 2;
    snprintf(path, sizeof(path), "%s/tx_key", dir);
    CHECK(pki_init(path) == 0 && pki_enabled(), "pki_init creates a key file");
    struct stat st;
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600, "key file mode 0600 (%o)", st.st_mode & 0777);
    uint8_t pub1[32], pub2[32];
    pki_public_key(pub1);
    CHECK(pki_init(path) == 0, "pki_init loads the existing key file");
    pki_public_key(pub2);
    CHECK(!memcmp(pub1, pub2, 32), "same identity after reload");
    FILE *f = fopen(path, "w");
    fputs("not a key\n", f);
    fclose(f);
    CHECK(pki_init(path) != 0, "garbage key file rejected");
    unlink(path);

    /* --- base64 / hex parsing --- */
    char b64[45];
    pki_b64_encode(pub1, b64);
    uint8_t back[32];
    CHECK(strlen(b64) == 44 && pki_key_decode(b64, back) == 0 && !memcmp(back, pub1, 32), "base64 round trip");
    b64[43] = 0;  /* no padding */
    CHECK(pki_key_decode(b64, back) == 0 && !memcmp(back, pub1, 32), "base64 without padding");
    CHECK(pki_key_decode("db18fc50eea47f00251cb784819a3cf5fc361882597f589f0d7ff820e8064457", back) == 0 &&
          back[0] == 0xdb && back[31] == 0x57, "64 hex digits accepted");
    CHECK(pki_key_decode("AQ==", back) != 0 && pki_key_decode("", back) != 0, "short keys rejected");

    /* --- end to end: firmware's test_PKC radio packet through mesh_packet --- */
    char kpath[64];
    snprintf(kpath, sizeof(kpath), "%s/fw_key", dir);
    f = fopen(kpath, "w");
    unhex("a00330633e63522f8a4d81ec6d9d1e6617f6c8ffd3a4c698229537d44e522277", priv);
    pki_b64_encode(priv, b64);
    fprintf(f, "%s\n", b64);
    fclose(f);
    CHECK(pki_init(kpath) == 0, "load the firmware test's private key");
    pki_set_own_node(0x7a6d648c);  /* the packet's "to" */
    mesh_packet_set_pki_decrypt(pki_mesh_hook);
    keyset_t *ks = keyset_create();
    keyset_parse_csv(ks, "default");
    g_events = 0;
    mesh_packet_decode(radio, sizeof(radio), ks, cb, NULL);
    CHECK(g_events == 1 && !g_ev.decrypted, "unknown sender key -> stays encrypted");
    pki_note_peer(0x0929, pub);
    g_events = 0;
    mesh_packet_decode(radio, sizeof(radio), ks, cb, NULL);
    CHECK(g_events == 1 && g_ev.decrypted && g_ev.pki_encrypted && g_ev.portnum == 1 &&
          g_ev.payload_len == 4 && !memcmp(g_payload, "test", 4) && !strcmp(g_ev.channel_name, "PKI"),
          "known sender key -> decoded as PKI text \"test\"");
    pki_set_own_node(0x11111111);
    g_events = 0;
    mesh_packet_decode(radio, sizeof(radio), ks, cb, NULL);
    CHECK(g_events == 1 && !g_ev.decrypted, "packet to another node -> not decrypted");
    keyset_destroy(ks);
    unlink(kpath);
    rmdir(dir);

    /* --- peer cache --- */
    uint8_t k[32];
    memset(k, 0, 32);
    pki_note_peer(0x1234, k);
    CHECK(!pki_peer_key(0x1234, k), "all-zero key ignored");
    for (uint32_t i = 1; i <= 1100; ++i) {
        memset(k, (int)(i & 0xff) | 1, 32);
        pki_note_peer(0x40000000u + i, k);
    }
    CHECK(pki_peer_key(0x40000000u + 1100, k) && k[0] == ((1100 & 0xff) | 1),
          "cache keeps the newest peers when full");

    printf("FAILS: %d\n", fails);
    return fails ? 1 : 0;
}
