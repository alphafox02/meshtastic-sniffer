/* End-to-end test of tx.c (POST /api/tx handler) with a stubbed tool and
 * a fake hackrf_transfer (or, with -DHAVE_HACKRF, a stubbed in-process
 * hackrf_tx_play). */
#define _GNU_SOURCE
#include "options.h"

bool          opt_tx_enable;
char         *opt_tx_tool;
char         *opt_tx_node;
char         *opt_region;
char         *opt_api_token;
sdr_backend_t opt_sdr_backend;
double        ppm_correction;
double        opt_tx_ppm;
bool          opt_tx_ppm_set;
char         *opt_tx_region;
char         *opt_tx_key;

#include "tx.c"
#include "pki.h"
#include "keyset.h"
#include "share_url.h"

/* c2.c is linked in as its own object so c2_dispatch("tx_send") is tested
 * for real; these stub the rest of what it references. */
keyset_t *app_get_keyset(void) { return NULL; }
int app_add_runtime_extra_freq(uint64_t f, int bw, int sf, int cr)
{ (void)f; (void)bw; (void)sf; (void)cr; return -1; }
int keyset_parse_csv(keyset_t *k, const char *csv) { (void)k; (void)csv; return 0; }
int decode_channel_share(keyset_t *ks, const char *u) { (void)ks; (void)u; return 0; }
int cot_set_endpoint(const char *host, int port) { (void)host; (void)port; return 0; }

#include <glob.h>

#ifdef HAVE_HACKRF
static int      play_calls;
static size_t   play_n;
static uint64_t play_f;
static uint32_t play_rate;
static int      play_gain, play_amp;
int hackrf_tx_available(void) { return 1; }
int hackrf_tx_play(const int8_t *iq, size_t n, uint64_t f, uint32_t rate, int gain,
                   int amp, char *err, size_t errlen)
{
    (void)err; (void)errlen;
    ++play_calls; play_n = n; play_f = f; play_rate = rate; play_gain = gain; play_amp = amp;
    return (iq[0] == 1 && iq[1] == 2) ? 0 : -1;  /* matches the dummy IQ pattern */
}
#endif

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   "); else { printf("FAIL "); ++fails; } \
                           printf(__VA_ARGS__); printf("\n"); } while (0)

static c2_response_t send(const char *body)
{
    c2_response_t r;
    memset(&r, 0, sizeof(r));
    g_last_tx = 0;  /* bypass the duty-cycle gap except where tested */
    tx_send(body, &r);
    return r;
}

static int count_lines(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int n = 0, c;
    while ((c = fgetc(f)) != EOF) if (c == '\n') ++n;
    fclose(f);
    return n;
}

static int file_has(const char *path, const char *needle)
{
    char buf[65536];
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = 0;
    fclose(f);
    return strstr(buf, needle) != NULL;
}

static int leftover_workdirs(void)
{
    glob_t g;
    int n = glob("/tmp/meshtx_*", 0, NULL, &g) == 0 ? (int)g.gl_pathc : 0;
    globfree(&g);
    return n;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    const char *tool_log = getenv("FAKE_LOG"), *ht_log = getenv("HT_LOG");
    unlink(tool_log); unlink(ht_log);
    int workdirs_before = leftover_workdirs();

    c2_response_t r = send("text=hi");
    CHECK(r.status == 403, "disabled without --tx -> 403 (%d %s)", r.status, r.body);

    opt_tx_enable = true;
    opt_tx_node = "!12345678";
    opt_tx_tool = "/nonexistent/meshtastic_tx.py";
    r = send("text=hi");
    CHECK(r.status == 500 && strstr(r.body, "not found"), "missing tool -> 500 (%s)", r.body);
    opt_tx_tool = argv[1];

    char st[256];
    tx_status_json(st, sizeof(st));
    CHECK(strstr(st, "\"enabled\":true") && strstr(st, "\"tool\":true") &&
          strstr(st, "\"from\":\"!12345678\"") && strstr(st, "\"region\":\"US\""),
          "status json: %s", st);

    /* --- validation --- */
    const char *bad[] = { "", "to=!aabbccdd", "text=a&gain=99", "text=a%0Ab",
                          "text=a&to=zz", "text=a&channel=waytoolongname",
                          "text=a&psk=%27%3B", "text=a&hop=8", "text=a&short_name=TOOLONG",
                          "text=a%2", "text=a&slot=-1",
                          "kind=position", "kind=position&to=broadcast", "kind=bogus&text=a",
                          "kind=traceroute&to=!aabbccdd&text=a",
                          "kind=nodeinfo&to=!aabbccdd&reply_id=1234",
                          "text=a&reply_id=xyz", "text=a&reply_id=0", "text=a&reply_id=123456789" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        r = send(bad[i]);
        CHECK(r.status == 400, "reject '%s' -> 400 (%s)", bad[i], r.body);
    }
    CHECK(count_lines(tool_log) == 0, "tool never ran for rejected requests");

    /* --- full send with NodeInfo, via hackrf_transfer (or inline) --- */
#ifdef HAVE_HACKRF
    opt_sdr_backend = SDR_BACKEND_HACKRF;
#endif
    r = send("text=hello+mesh&long_name=Sniffer%20TX&short_name=STX&gain=12&amp=1"
             "&channel=LongFast&psk=AQ%3D%3D");
    CHECK(r.status == 200 && strstr(r.body, "\"packets\":2") &&
          strstr(r.body, "\"from\":\"!12345678\"") && strstr(r.body, "906.875000"),
          "send text+nodeinfo -> 200 (%s)", r.body);
    CHECK(file_has(tool_log, "\"--text=hello mesh\"") &&
          file_has(tool_log, "\"--from-node=0x12345678\"") &&
          file_has(tool_log, "\"--long-name=Sniffer TX\"") &&
          file_has(tool_log, "\"--short-name=STX\"") &&
          file_has(tool_log, "\"--emit-json\"") && file_has(tool_log, "\"--dry-run\""),
          "tool got the expected argv");
#ifdef HAVE_HACKRF
    CHECK(play_calls == 2 && play_n == 40000 && play_f == 906375000 &&
          play_rate == 2000000 && play_gain == 12 && play_amp == 1,
          "inline hackrf_tx_play x%d n=%zu f=%llu rate=%u gain=%d amp=%d", play_calls,
          play_n, (unsigned long long)play_f, play_rate, play_gain, play_amp);
    CHECK(count_lines(ht_log) == 0, "hackrf_transfer not used in inline mode");
#else
    CHECK(count_lines(ht_log) == 2 && file_has(ht_log, "-f 906375000 -s 2000000 -x 12 -a 1"),
          "hackrf_transfer called twice with LO=906.375 MHz, 2 Msps, gain 12, amp on");
#endif
    CHECK(leftover_workdirs() == workdirs_before, "scratch dir removed after send");

    /* --- duty-cycle guard --- */
    c2_response_t r2;
    memset(&r2, 0, sizeof(r2));
    tx_send("text=again", &r2);  /* no g_last_tx reset */
    CHECK(r2.status == 429, "immediate resend -> 429 (%s)", r2.body);

    /* --- option-looking text and DM --- */
    r = send("text=-x+%26+rm+-rf+%2F+%24(id)&to=!aabbccdd&preset=MEDIUM_FAST");
    CHECK(r.status == 200 && strstr(r.body, "\"packets\":1") && strstr(r.body, "913.125000"),
          "option-looking text, DM, MediumFast -> 200 (%s)", r.body);
    CHECK(file_has(tool_log, "\"--text=-x & rm -rf / $(id)\"") &&
          file_has(tool_log, "\"--to=0xaabbccdd\""), "text passed verbatim as one argv element");

    /* --- node requests, replies, ACK --- */
    static const struct { const char *kind; const char *mhz; } reqs[] = {
        { "position", "906.875000" }, { "nodeinfo", "906.875000" },
        { "telemetry", "906.875000" }, { "traceroute", "906.875000" },
    };
    for (size_t i = 0; i < sizeof(reqs) / sizeof(reqs[0]); ++i) {
        char body[96], kexp[64], kjson[48];
        snprintf(body, sizeof(body), "kind=%s&to=%%21AABBCCDD&ack=1", reqs[i].kind);
        snprintf(kexp, sizeof(kexp), "\"--kind=%s\"", reqs[i].kind);
        snprintf(kjson, sizeof(kjson), "\"kind\":\"%s\"", reqs[i].kind);
        r = send(body);
        CHECK(r.status == 200 && strstr(r.body, "\"packets\":1") && strstr(r.body, kjson) &&
              strstr(r.body, "\"to\":\"!aabbccdd\"") && strstr(r.body, reqs[i].mhz) &&
              !strstr(r.body, "\"id\":\"00000000\""),
              "%s request -> 200 with its own id (%s)", reqs[i].kind, r.body);
        CHECK(file_has(tool_log, kexp) && file_has(tool_log, "\"--want-ack\""),
              "tool got %s + --want-ack", kexp);
    }
    r = send("text=thanks&reply_id=1a2b3c4d");
    CHECK(r.status == 200 && strstr(r.body, "\"kind\":\"text\"") && strstr(r.body, "\"to\":\"broadcast\"") &&
          file_has(tool_log, "\"--reply-id=0x1a2b3c4d\"") && file_has(tool_log, "\"--text=thanks\""),
          "text reply -> --reply-id (%s)", r.body);

    /* --- public-key DMs --- */
    CHECK(tx_init() == 0 && pki_enabled() && pki_own_node() == 0x12345678, "tx_init: PKI identity for !12345678");
    tx_status_json(st, sizeof(st));
    CHECK(strstr(st, "\"public_key\":\"") && !strstr(st, "\"public_key\":\"\""), "status json has our public key");
    r = send("text=no+key+yet&to=!aabbccdd");
    CHECK(r.status == 200 && strstr(r.body, "\"pki\":false") && strstr(r.body, "\"warning\":"),
          "DM without a known key -> channel key + warning (%s)", r.body);
    CHECK(file_has(tool_log, "\"--pki-key-file=/tmp/meshtx_") && !file_has(tool_log, "--dest-pubkey"),
          "tool gets our key file but no --dest-pubkey");
    /* the node's key, as the Meshtastic app shows it */
    r = send("text=secret&to=!aabbccdd&pubkey=2xj8UO6kfwAlHLeEgZo89fw2GIJZf1ifDX%2F4IOgGRFc%3D");
    CHECK(r.status == 200 && strstr(r.body, "\"pki\":true") && strstr(r.body, "\"packets\":2") &&
          !strstr(r.body, "warning"), "first PKI DM -> NodeInfo to the node + DM (%s)", r.body);
    CHECK(file_has(tool_log, "\"--dest-pubkey=2xj8UO6kfwAlHLeEgZo89fw2GIJZf1ifDX/4IOgGRFc=\"") &&
          file_has(tool_log, "\"--announce-dest\""), "tool got --dest-pubkey + --announce-dest");
    unlink(tool_log);
    r = send("text=again&to=!aabbccdd");
    CHECK(r.status == 200 && strstr(r.body, "\"pki\":true") && strstr(r.body, "\"packets\":1") &&
          file_has(tool_log, "--dest-pubkey") && !file_has(tool_log, "--announce-dest"),
          "later DMs: key remembered, no second announcement (%s)", r.body);
    r = send("kind=telemetry&to=!aabbccdd");
    CHECK(r.status == 200 && strstr(r.body, "\"pki\":true"), "telemetry request is PKI too (%s)", r.body);
    r = send("kind=nodeinfo&to=!11223344");
    unlink(tool_log);
    r = send("text=after+exchange&to=!11223344&pubkey=2xj8UO6kfwAlHLeEgZo89fw2GIJZf1ifDX%2F4IOgGRFc%3D");
    CHECK(r.status == 200 && strstr(r.body, "\"pki\":true") && strstr(r.body, "\"packets\":1") &&
          !file_has(tool_log, "--announce-dest"),
          "node info exchange counts as announcing our key (%s)", r.body);
    r = send("kind=traceroute&to=!aabbccdd");
    CHECK(r.status == 200 && strstr(r.body, "\"pki\":false"),
          "traceroute never PKI, like the firmware (%s)", r.body);
    r = send("text=x&to=!aabbccdd&pubkey=AQ%3D%3D");
    CHECK(r.status == 400, "bad pubkey -> 400 (%s)", r.body);
    r = send("text=x&pubkey=2xj8UO6kfwAlHLeEgZo89fw2GIJZf1ifDX%2F4IOgGRFc%3D");
    CHECK(r.status == 400, "pubkey without a destination -> 400 (%s)", r.body);
    /* our private key never on the command line */
    char b64[45]; uint8_t priv[32];
    pki_private_key(priv); pki_b64_encode(priv, b64);
    CHECK(!file_has(tool_log, b64), "private key not in any argv");

    /* --- --tx-region: transmit in another band than RX --- */
    opt_region = "US";
    opt_tx_region = "EU_868";
    tx_status_json(st, sizeof(st));
    CHECK(strstr(st, "\"region\":\"EU_868\"") && strstr(st, "\"rx_region\":\"US\""),
          "status json reports TX and RX regions (%s)", st);
    r = send("text=eu&preset=MEDIUM_FAST");
    CHECK(r.status == 200 && strstr(r.body, "869.525000") && file_has(tool_log, "\"--region=EU_868\""),
          "--tx-region=EU_868 -> 869.525 MHz (%s)", r.body);
    opt_tx_region = NULL;
    opt_region = "eu868";   /* alias: the tool gets the canonical name */
    r = send("text=alias&preset=MEDIUM_FAST");
    CHECK(r.status == 200 && strstr(r.body, "869.525000") && file_has(tool_log, "\"--region=EU_868\""),
          "--region alias canonicalised for the tool (%s)", r.body);
    opt_region = NULL;

    /* --- clock correction --- */
    opt_tx_ppm = 10.0; opt_tx_ppm_set = true;
    r = send("text=ppm");
    tx_status_json(st, sizeof(st));
    CHECK(r.status == 200 && file_has(tool_log, "\"--ppm=10\"") && strstr(st, "\"ppm\":10"),
          "--tx-ppm=10 reaches the tool and the status json (%s)", st);
#ifdef HAVE_HACKRF
    CHECK(play_f == 906365936, "inline LO corrected by 10 ppm (f=%llu)",
          (unsigned long long)play_f);
#else
    CHECK(file_has(ht_log, "-f 906365936 "), "hackrf_transfer LO corrected by 10 ppm");
#endif
    opt_tx_ppm_set = false; ppm_correction = -3.5;
    tx_status_json(st, sizeof(st));
#ifdef HAVE_HACKRF
    CHECK(strstr(st, "\"ppm\":-3.5") != NULL, "inline: --ppm inherited (%s)", st);
#else
    CHECK(strstr(st, "\"ppm\":0") != NULL, "other RX backend: --ppm not applied to TX (%s)", st);
#endif
    ppm_correction = 0;

    /* --- C2 transport --- */
    g_last_tx = 0;
    c2_response_t rc2;
    memset(&rc2, 0, sizeof(rc2));
    c2_dispatch("tx_send", "text=via+c2", &rc2);
    CHECK(rc2.status == 200 && strstr(rc2.body, "\"packets\":1") &&
          file_has(tool_log, "\"--text=via c2\""), "c2_dispatch tx_send -> 200 (%s)", rc2.body);
    g_last_tx = 0;
    opt_tx_enable = false;
    memset(&rc2, 0, sizeof(rc2));
    c2_dispatch("tx_send", "text=x", &rc2);
    CHECK(rc2.status == 403, "c2 tx_send without --tx -> 403 (%s)", rc2.body);
    opt_tx_enable = true;

    /* --- failures --- */
    setenv("FAKE_MODE", "fail", 1);
    r = send("text=x");
    CHECK(r.status == 500 && strstr(r.body, "generation failed"), "tool failure -> 500 (%s)", r.body);
    setenv("FAKE_MODE", "outside", 1);
    r = send("text=x");
    CHECK(r.status == 500 && strstr(r.body, "no packets"),
          "s8 outside scratch dir ignored (%s)", r.body);
    unsetenv("FAKE_MODE");
#ifndef HAVE_HACKRF
    setenv("HT_RC", "1", 1);
    r = send("text=x");
    CHECK(r.status == 500 && strstr(r.body, "hackrf_transfer failed"),
          "hackrf_transfer failure -> 500 (%s)", r.body);
    unsetenv("HT_RC");
#endif
    CHECK(leftover_workdirs() == workdirs_before, "no scratch dirs leaked after failures");

    printf("FAILS: %d\n", fails);
    return fails ? 1 : 0;
}
