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

#include "tx.c"
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
                          "text=a%2", "text=a&slot=-1" };
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
