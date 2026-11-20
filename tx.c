/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * meshtastic-sniffer: transmit path for the dashboard send box.
 * See tx.h for the request format.
 */

#define _GNU_SOURCE
#include "tx.h"
#include "options.h"

#ifdef HAVE_HACKRF
#include "hackrf.h"
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TX_RATE_HZ        2000000   /* HackRF-legal, multiple of every BW */
#define TX_GEN_TIMEOUT_MS 90000     /* python + gr-lora_sdr start-up included */
#define TX_PLAY_TIMEOUT_MS 30000
#define TX_MIN_GAP_S      3.0       /* crude duty-cycle guard between sends */
#define TX_MAX_PACKETS    4

static pthread_mutex_t g_tx_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t        g_from_node;
static pthread_once_t  g_from_once = PTHREAD_ONCE_INIT;
static double          g_last_tx;

static void respond(c2_response_t *out, int status, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out->body, sizeof(out->body), fmt, ap);
    va_end(ap);
    if (n < 0) n = 0;
    if ((size_t)n >= sizeof(out->body)) n = (int)sizeof(out->body) - 1;
    out->body_len = (size_t)n;
    out->status   = status;
}

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

/* ---- node number we transmit as (stable for the process lifetime) ---- */

static int parse_node(const char *s, uint32_t *out)
{
    if (!s || !*s) return -1;
    if (*s == '!') ++s;
    else if (!strncasecmp(s, "0x", 2)) s += 2;
    size_t n = strlen(s);
    if (n == 0 || n > 8) return -1;
    for (size_t i = 0; i < n; ++i)
        if (!isxdigit((unsigned char)s[i])) return -1;
    *out = (uint32_t)strtoul(s, NULL, 16);
    return 0;
}

static void from_node_init(void)
{
    uint32_t v = 0;
    if (opt_tx_node && parse_node(opt_tx_node, &v) == 0 && v != 0 && v != 0xFFFFFFFFu) {
        g_from_node = v;
    } else {
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            if (read(fd, &v, sizeof(v)) != (ssize_t)sizeof(v)) v = 0;
            close(fd);
        }
        if (!v) v = (uint32_t)time(NULL) * 2654435761u;
        g_from_node = 0x10000000u | (v & 0x0FFFFFFFu);  /* never 0 / broadcast */
    }
}

static uint32_t from_node(void)
{
    pthread_once(&g_from_once, from_node_init);
    return g_from_node;
}

/* ---- tool discovery ---- */

static const char *tool_path(void)
{
    static char path[PATH_MAX];
    if (opt_tx_tool) return access(opt_tx_tool, R_OK) == 0 ? opt_tx_tool : NULL;

    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        exe[n] = 0;
        char *slash = strrchr(exe, '/');
        if (slash) {
            *slash = 0;
            const char *rel[] = { "/../tools/meshtastic_tx.py", "/tools/meshtastic_tx.py" };
            for (size_t i = 0; i < sizeof(rel) / sizeof(rel[0]); ++i) {
                snprintf(path, sizeof(path), "%s%s", exe, rel[i]);
                if (access(path, R_OK) == 0) return path;
            }
        }
    }
    if (access("tools/meshtastic_tx.py", R_OK) == 0) return "tools/meshtastic_tx.py";
    return NULL;
}

static int inline_hackrf(void)
{
#ifdef HAVE_HACKRF
    return opt_sdr_backend == SDR_BACKEND_HACKRF && hackrf_tx_available();
#else
    return 0;
#endif
}

/* Clock correction for the transmitting HackRF. --tx-ppm wins; otherwise
 * the sniffer's --ppm applies only when that same HackRF is the receiver
 * (with another RX backend, --ppm describes that SDR, not the TX HackRF). */
static double tx_ppm(void)
{
    double p = opt_tx_ppm_set ? opt_tx_ppm : (inline_hackrf() ? ppm_correction : 0.0);
    return isfinite(p) ? p : 0.0;   /* strtod accepts "nan"/"inf" */
}

void tx_status_json(char *out, size_t cap)
{
    const char *tool = opt_tx_enable ? tool_path() : NULL;
    snprintf(out, cap,
        "{\"enabled\":%s,\"tool\":%s,\"mode\":\"%s\",\"region\":\"%s\","
        "\"from\":\"!%08x\",\"ppm\":%g,\"auth\":%s}",
        opt_tx_enable ? "true" : "false",
        tool ? "true" : "false",
        inline_hackrf() ? "hackrf-inline" : "hackrf_transfer",
        opt_region ? opt_region : "US",
        opt_tx_enable ? from_node() : 0,
        tx_ppm(),
        opt_api_token ? "true" : "false");
}

/* ---- form parsing ---- */

typedef struct {
    char text[256];
    char to[16];
    char channel[16];
    char psk[64];
    char preset[24];
    char long_name[48];
    char short_name[8];
    int  slot;       /* -1 = firmware hash */
    int  gain;
    int  amp;
    int  hop;
} tx_req_t;

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c = tolower(c);
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* URL-decode src[0..n) into dst (cap bytes incl. NUL). Rejects control
 * characters and over-long values. Returns 0 on success. */
static int form_decode(const char *src, size_t n, char *dst, size_t cap)
{
    size_t w = 0;
    for (size_t i = 0; i < n; ++i) {
        int c = (unsigned char)src[i];
        if (c == '+') c = ' ';
        else if (c == '%') {
            if (i + 2 >= n) return -1;
            int h = hexval((unsigned char)src[i + 1]), l = hexval((unsigned char)src[i + 2]);
            if (h < 0 || l < 0) return -1;
            c = (h << 4) | l;
            i += 2;
        }
        if (c < 0x20 || c == 0x7f) return -1;  /* no NUL / newlines / control */
        if (w + 1 >= cap) return -1;
        dst[w++] = (char)c;
    }
    dst[w] = 0;
    return 0;
}

static int only_chars(const char *s, const char *extra)
{
    for (; *s; ++s)
        if (!isalnum((unsigned char)*s) && !strchr(extra, *s)) return 0;
    return 1;
}

static int parse_int(const char *s, int lo, int hi, int *out)
{
    char *end;
    if (!*s) return -1;
    long v = strtol(s, &end, 10);
    if (*end || v < lo || v > hi) return -1;
    *out = (int)v;
    return 0;
}

static const char *parse_form(const char *body, tx_req_t *r)
{
    memset(r, 0, sizeof(*r));
    r->slot = -1; r->gain = 10; r->hop = 3;
    snprintf(r->to, sizeof(r->to), "broadcast");
    snprintf(r->psk, sizeof(r->psk), "AQ==");
    snprintf(r->preset, sizeof(r->preset), "LONG_FAST");

    const char *p = body;
    while (p && *p) {
        const char *amp = strchr(p, '&');
        size_t len = amp ? (size_t)(amp - p) : strlen(p);
        const char *eq = memchr(p, '=', len);
        if (eq) {
            char key[24], val[512];
            size_t klen = (size_t)(eq - p);
            if (form_decode(p, klen, key, sizeof(key)) != 0) return "bad field name";
            if (form_decode(eq + 1, len - klen - 1, val, sizeof(val)) != 0)
                return "field too long or contains control characters";

            if (!strcmp(key, "text")) {
                if (strlen(val) >= sizeof(r->text)) return "text too long";
                strcpy(r->text, val);
            } else if (!strcmp(key, "to")) {
                uint32_t n;
                if (!*val || !strcasecmp(val, "broadcast")) strcpy(r->to, "broadcast");
                else if (parse_node(val, &n) == 0) snprintf(r->to, sizeof(r->to), "0x%08x", n);
                else return "to: use !aabbccdd or broadcast";
            } else if (!strcmp(key, "channel")) {
                if (strlen(val) > 11) return "channel name max 11 bytes";
                if (!only_chars(val, "-_ .")) return "channel name: letters, digits, - _ . space";
                strcpy(r->channel, val);
            } else if (!strcmp(key, "psk")) {
                if (*val) {
                    if (strlen(val) >= sizeof(r->psk) || !only_chars(val, "+/=-_"))
                        return "psk: base64 (as in the app) or none";
                    strcpy(r->psk, val);
                }
            } else if (!strcmp(key, "preset")) {
                if (*val) {
                    if (strlen(val) >= sizeof(r->preset) || !only_chars(val, "_-"))
                        return "bad preset";
                    strcpy(r->preset, val);
                }
            } else if (!strcmp(key, "slot")) {
                if (*val && parse_int(val, 0, 999, &r->slot)) return "slot: 0..999";
            } else if (!strcmp(key, "gain")) {
                if (*val && parse_int(val, 0, 47, &r->gain)) return "gain: 0..47";
            } else if (!strcmp(key, "hop")) {
                if (*val && parse_int(val, 0, 7, &r->hop)) return "hop: 0..7";
            } else if (!strcmp(key, "amp")) {
                r->amp = (!strcmp(val, "1") || !strcasecmp(val, "on") || !strcasecmp(val, "true"));
            } else if (!strcmp(key, "long_name")) {
                if (strlen(val) >= sizeof(r->long_name) - 8) return "long name max 39 bytes";
                strcpy(r->long_name, val);
            } else if (!strcmp(key, "short_name")) {
                if (strlen(val) > 4) return "short name max 4 bytes";
                strcpy(r->short_name, val);
            }
        }
        p = amp ? amp + 1 : NULL;
    }
    if (!r->text[0]) return "text is required";
    return NULL;
}

/* ---- child processes ---- */

static void child_close_fds(void)
{
    long max = sysconf(_SC_OPEN_MAX);
    if (max < 0 || max > 4096) max = 4096;
    for (int fd = 3; fd < max; ++fd) close(fd);
}

/* Run argv, capture stdout into out (NUL-terminated). Returns the exit
 * status (0 = ok) or -1 on spawn failure / timeout. stderr is inherited
 * so tool diagnostics land in the sniffer's log. */
static int run_capture(char *const argv[], char *out, size_t cap, int timeout_ms)
{
    int pfd[2];
    if (pipe(pfd) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) dup2(devnull, 0);
        dup2(pfd[1], 1);
        child_close_fds();
        signal(SIGPIPE, SIG_DFL);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pfd[1]);

    size_t used = 0;
    if (out && cap) out[0] = 0;
    double deadline = now_s() + timeout_ms / 1000.0;
    int timed_out = 0;
    for (;;) {
        int left = (int)((deadline - now_s()) * 1000.0);
        if (left <= 0) { timed_out = 1; break; }
        struct pollfd pf = { .fd = pfd[0], .events = POLLIN };
        int pr = poll(&pf, 1, left);
        if (pr < 0) { if (errno == EINTR) continue; break; }
        if (pr == 0) { timed_out = 1; break; }
        char tmp[1024];
        ssize_t n = read(pfd[0], tmp, sizeof(tmp));
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (n == 0) break;
        if (out && used + 1 < cap) {
            size_t k = (size_t)n < cap - 1 - used ? (size_t)n : cap - 1 - used;
            memcpy(out + used, tmp, k);
            used += k;
            out[used] = 0;
        }
    }
    close(pfd[0]);
    if (timed_out) kill(pid, SIGKILL);

    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    if (timed_out) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void rm_tree_flat(const char *dir)
{
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *e;
        char p[PATH_MAX];
        while ((e = readdir(d))) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(dir);
}

/* ---- tiny JSON field extractors for the tool's one-line records ---- */

static int json_str(const char *line, const char *key, char *out, size_t cap)
{
    char pat[32];
    snprintf(pat, sizeof(pat), "\"%s\": \"", key);
    const char *p = strstr(line, pat);
    if (!p) return -1;
    p += strlen(pat);
    size_t w = 0;
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) ++p;
        if (w + 1 >= cap) return -1;
        out[w++] = *p++;
    }
    out[w] = 0;
    return *p == '"' ? 0 : -1;
}

static int json_u64(const char *line, const char *key, uint64_t *out)
{
    char pat[32];
    snprintf(pat, sizeof(pat), "\"%s\": ", key);
    const char *p = strstr(line, pat);
    if (!p) return -1;
    p += strlen(pat);
    if (!isdigit((unsigned char)*p)) return -1;
    *out = strtoull(p, NULL, 10);
    return 0;
}

typedef struct {
    char     label[16];
    char     s8[PATH_MAX];
    uint64_t freq, lo_freq, rate, id, airtime_ms;
} tx_pkt_t;

#ifdef HAVE_HACKRF
static int read_file(const char *path, int8_t **buf, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz <= 0 || sz > 256L * 1024 * 1024) { fclose(f); return -1; }
    rewind(f);
    *buf = malloc((size_t)sz);
    if (!*buf) { fclose(f); return -1; }
    if (fread(*buf, 1, (size_t)sz, f) != (size_t)sz) { free(*buf); fclose(f); return -1; }
    fclose(f);
    *n = (size_t)sz;
    return 0;
}
#endif

static int play_packet(const tx_pkt_t *pk, const tx_req_t *rq, char *err, size_t errlen)
{
#ifdef HAVE_HACKRF
    if (inline_hackrf()) {
        int8_t *iq = NULL;
        size_t n = 0;
        if (read_file(pk->s8, &iq, &n) != 0) {
            snprintf(err, errlen, "cannot read generated IQ");
            return -1;
        }
        int rc = hackrf_tx_play(iq, n, pk->lo_freq, (uint32_t)pk->rate,
                                rq->gain, rq->amp, err, errlen);
        free(iq);
        return rc;
    }
#endif
    char f[32], s[32], x[16];
    snprintf(f, sizeof(f), "%llu", (unsigned long long)pk->lo_freq);
    snprintf(s, sizeof(s), "%llu", (unsigned long long)pk->rate);
    snprintf(x, sizeof(x), "%d", rq->gain);
    char *argv[] = { "hackrf_transfer", "-t", (char *)pk->s8, "-f", f, "-s", s,
                     "-x", x, "-a", rq->amp ? "1" : "0", NULL };
    int rc = run_capture(argv, NULL, 0, TX_PLAY_TIMEOUT_MS);
    if (rc != 0) {
        snprintf(err, errlen, rc == 127 ? "hackrf_transfer not found"
                                        : "hackrf_transfer failed (HackRF busy or missing?)");
        return -1;
    }
    return 0;
}

/* ---- POST /api/tx ---- */

void tx_send(const char *body, c2_response_t *out)
{
    if (!opt_tx_enable) {
        respond(out, 403, "{\"error\":\"TX disabled; start the sniffer with --tx\"}");
        return;
    }
    if (!body) {
        respond(out, 400, "{\"error\":\"no body\"}");
        return;
    }
    tx_req_t rq;
    const char *perr = parse_form(body, &rq);
    if (perr) {
        respond(out, 400, "{\"error\":\"%s\"}", perr);
        return;
    }
    const char *tool = tool_path();
    if (!tool) {
        respond(out, 500, "{\"error\":\"tools/meshtastic_tx.py not found; pass --tx-tool=PATH\"}");
        return;
    }
    if (pthread_mutex_trylock(&g_tx_lock) != 0) {
        respond(out, 409, "{\"error\":\"a transmission is already in progress\"}");
        return;
    }
    if (g_last_tx > 0 && now_s() - g_last_tx < TX_MIN_GAP_S) {
        pthread_mutex_unlock(&g_tx_lock);
        respond(out, 429, "{\"error\":\"wait a few seconds between sends\"}");
        return;
    }

    char workdir[] = "/tmp/meshtx_XXXXXX";
    if (!mkdtemp(workdir)) {
        pthread_mutex_unlock(&g_tx_lock);
        respond(out, 500, "{\"error\":\"mkdtemp failed\"}");
        return;
    }

    /* Every user string goes in as --flag=value: no shell, and a value
     * starting with '-' can't be taken for an option. */
    char a_keep[PATH_MAX + 8], a_rate[32], a_region[48], a_preset[40], a_psk[80],
         a_to[32], a_from[32], a_hop[24], a_gain[24], a_text[280], a_chan[32],
         a_slot[24], a_long[64], a_short[24], a_ppm[40];
    snprintf(a_keep,   sizeof(a_keep),   "--keep=%s", workdir);
    snprintf(a_rate,   sizeof(a_rate),   "--rate=%d", TX_RATE_HZ);
    snprintf(a_region, sizeof(a_region), "--region=%s", opt_region ? opt_region : "US");
    snprintf(a_preset, sizeof(a_preset), "--preset=%s", rq.preset);
    snprintf(a_psk,    sizeof(a_psk),    "--psk=%s", rq.psk);
    snprintf(a_to,     sizeof(a_to),     "--to=%s", rq.to);
    snprintf(a_from,   sizeof(a_from),   "--from-node=0x%08x", from_node());
    snprintf(a_hop,    sizeof(a_hop),    "--hop-limit=%d", rq.hop);
    snprintf(a_gain,   sizeof(a_gain),   "--tx-gain=%d", rq.gain);
    snprintf(a_text,   sizeof(a_text),   "--text=%s", rq.text);

    char *argv[24];
    int ac = 0;
    argv[ac++] = "python3";
    argv[ac++] = (char *)tool;
    argv[ac++] = "--emit-json";
    argv[ac++] = "--dry-run";
    argv[ac++] = a_keep;
    argv[ac++] = a_rate;
    argv[ac++] = a_region;
    argv[ac++] = a_preset;
    argv[ac++] = a_psk;
    argv[ac++] = a_to;
    argv[ac++] = a_from;
    argv[ac++] = a_hop;
    argv[ac++] = a_gain;
    argv[ac++] = a_text;
    if (rq.channel[0]) {
        snprintf(a_chan, sizeof(a_chan), "--channel=%s", rq.channel);
        argv[ac++] = a_chan;
    }
    if (rq.slot >= 0) {
        snprintf(a_slot, sizeof(a_slot), "--slot=%d", rq.slot);
        argv[ac++] = a_slot;
    }
    double ppm = tx_ppm();
    if (ppm != 0.0) {
        snprintf(a_ppm, sizeof(a_ppm), "--ppm=%.6g", ppm);
        argv[ac++] = a_ppm;
    }
    if (rq.long_name[0]) {
        snprintf(a_long, sizeof(a_long), "--long-name=%s", rq.long_name);
        argv[ac++] = a_long;
        if (rq.short_name[0]) {
            snprintf(a_short, sizeof(a_short), "--short-name=%s", rq.short_name);
            argv[ac++] = a_short;
        }
    }
    argv[ac] = NULL;

    char gen_out[8192];
    int rc = run_capture(argv, gen_out, sizeof(gen_out), TX_GEN_TIMEOUT_MS);
    if (rc != 0) {
        rm_tree_flat(workdir);
        pthread_mutex_unlock(&g_tx_lock);
        respond(out, 500, "{\"error\":\"%s\"}",
                rc == 127 ? "python3 not found"
                          : "packet generation failed (see the sniffer's stderr)");
        return;
    }

    tx_pkt_t pk[TX_MAX_PACKETS];
    int npk = 0;
    for (char *save = NULL, *line = strtok_r(gen_out, "\n", &save);
         line && npk < TX_MAX_PACKETS; line = strtok_r(NULL, "\n", &save)) {
        if (strncmp(line, "{\"tx\": ", 7) != 0) continue;
        tx_pkt_t *p = &pk[npk];
        memset(p, 0, sizeof(*p));
        if (json_str(line, "tx", p->label, sizeof(p->label)) ||
            json_str(line, "s8", p->s8, sizeof(p->s8)) ||
            json_u64(line, "freq", &p->freq) ||
            json_u64(line, "lo_freq", &p->lo_freq) ||
            json_u64(line, "rate", &p->rate) ||
            json_u64(line, "id", &p->id))
            continue;
        json_u64(line, "airtime_ms", &p->airtime_ms);
        /* Only play files from our own scratch directory. */
        if (strncmp(p->s8, workdir, strlen(workdir)) != 0 || strstr(p->s8, ".."))
            continue;
        ++npk;
    }
    if (npk == 0) {
        rm_tree_flat(workdir);
        pthread_mutex_unlock(&g_tx_lock);
        respond(out, 500, "{\"error\":\"generator produced no packets\"}");
        return;
    }

    char err[160] = "";
    int sent = 0;
    uint64_t text_id = 0, airtime = 0;
    for (int i = 0; i < npk; ++i) {
        if (i > 0) sleep(1);  /* NodeInfo first, then the text */
        if (play_packet(&pk[i], &rq, err, sizeof(err)) != 0) break;
        ++sent;
        airtime += pk[i].airtime_ms;
        if (!strcmp(pk[i].label, "text")) text_id = pk[i].id;
    }
    g_last_tx = now_s();
    rm_tree_flat(workdir);
    pthread_mutex_unlock(&g_tx_lock);

    if (sent < npk) {
        /* err never contains quotes: it's built from libhackrf names + literals. */
        respond(out, 500, "{\"error\":\"%s\",\"sent\":%d}", err[0] ? err : "transmit failed", sent);
        return;
    }
    fprintf(stderr, "[tx] sent %d packet(s) as !%08x on %.6f MHz (id 0x%08llx)\n",
            sent, from_node(), pk[0].freq / 1e6, (unsigned long long)text_id);
    respond(out, 200,
        "{\"ok\":true,\"from\":\"!%08x\",\"freq_mhz\":%.6f,\"packets\":%d,"
        "\"id\":\"%08llx\",\"airtime_ms\":%llu}",
        from_node(), pk[0].freq / 1e6, sent,
        (unsigned long long)text_id, (unsigned long long)airtime);
}
