/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: CLI option parsing and shared runtime state.
 *
 */

#include "options.h"
#include "sdr.h"

#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ---- Shared runtime state ---- */
volatile sig_atomic_t running = 1;
double  samp_rate       = 0.0;
double  center_freq     = 0.0;
int     bias_tee        = 0;
double  ppm_correction  = 0.0;

/* ---- Top-level user input ---- */
sdr_backend_t opt_sdr_backend         = SDR_BACKEND_NONE;
char         *opt_sdr_serial          = NULL;
uint64_t      opt_center_freq_hz      = 0;
uint32_t      opt_sample_rate         = 0;
int           opt_clock_src           = CLOCK_SRC_INTERNAL;
int           verbose                 = 0;
bool          opt_force_simd_generic  = false;
op_mode_t     opt_op_mode             = OP_MODE_DECODE;
bool          opt_alert_off_grid      = false;
bool          opt_list_devices        = false;
bool          opt_print_schema        = false;
bool          opt_trusted_only        = false;
bool          opt_show_untrusted      = false;
bool          opt_diagnostics         = false;
deep_decode_mode_t opt_deep_decode    = DEEP_DECODE_AUTO;
int           opt_focus_workers       = 2;
double        opt_focus_hold_s        = 5.0;
int           opt_focus_rewind_ms     = 20;
int           opt_focus_ring_ms       = 500;
char         *opt_focus_freqs_csv     = NULL;
double        opt_focus_min_snr_db    = 6.0;
int           opt_focus_os            = 0;    /* 0 = auto policy */

char         *opt_snapshot_store_dir     = NULL;
int           opt_snapshot_window_pre_ms = 50;
int           opt_snapshot_window_post_ms= 100;
long long     opt_snapshot_disk_mb       = 2048;     /* 2 GiB cap */
long long     opt_snapshot_age_s         = 86400;    /* 24 h */
double        opt_snapshot_min_snr_db    = -1.0;     /* <0: inherit focus floor */

char         *opt_region              = NULL;
char         *opt_preset_csv          = NULL;
char         *opt_keys_csv            = NULL;
char         *opt_keys_file           = NULL;
char         *opt_share_url           = NULL;
char         *opt_iq_record           = NULL;
char         *opt_stats_json          = NULL;
char         *opt_fftw_wisdom         = NULL;

extra_freq_t  opt_extra_freqs[EXTRA_FREQ_MAX];
int           opt_extra_freq_count    = 0;

/* SDR / file input */
char       *opt_input_file = NULL;
iq_format_t iq_format      = FMT_CI8;
bool        opt_iq_format_set = false;

/* Per-backend gain controls.
 *
 * HackRF defaults: LNA=24 sets the noise figure; VGA=20 fills behind. */
int   hackrf_lna_gain   = 24;
int   hackrf_vga_gain   = 20;
int   hackrf_amp_enable = 0;
int   bladerf_gain_val  = 30;
int   rtl_dev_index     = 0;
int   rtl_gain_tenths_db = -1;
int   agc_enabled       = 0;        /* used by rtlsdr.c */
int   airspy_gain_val   = -1;
char *sdrplay_serial    = NULL;
int   sdrplay_gain_val  = 40;
int   soapy_num         = -1;
char *soapy_args        = NULL;
char *soapy_gain_elem_names[SOAPY_GAINS_MAX];
double soapy_gain_elem_vals[SOAPY_GAINS_MAX];
int    soapy_gain_elem_count = 0;
double soapy_gain_val   = 40.0;
int    soapy_gain_explicit = 0;
char *soapy_setting_keys[SOAPY_SETTINGS_MAX];
char *soapy_setting_vals[SOAPY_SETTINGS_MAX];
int    soapy_setting_count = 0;
char  *uhd_args         = NULL;
/* UHD over-the-wire IQ format: "sc16" (default, 4 B/sample, preserves the
 * full 12-bit ADC) or "sc8" (2 B/sample, halves USB bandwidth at the cost
 * of 4 LSBs). sc8 is fine for LoRa decode and avoids USB overflow on
 * B-series at >= 20 Msps full-channel-grid captures. */
char  *opt_usrp_otw_format = NULL;
int    usrp_gain_val    = 40;
int    vita49_enabled   = 0;
char  *vita49_endpoint  = NULL;

/* Output sinks */
char *opt_feed_endpoint[FEED_MAX] = { NULL, NULL, NULL, NULL };
int   opt_feed_count              = 0;
char *opt_mqtt_host               = NULL;
int   opt_mqtt_port               = 1883;
char *opt_mqtt_topic              = NULL;
char *opt_zmq_endpoint            = NULL;
char *opt_announce_to             = NULL;
char *opt_c2_dealer               = NULL;
char *opt_zmq_curve_secret        = NULL;
char *opt_zmq_curve_keygen        = NULL;
uint32_t opt_station_t_acc_ns     = 1000000;  /* 1 ms = NTP-class default; mlat solver weights by this */
char *opt_cot_multicast           = NULL;
int   opt_web_port                = 0;
char *opt_station_id              = NULL;
char *opt_gpsd_endpoint           = NULL;
char *opt_api_token               = NULL;
char *opt_pcap_path               = NULL;
char *opt_pcap_fifo               = NULL;
char *opt_psk_wordlist            = NULL;
char *opt_archive_dir             = NULL;
char *opt_geofence_file           = NULL;

void options_print_help(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Mode:\n"
        "  --decode               (default) decode standard channels + any --extra-freq\n"
        "  --scan                 off-grid LoRa discovery only (no decode)\n"
        "  --scan-and-decode      both: decode grid, alert on off-grid sightings\n"
        "  --alert-off-grid       emit OFF_GRID_LORA alerts on first off-grid sighting\n"
        "  --trusted-only         suppress fields_trusted:false events from JSON/UDP/MQTT/web feeds\n"
        "                         (stats counters still tally everything; only publishing is filtered)\n"
        "  --show-untrusted       include CRC-fail/no-CRC events even when --trusted-only is set\n"
        "                         (kept off by default in deep-decode-auto mode)\n"
        "\n"
        "Scan-then-focus deep decode (wideband scanner always on, focused workers wake on activity):\n"
        "  --deep-decode=MODE     off | auto (default auto). 'auto' enables the focused-worker pool\n"
        "                         driven by wideband preamble locks; wideband never goes blind.\n"
        "                         Pass 'off' to disable on weak CPUs or for a strict wideband-only run.\n"
        "  --focus-workers=N      bounded pool size, 1..4 (default 2)\n"
        "  --focus-hold-s=S       seconds of frame inactivity before a worker idles (default 5)\n"
        "  --focus-rewind-ms=N    rewind from 'now' when a preamble lock arrives (default 20)\n"
        "  --focus-ring-ms=N      raw-IQ ring buffer in ms of history (default 500)\n"
        "  --focus-freqs=LIST     optional allowlist (decimal Hz, comma-separated). Default: any slot.\n"
        "  --focus-min-snr-db=DB  drop pool promotions below this preamble-lock SNR (default 6).\n"
        "                         Wideband decode is unaffected; this only filters which locks\n"
        "                         wake a focused worker. Set 0 to promote on every lock.\n"
        "  --focus-os=N|auto      focused decoder oversampling (default auto; N=1,2,4,8)\n"
        "  --snapshot-store=DIR   write a bounded raw-IQ window + JSON sidecar to DIR/YYYYMMDD/\n"
        "                         on every qualifying wideband preamble lock. Off by default.\n"
        "                         Snapshot writes happen on a separate thread; decode is\n"
        "                         never blocked by disk. Activating this option auto-enables\n"
        "                         the iq-ring even when --deep-decode=off.\n"
        "  --snapshot-window-pre-ms=N    samples before lock to include (default 50)\n"
        "  --snapshot-window-post-ms=N   samples after  lock to include (default 100)\n"
        "  --snapshot-store-disk-mb=N    rolling cap on total snapshot bytes (default 2048)\n"
        "  --snapshot-store-age-s=N      rolling cap on snapshot age in seconds (default 86400)\n"
        "  --snapshot-min-snr-db=DB      SNR floor; default = --focus-min-snr-db\n"
        "  --diagnostics          enable verbose internal counters (demod stats, focus telemetry, etc.)\n"
        "\n"
        "SDR selection (one):\n"
        "  --hackrf[=SERIAL]      use HackRF One\n"
        "  --bladerf[=SERIAL]     use BladeRF 2.0\n"
        "  --rtlsdr[=INDEX]       use RTL-SDR (device index, default 0)\n"
        "  --soapy=ARGS           use SoapySDR (driver=...)\n"
        "  --sdrplay[=SERIAL]     use SDRplay native API\n"
        "  --airspy[=SERIAL]      use Airspy R2/Mini\n"
        "  --usrp=ARGS            use USRP via UHD\n"
        "  --vita49=[BIND:]PORT   listen for VITA-49 (VRT) UDP. PORT is required;\n"
        "                         BIND defaults to 0.0.0.0. Sender side must use:\n"
        "                           - VRT signal-data packets (network byte order, big-endian)\n"
        "                           - an --iq-format matching the payload, unless the\n"
        "                             sender's IF-context declares the payload format\n"
        "                         VRL wrapper ('VRLP') is auto-detected (optional).\n"
        "                         IF-context packets are auto-adopted: sample_rate (Q44.20),\n"
        "                         RF freq, and data-packet payload format override missing\n"
        "                         CLI values, so a sender that emits context can run with\n"
        "                         bare --vita49=PORT.\n"
        "  --file=PATH            replay IQ file\n"
        "  --iq-format=FMT        cs8 (default) | cs16 | cf32. Used for raw file replay\n"
        "                         AND for the VITA-49 payload format. For VITA-49 this is\n"
        "                         only needed when the sender's context omits the payload\n"
        "                         format; an explicit value here always wins.\n"
        "\n"
        "RF:\n"
        "  --center=HZ            center frequency (default: region-derived)\n"
        "  --rate=HZ              sample rate (default: max for SDR)\n"
        "  --gain=DB              RF gain (backend-specific). HackRF maps a single\n"
        "                         knob across LNA+VGA+amp: 0..40 grows VGA only\n"
        "                         (close-range default 30); 40..60 adds LNA in 8 dB\n"
        "                         steps (distant rooftop ~50); 60..70 maxes both;\n"
        "                         70+ enables the 14 dB front-end amp (very weak).\n"
        "  --hackrf-lna=N         HackRF: explicit LNA gain in dB (0..40 step 8).\n"
        "                         Overrides whatever --gain mapped.\n"
        "  --hackrf-vga=N         HackRF: explicit VGA gain in dB (0..62 step 2).\n"
        "                         Overrides whatever --gain mapped.\n"
        "  --hackrf-amp           HackRF: enable the 14 dB front-end amp.\n"
        "  --hackrf-amp-off       HackRF: disable the front-end amp (default).\n"
        "  --bias-tee             enable antenna bias tee where supported\n"
        "  --ppm=PPM              SDR oscillator correction\n"
        "  --clock=internal|external|gpsdo\n"
        "                         clock + time source. USRP only for now\n"
        "                         (UHD set_clock_source / set_time_source); other\n"
        "                         backends ignore. 'external' = 10 MHz + 1PPS in;\n"
        "                         'gpsdo' = internal GPSDO daughtercard.\n"
        "\n"
        "Meshtastic:\n"
        "  --region=NAME          US|EU_868|EU_433|CN|JP|ANZ|...|LORA_24\n"
        "  --presets=LIST         comma-separated, or 'all' (default: LongFast)\n"
        "  --keys=LIST            comma-separated key list. Each entry is:\n"
        "                           ChannelName=SPEC   (recommended)\n"
        "                           SPEC               (assumed channel: LongFast)\n"
        "                         where SPEC is one of:\n"
        "                           default | simple0..10 | hex:HHHH... | base64:....\n"
        "                         Keys are routed via 1-byte channel hash; adding\n"
        "                         keys does not slow per-packet decode.\n"
        "                         Also reads MESHTASTIC_KEYS env var.\n"
        "  --keys-file=PATH       load keys from a file (one SPEC per line, # comments ok).\n"
        "                         Also tried at $XDG_CONFIG_HOME/meshtastic-sniffer/keys\n"
        "                         and ~/.config/meshtastic-sniffer/keys by default.\n"
        "  --share-url=URL        import a meshtastic.org/e/ channel-share URL at startup\n"
        "  --extra-freq=SPEC      add a non-standard decoder slot. SPEC is\n"
        "                         HZ:bw=BW:sf=SF:cr=CR (repeatable, max %d)\n"
        "  --iq-record=PATH       tee raw IQ samples to a file for later replay\n"
        "  --stats-json=PATH      write per-channel stats JSON every 5s (rotates)\n"
        "  --fftw-wisdom[=PATH]   load/save FFTW plan timing data so cold starts skip\n"
        "                         the FFTW_MEASURE benchmark (off by default). Without\n"
        "                         PATH uses $XDG_CACHE_HOME/meshtastic-sniffer/fftw.wisdom\n"
        "                         or $HOME/.cache/meshtastic-sniffer/fftw.wisdom.\n"
        "\n"
        "Outputs (any combination):\n"
        "  --feed=HOST:PORT       JSON UDP feed (repeatable, max %d)\n"
        "  --mqtt=HOST[:PORT]     MQTT broker\n"
        "  --mqtt-topic=TOPIC     MQTT topic (default: meshtastic/<station>)\n"
        "  --zmq[=ENDPOINT]       ZMQ PUB (default tcp://*:7008)\n"
        "  --cot-multicast=GROUP[:PORT]\n"
        "                         republish ATAK port-72 PLIs as CoT XML to a\n"
        "                         multicast group (default port 6969). LAN-scope.\n"
        "  --web[=PORT]           built-in dashboard (default 8888)\n"
        "  --station-id=ID        station identifier in feed messages\n"
        "  --gpsd[=HOST:PORT]     read this station's own GPS from gpsd\n"
        "                         (default localhost:2947). Tags every emitted\n"
        "                         JSON event with station_lat / station_lon /\n"
        "                         station_alt_m so a multi-station deployment\n"
        "                         can group same-packet observations spatially.\n"
        "  --api-token=SECRET     require 'Authorization: Bearer SECRET' on every\n"
        "                         POST /api/* request. GET endpoints (dashboard,\n"
        "                         /events SSE) stay open. Unset = no auth.\n"
        "  --pcap=PATH            write received LoRa frames to PATH as a libpcap\n"
        "                         file (DLT_USER0=147). Use with tshark / Wireshark.\n"
        "  --pcap-fifo=PATH       like --pcap but creates PATH as a named pipe;\n"
        "                         start `wireshark -k -i PATH` for live capture.\n"
        "  --psk-wordlist=PATH    background dictionary attack on undecrypted frames.\n"
        "                         File format: one PSK spec per line (same grammar\n"
        "                         as --keys: default | simpleN | hex:HHHH... |\n"
        "                         base64:...). Discovered keys auto-add to the\n"
        "                         runtime keyset; PSK_DISCOVERED events fire per hit.\n"
        "  --archive=DIR          long-term JSONL archive. Every emitted event is\n"
        "                         appended to DIR/meshtastic-YYYYMMDD.jsonl.gz\n"
        "                         (gzipped, daily rotation at UTC midnight).\n"
        "  --geofence=PATH        load polygons from PATH (INI-style: [name]\n"
        "                         section + lat,lon vertices, one per line).\n"
        "                         Emits GEOFENCE_ENTRY / GEOFENCE_EXIT events when\n"
        "                         a positioned node crosses a polygon boundary.\n"
        "  --announce-to=URL      periodically POST this sensor's entry to a\n"
        "                         meshtastic-fusion /api/sensors endpoint so\n"
        "                         the fusion auto-discovers it. URL example:\n"
        "                         http://fusion.local:9000/api/sensors\n"
        "  --c2-dealer=tcp://...  open an outbound ZMQ DEALER socket to the\n"
        "                         fusion's ROUTER for command-and-control over\n"
        "                         a single multiplexed connection (works through\n"
        "                         NAT). Coexists with --web HTTP /api/* endpoints.\n"
        "  --zmq-curve-secret=PATH\n"
        "                         load Z85 server secret key from PATH and\n"
        "                         enable CurveZMQ on --zmq PUB. PATH.pub must\n"
        "                         contain the matching public key (publish to\n"
        "                         fusion as the sensor's curve_pub field).\n"
        "  --zmq-curve-keygen=PATH\n"
        "                         generate a CurveZMQ keypair, write secret to\n"
        "                         PATH and public to PATH.pub, then exit.\n"
        "  --station-t-acc-ns=N   self-reported timestamp accuracy class in\n"
        "                         nanoseconds. Defaults to 1000000 (1 ms,\n"
        "                         NTP-class). Set 1000 for chrony+PPS hosts,\n"
        "                         100 for GPSDO + 1PPS-locked SDR. Consumed\n"
        "                         by the fusion-side mlat solver to weight\n"
        "                         observations from this station.\n"
        "\n"
        "Misc:\n"
        "  --simd-generic         force scalar SIMD (debug)\n"
        "  --selftest             run self-tests (channelizer + AES end-to-end)\n"
        "  --selftest-rejection   measure channelizer ACR across the grid; CSV to /tmp/meshtastic-pfb-rejection-<ts>.csv\n"
        "  --selftest-rejection-amplitude\n"
        "                         sweep ACR vs source amplitude {-40,-20,-10,-3,-0.1} dBFS; CSV to /tmp\n"
        "  --selftest-rejection-twotone\n"
        "                         strong tone in A + weak tone in B; measure B's recovered power with/without A; CSV to /tmp\n"
        "  --selftest-rejection-offbin\n"
        "                         sweep tone offset from channel center in fractional-bin steps; CSV to /tmp\n"
        "  --selftest-rejection-procgain\n"
        "                         wideband-noise processing-gain test: input vs output SNR vs 10*log10(M); CSV to /tmp\n"
        "  --list                 enumerate all available SDR devices and exit\n"
        "  --schema               print JSON Schema for the event format and exit\n"
        "  -v, --verbose          INFO+WARN diagnostics (-vv DEBUG, -vvv TRACE)\n"
        "  -h, --help\n",
        prog, EXTRA_FREQ_MAX, FEED_MAX);
}

/* Parse "f_hz:bw=BW:sf=SF:cr=CR" (BW/SF/CR optional, defaults match LongFast). */
static int parse_extra_freq(const char *spec)
{
    if (opt_extra_freq_count >= EXTRA_FREQ_MAX) return -1;
    extra_freq_t *e = &opt_extra_freqs[opt_extra_freq_count];
    e->bw_hz = 250000; e->sf = 11; e->cr = 5; e->freq_hz = 0;

    char *dup = strdup(spec);
    char *save = NULL;
    int  field = 0;
    for (char *tok = strtok_r(dup, ":", &save); tok; tok = strtok_r(NULL, ":", &save), ++field) {
        if (field == 0) {
            e->freq_hz = strtoull(tok, NULL, 10);
        } else {
            char *eq = strchr(tok, '=');
            if (!eq) continue;
            *eq = 0;
            int v = atoi(eq + 1);
            if      (!strcasecmp(tok, "bw")) e->bw_hz = v;
            else if (!strcasecmp(tok, "sf")) e->sf    = v;
            else if (!strcasecmp(tok, "cr")) e->cr    = v;
        }
    }
    free(dup);
    if (e->freq_hz == 0) return -1;
    opt_extra_freq_count++;
    return 0;
}

static int set_backend(sdr_backend_t b, const char *arg)
{
    if (opt_sdr_backend != SDR_BACKEND_NONE) {
        fprintf(stderr, "error: only one SDR backend may be selected\n");
        return -1;
    }
    opt_sdr_backend = b;
    if (arg && *arg) opt_sdr_serial = strdup(arg);
    return 0;
}

int options_parse(int argc, char **argv)
{
    enum {
        O_HACKRF = 200, O_BLADERF, O_RTLSDR, O_SOAPY, O_SDRPLAY, O_AIRSPY,
        O_USRP, O_VITA49, O_FILE, O_IQ_FORMAT,
        O_CENTER, O_RATE, O_GAIN, O_BIAS, O_PPM, O_CLOCK,
        O_REGION, O_PRESETS, O_KEYS, O_KEYS_FILE, O_SHARE_URL, O_EXTRA_FREQ,
        O_IQ_RECORD, O_STATS_JSON, O_FFTW_WISDOM,
        O_FEED, O_MQTT, O_MQTT_TOPIC, O_ZMQ, O_COT, O_WEB, O_STATION, O_GPSD, O_API_TOKEN,
        O_PCAP, O_PCAP_FIFO, O_PSK_WORDLIST, O_ARCHIVE, O_GEOFENCE, O_ANNOUNCE_TO, O_C2_DEALER,
        O_ZMQ_CURVE_SECRET, O_ZMQ_CURVE_KEYGEN, O_STATION_T_ACC_NS,
        O_HACKRF_LNA, O_HACKRF_VGA, O_HACKRF_AMP, O_HACKRF_AMP_OFF, O_USRP_OTW,
        O_DECODE, O_SCAN, O_SCAN_DEC, O_ALERT_OFF_GRID, O_TRUSTED_ONLY,
        O_SHOW_UNTRUSTED, O_DIAGNOSTICS,
        O_DEEP_DECODE, O_FOCUS_WORKERS, O_FOCUS_HOLD_S, O_FOCUS_REWIND_MS,
        O_FOCUS_FREQS, O_FOCUS_RING_MS, O_FOCUS_MIN_SNR_DB, O_FOCUS_OS,
        O_SNAPSHOT_STORE, O_SNAPSHOT_PRE_MS, O_SNAPSHOT_POST_MS,
        O_SNAPSHOT_DISK_MB, O_SNAPSHOT_AGE_S, O_SNAPSHOT_MIN_SNR_DB,
        O_SIMD_GEN, O_SELFTEST, O_SELFTEST_REJECTION, O_SELFTEST_REJECTION_AMP,
        O_SELFTEST_REJECTION_TWOTONE, O_SELFTEST_REJECTION_OFFBIN,
        O_SELFTEST_REJECTION_PROCGAIN,
        O_LIST, O_SCHEMA,
    };
    static const struct option longopts[] = {
        { "hackrf",     optional_argument, NULL, O_HACKRF },
        { "hackrf-lna", required_argument, NULL, O_HACKRF_LNA },
        { "hackrf-vga", required_argument, NULL, O_HACKRF_VGA },
        { "hackrf-amp", no_argument,       NULL, O_HACKRF_AMP },
        { "hackrf-amp-off", no_argument,   NULL, O_HACKRF_AMP_OFF },
        { "bladerf",    optional_argument, NULL, O_BLADERF },
        { "rtlsdr",     optional_argument, NULL, O_RTLSDR },
        { "soapy",      required_argument, NULL, O_SOAPY },
        { "sdrplay",    optional_argument, NULL, O_SDRPLAY },
        { "airspy",     optional_argument, NULL, O_AIRSPY },
        { "usrp",       optional_argument, NULL, O_USRP },
        { "usrp-otw",   required_argument, NULL, O_USRP_OTW },
        { "vita49",     required_argument, NULL, O_VITA49 },
        { "file",       required_argument, NULL, O_FILE },
        { "iq-format",  required_argument, NULL, O_IQ_FORMAT },
        { "center",     required_argument, NULL, O_CENTER },
        { "rate",       required_argument, NULL, O_RATE },
        { "gain",       required_argument, NULL, O_GAIN },
        { "bias-tee",   no_argument,       NULL, O_BIAS },
        { "ppm",        required_argument, NULL, O_PPM },
        { "clock",      required_argument, NULL, O_CLOCK },
        { "region",     required_argument, NULL, O_REGION },
        { "presets",    required_argument, NULL, O_PRESETS },
        { "keys",       required_argument, NULL, O_KEYS },
        { "keys-file",  required_argument, NULL, O_KEYS_FILE },
        { "share-url",  required_argument, NULL, O_SHARE_URL },
        { "iq-record",  required_argument, NULL, O_IQ_RECORD },
        { "stats-json", required_argument, NULL, O_STATS_JSON },
        { "fftw-wisdom", optional_argument, NULL, O_FFTW_WISDOM },
        { "extra-freq", required_argument, NULL, O_EXTRA_FREQ },
        { "feed",       required_argument, NULL, O_FEED },
        { "mqtt",       required_argument, NULL, O_MQTT },
        { "mqtt-topic", required_argument, NULL, O_MQTT_TOPIC },
        { "zmq",        optional_argument, NULL, O_ZMQ },
        { "cot-multicast", required_argument, NULL, O_COT },
        { "web",        optional_argument, NULL, O_WEB },
        { "station-id", required_argument, NULL, O_STATION },
        { "gpsd",       optional_argument, NULL, O_GPSD },
        { "api-token",  required_argument, NULL, O_API_TOKEN },
        { "pcap",       required_argument, NULL, O_PCAP },
        { "pcap-fifo",  required_argument, NULL, O_PCAP_FIFO },
        { "psk-wordlist", required_argument, NULL, O_PSK_WORDLIST },
        { "archive",    required_argument, NULL, O_ARCHIVE },
        { "geofence",   required_argument, NULL, O_GEOFENCE },
        { "announce-to", required_argument, NULL, O_ANNOUNCE_TO },
        { "c2-dealer", required_argument, NULL, O_C2_DEALER },
        { "zmq-curve-secret", required_argument, NULL, O_ZMQ_CURVE_SECRET },
        { "zmq-curve-keygen", required_argument, NULL, O_ZMQ_CURVE_KEYGEN },
        { "station-t-acc-ns", required_argument, NULL, O_STATION_T_ACC_NS },
        { "decode",     no_argument,       NULL, O_DECODE },
        { "scan",       no_argument,       NULL, O_SCAN },
        { "scan-and-decode", no_argument,  NULL, O_SCAN_DEC },
        { "alert-off-grid",  no_argument,  NULL, O_ALERT_OFF_GRID },
        { "trusted-only",    no_argument,       NULL, O_TRUSTED_ONLY },
        { "show-untrusted",  no_argument,       NULL, O_SHOW_UNTRUSTED },
        { "diagnostics",     no_argument,       NULL, O_DIAGNOSTICS },
        { "deep-decode",     required_argument, NULL, O_DEEP_DECODE },
        { "focus-workers",   required_argument, NULL, O_FOCUS_WORKERS },
        { "focus-hold-s",    required_argument, NULL, O_FOCUS_HOLD_S },
        { "focus-rewind-ms", required_argument, NULL, O_FOCUS_REWIND_MS },
        { "focus-freqs",     required_argument, NULL, O_FOCUS_FREQS },
        { "focus-ring-ms",   required_argument, NULL, O_FOCUS_RING_MS },
        { "focus-min-snr-db", required_argument, NULL, O_FOCUS_MIN_SNR_DB },
        { "focus-os",        required_argument, NULL, O_FOCUS_OS },
        { "snapshot-store",         required_argument, NULL, O_SNAPSHOT_STORE },
        { "snapshot-window-pre-ms", required_argument, NULL, O_SNAPSHOT_PRE_MS },
        { "snapshot-window-post-ms",required_argument, NULL, O_SNAPSHOT_POST_MS },
        { "snapshot-store-disk-mb", required_argument, NULL, O_SNAPSHOT_DISK_MB },
        { "snapshot-store-age-s",   required_argument, NULL, O_SNAPSHOT_AGE_S },
        { "snapshot-min-snr-db",    required_argument, NULL, O_SNAPSHOT_MIN_SNR_DB },
        { "simd-generic", no_argument,     NULL, O_SIMD_GEN },
        { "selftest",   no_argument,       NULL, O_SELFTEST },
        { "selftest-rejection", no_argument, NULL, O_SELFTEST_REJECTION },
        { "selftest-rejection-amplitude", no_argument, NULL, O_SELFTEST_REJECTION_AMP },
        { "selftest-rejection-twotone",   no_argument, NULL, O_SELFTEST_REJECTION_TWOTONE },
        { "selftest-rejection-offbin",    no_argument, NULL, O_SELFTEST_REJECTION_OFFBIN },
        { "selftest-rejection-procgain",  no_argument, NULL, O_SELFTEST_REJECTION_PROCGAIN },
        { "list",       no_argument,       NULL, O_LIST },
        { "schema",     no_argument,       NULL, O_SCHEMA },
        { "help",       no_argument,       NULL, 'h' },
        { "verbose",    no_argument,       NULL, 'v' },
        { NULL, 0, NULL, 0 },
    };

    int c;
    while ((c = getopt_long(argc, argv, "hv", longopts, NULL)) != -1) {
        switch (c) {
        case 'h': options_print_help(argv[0]); return 1;
        case 'v': ++verbose; break;

        case O_HACKRF:  if (set_backend(SDR_BACKEND_HACKRF,  optarg) < 0) return 2; break;
        case O_BLADERF: if (set_backend(SDR_BACKEND_BLADERF, optarg) < 0) return 2; break;
        case O_RTLSDR:
            if (set_backend(SDR_BACKEND_RTLSDR, optarg) < 0) return 2;
            if (optarg) rtl_dev_index = atoi(optarg);
            break;
        case O_SOAPY:   if (set_backend(SDR_BACKEND_SOAPYSDR, optarg) < 0) return 2;
                        soapy_args = optarg ? strdup(optarg) : NULL; break;
        case O_SDRPLAY: if (set_backend(SDR_BACKEND_SDRPLAY, optarg) < 0) return 2; break;
        case O_AIRSPY:  if (set_backend(SDR_BACKEND_AIRSPY,  optarg) < 0) return 2; break;
        case O_USRP:    if (set_backend(SDR_BACKEND_USRP,    optarg) < 0) return 2;
                        /* optarg may be NULL when --usrp is passed without
                         * an explicit serial; downstream strdup(NULL) would
                         * crash. Treat absent serial as empty string. */
                        uhd_args = strdup(optarg ? optarg : ""); break;
        case O_USRP_OTW:
            if (strcasecmp(optarg, "sc16") != 0 && strcasecmp(optarg, "sc8") != 0) {
                fprintf(stderr, "--usrp-otw must be sc16 or sc8 (got %s)\n", optarg);
                return 2;
            }
            opt_usrp_otw_format = strdup(optarg);
            break;
        case O_VITA49:  if (set_backend(SDR_BACKEND_VITA49,  optarg) < 0) return 2;
                        vita49_endpoint = strdup(optarg);
                        vita49_enabled = 1;
                        break;
        case O_FILE:    if (set_backend(SDR_BACKEND_FILE, NULL) < 0) return 2;
                        opt_input_file = strdup(optarg); break;

        case O_IQ_FORMAT:
            if      (!strcasecmp(optarg, "cs8")  || !strcasecmp(optarg, "ci8"))  iq_format = FMT_CI8;
            else if (!strcasecmp(optarg, "cs16") || !strcasecmp(optarg, "ci16")) iq_format = FMT_CI16;
            else if (!strcasecmp(optarg, "cf32") || !strcasecmp(optarg, "fc32")) iq_format = FMT_CF32;
            else { fprintf(stderr, "unknown --iq-format=%s\n", optarg); return 2; }
            opt_iq_format_set = true;
            break;

        case O_CENTER:  opt_center_freq_hz = strtoull(optarg, NULL, 10); break;
        case O_RATE:    opt_sample_rate    = (uint32_t)strtoul(optarg, NULL, 10); break;
        case O_GAIN: {
            double g = strtod(optarg, NULL);
            soapy_gain_val = g; bladerf_gain_val = (int)g; usrp_gain_val = (int)g;
            rtl_gain_tenths_db = (int)(g * 10.0);
            sdrplay_gain_val = (int)g;
            airspy_gain_val = (int)g;
            /* HackRF: fill LNA (sets noise figure) first, then VGA, then
             * more LNA, then the 14 dB front-end amp at the top. */
            if (g <= 0) {
                hackrf_lna_gain = 0;  hackrf_vga_gain = 0;
                hackrf_amp_enable = 0;
            } else if (g <= 24) {
                int lna = ((int)g / 8) * 8;       /* 0/8/16/24 */
                hackrf_lna_gain = lna;
                hackrf_vga_gain = (int)g - lna;
                hackrf_amp_enable = 0;
            } else if (g <= 56) {
                hackrf_lna_gain = 24;
                hackrf_vga_gain = (int)g - 24;
                hackrf_amp_enable = 0;
            } else if (g <= 72) {
                int lna = (g <= 64) ? 32 : 40;
                hackrf_lna_gain = lna;
                hackrf_vga_gain = (int)g - lna;
                hackrf_amp_enable = 0;
            } else {
                hackrf_lna_gain = 40;
                hackrf_vga_gain = 62;
                hackrf_amp_enable = 1;
            }
            break;
        }
        case O_BIAS:    bias_tee = 1; break;
        case O_PPM:     ppm_correction = strtod(optarg, NULL); break;
        case O_CLOCK:
            if      (!strcasecmp(optarg, "internal")) opt_clock_src = CLOCK_SRC_INTERNAL;
            else if (!strcasecmp(optarg, "external")) opt_clock_src = CLOCK_SRC_EXTERNAL;
            else if (!strcasecmp(optarg, "gpsdo"))    opt_clock_src = CLOCK_SRC_GPSDO;
            else { fprintf(stderr, "unknown --clock=%s\n", optarg); return 2; }
            break;

        case O_REGION:  opt_region     = strdup(optarg); break;
        case O_PRESETS: opt_preset_csv = strdup(optarg); break;
        case O_KEYS:       opt_keys_csv   = strdup(optarg); break;
        case O_KEYS_FILE:  opt_keys_file  = strdup(optarg); break;
        case O_SHARE_URL:  opt_share_url  = strdup(optarg); break;
        case O_IQ_RECORD:  opt_iq_record  = strdup(optarg); break;
        case O_STATS_JSON: opt_stats_json = strdup(optarg); break;
        case O_FFTW_WISDOM:
            /* Empty string means "use the default cache path". */
            opt_fftw_wisdom = strdup(optarg ? optarg : "");
            break;
        case O_EXTRA_FREQ:
            if (parse_extra_freq(optarg) < 0) {
                fprintf(stderr, "bad --extra-freq=%s (need HZ:bw=BW:sf=SF:cr=CR)\n", optarg);
                return 2;
            }
            break;

        case O_FEED:
            if (opt_feed_count < FEED_MAX)
                opt_feed_endpoint[opt_feed_count++] = strdup(optarg);
            break;
        case O_MQTT: {
            char *colon = strchr(optarg, ':');
            if (colon) {
                *colon = 0;
                opt_mqtt_port = atoi(colon + 1);
            }
            opt_mqtt_host = strdup(optarg);
            break;
        }
        case O_MQTT_TOPIC: opt_mqtt_topic = strdup(optarg); break;
        case O_ZMQ:        opt_zmq_endpoint = optarg ? strdup(optarg) : strdup("tcp://*:7008"); break;
        case O_COT:        opt_cot_multicast = strdup(optarg); break;
        case O_WEB:        opt_web_port = optarg ? atoi(optarg) : 8888; break;
        case O_STATION:    opt_station_id = strdup(optarg); break;
        case O_GPSD:       opt_gpsd_endpoint = strdup(optarg ? optarg : "localhost:2947"); break;
        case O_API_TOKEN:  opt_api_token = strdup(optarg); break;
        case O_PCAP:       opt_pcap_path = strdup(optarg); break;
        case O_PCAP_FIFO:  opt_pcap_fifo = strdup(optarg); break;
        case O_PSK_WORDLIST: opt_psk_wordlist = strdup(optarg); break;
        case O_ARCHIVE:    opt_archive_dir = strdup(optarg); break;
        case O_GEOFENCE:   opt_geofence_file = strdup(optarg); break;
        case O_ANNOUNCE_TO: opt_announce_to = strdup(optarg); break;
        case O_C2_DEALER:  opt_c2_dealer = strdup(optarg); break;
        case O_ZMQ_CURVE_SECRET: opt_zmq_curve_secret = strdup(optarg); break;
        case O_ZMQ_CURVE_KEYGEN: opt_zmq_curve_keygen = strdup(optarg); break;
        case O_STATION_T_ACC_NS: opt_station_t_acc_ns = (uint32_t)strtoul(optarg, NULL, 10); break;
        case O_HACKRF_LNA: hackrf_lna_gain = atoi(optarg); break;
        case O_HACKRF_VGA: hackrf_vga_gain = atoi(optarg); break;
        case O_HACKRF_AMP: hackrf_amp_enable = 1; break;
        case O_HACKRF_AMP_OFF: hackrf_amp_enable = 0; break;

        case O_DECODE:           opt_op_mode = OP_MODE_DECODE; break;
        case O_SCAN:             opt_op_mode = OP_MODE_SCAN; break;
        case O_SCAN_DEC:         opt_op_mode = OP_MODE_SCAN_AND_DECODE; break;
        case O_ALERT_OFF_GRID:   opt_alert_off_grid = true; break;
        case O_TRUSTED_ONLY:     opt_trusted_only   = true; break;
        case O_SHOW_UNTRUSTED:   opt_show_untrusted = true; break;
        case O_DIAGNOSTICS:      opt_diagnostics    = true; break;
        case O_DEEP_DECODE:
            if (!strcasecmp(optarg, "off"))       opt_deep_decode = DEEP_DECODE_OFF;
            else if (!strcasecmp(optarg, "auto")) opt_deep_decode = DEEP_DECODE_AUTO;
            else { fprintf(stderr,
                           "--deep-decode must be off|auto (got %s)\n", optarg);
                   return 2; }
            break;
        case O_FOCUS_WORKERS: {
            int n = atoi(optarg);
            if (n < 1 || n > 4) {
                fprintf(stderr, "--focus-workers must be 1..4 (got %s)\n", optarg);
                return 2;
            }
            opt_focus_workers = n;
            break;
        }
        case O_FOCUS_HOLD_S:    opt_focus_hold_s    = atof(optarg); break;
        case O_FOCUS_REWIND_MS: opt_focus_rewind_ms = atoi(optarg); break;
        case O_FOCUS_RING_MS:   opt_focus_ring_ms   = atoi(optarg); break;
        case O_FOCUS_FREQS:     opt_focus_freqs_csv = strdup(optarg); break;
        case O_FOCUS_MIN_SNR_DB: opt_focus_min_snr_db = atof(optarg); break;
        case O_FOCUS_OS:
            if (!strcasecmp(optarg, "auto")) {
                opt_focus_os = 0;
            } else {
                int n = atoi(optarg);
                if (!(n == 1 || n == 2 || n == 4 || n == 8)) {
                    fprintf(stderr, "--focus-os must be auto,1,2,4,8 (got %s)\n", optarg);
                    return 2;
                }
                opt_focus_os = n;
            }
            break;
        case O_SNAPSHOT_STORE:        opt_snapshot_store_dir       = strdup(optarg); break;
        case O_SNAPSHOT_PRE_MS:       opt_snapshot_window_pre_ms   = atoi(optarg);  break;
        case O_SNAPSHOT_POST_MS:      opt_snapshot_window_post_ms  = atoi(optarg);  break;
        case O_SNAPSHOT_DISK_MB:      opt_snapshot_disk_mb         = atoll(optarg); break;
        case O_SNAPSHOT_AGE_S:        opt_snapshot_age_s           = atoll(optarg); break;
        case O_SNAPSHOT_MIN_SNR_DB:   opt_snapshot_min_snr_db      = atof(optarg);  break;

        case O_SIMD_GEN: opt_force_simd_generic = true; break;
        case O_SELFTEST: return 100;
        case O_SELFTEST_REJECTION: return 101;
        case O_SELFTEST_REJECTION_AMP: return 102;
        case O_SELFTEST_REJECTION_TWOTONE: return 103;
        case O_SELFTEST_REJECTION_OFFBIN: return 104;
        case O_SELFTEST_REJECTION_PROCGAIN: return 105;
        case O_LIST:     opt_list_devices = true; break;
        case O_SCHEMA:   opt_print_schema = true; break;

        default:
            options_print_help(argv[0]);
            return 2;
        }
    }

    /* Pull MESHTASTIC_KEYS env var into the keys csv if not set on CLI. */
    if (!opt_keys_csv) {
        const char *env = getenv("MESHTASTIC_KEYS");
        if (env && *env) opt_keys_csv = strdup(env);
    }

    /* Defaults */
    if (!opt_region)     opt_region     = strdup("US");
    if (!opt_preset_csv) opt_preset_csv = strdup("LongFast");
    if (!opt_keys_csv)   opt_keys_csv   = strdup("default");

    return 0;
}
