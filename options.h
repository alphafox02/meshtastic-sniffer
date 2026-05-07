/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * meshtastic-sniffer: CLI option parsing and shared runtime state.
 *
 */

#ifndef OPTIONS_H
#define OPTIONS_H

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "sdr.h"

/* SDR backend selection -- one and only one of these is active per run. */
typedef enum {
    SDR_BACKEND_NONE = 0,
    SDR_BACKEND_HACKRF,
    SDR_BACKEND_BLADERF,
    SDR_BACKEND_RTLSDR,
    SDR_BACKEND_SOAPYSDR,
    SDR_BACKEND_SDRPLAY,
    SDR_BACKEND_AIRSPY,
    SDR_BACKEND_USRP,
    SDR_BACKEND_VITA49,
    SDR_BACKEND_FILE,
} sdr_backend_t;

typedef enum {
    OP_MODE_DECODE = 0,        /* default: stare at standard grid + decode */
    OP_MODE_SCAN,              /* off-grid LoRa discovery only */
    OP_MODE_SCAN_AND_DECODE,   /* both: decode the grid, alert on off-grid */
} op_mode_t;

/* ---- Shared runtime state ---- */

extern volatile sig_atomic_t running;  /* set to 0 by SIGINT/SIGTERM */
extern double  samp_rate;              /* resolved sample rate (Hz, double for SDR APIs) */
extern double  center_freq;            /* resolved center frequency (Hz) */
extern int     bias_tee;
extern double  ppm_correction;

/* ---- Top-level user input ---- */

extern sdr_backend_t opt_sdr_backend;
extern char         *opt_sdr_serial;
extern uint64_t      opt_center_freq_hz;  /* user override; 0 = derive from region */
extern uint32_t      opt_sample_rate;     /* user override; 0 = SDR max */
extern int           opt_clock_src;       /* CLOCK_SRC_* from sdr.h */
/* Log level: 0 = silent (warnings still go to stderr via warnx),
 *            1 = -v   INFO  (config, channel adds, frame decodes),
 *            2 = -vv  DEBUG (per-frame meta, decryption attempts),
 *            3 = -vvv TRACE (per-symbol state machine). */
extern int           verbose;
extern bool          opt_force_simd_generic;
extern op_mode_t     opt_op_mode;
extern bool          opt_alert_off_grid;
extern bool          opt_list_devices;

/* Meshtastic */
extern char         *opt_region;          /* "US", "EU_868", ... */
extern char         *opt_preset_csv;      /* "LongFast,LongSlow" or "all" */
extern char         *opt_keys_csv;        /* user key list */
extern char         *opt_keys_file;       /* path; one spec per line, # comments ok */
extern char         *opt_share_url;       /* meshtastic.org/e/ URL to import at startup */
extern char         *opt_iq_record;       /* path to write raw IQ to (tee from push_samples) */
extern char         *opt_stats_json;      /* path to dump 5s per-channel stats JSON */

/* Extra user-supplied off-grid slots (e.g. promoted from scan). */
#define EXTRA_FREQ_MAX 32
typedef struct {
    uint64_t freq_hz;
    int      bw_hz;
    int      sf;
    int      cr;
} extra_freq_t;
extern extra_freq_t opt_extra_freqs[EXTRA_FREQ_MAX];
extern int          opt_extra_freq_count;

/* SDR / file input */
extern char       *opt_input_file;       /* IQ file path for FILE backend */
extern iq_format_t iq_format;            /* FMT_CI8 / FMT_CI16 / FMT_CF32 */

/* Per-backend gain controls */
extern int  hackrf_lna_gain;             /* 0..40 step 8 */
extern int  hackrf_vga_gain;             /* 0..62 step 2 */
extern int  hackrf_amp_enable;
extern int  bladerf_gain_db;
extern int  rtl_dev_index;
extern int  rtl_gain_tenths_db;          /* tenths of dB; <0 = AGC */
extern int  airspy_lin_gain;             /* 0..21; <0 = default */
extern char *sdrplay_serial;
extern int  sdrplay_gain_val;
extern int  soapy_num;
extern char *soapy_args;
#define SOAPY_GAINS_MAX 8
extern char  *soapy_gain_elem_names[SOAPY_GAINS_MAX];
extern double soapy_gain_elem_vals[SOAPY_GAINS_MAX];
extern int    soapy_gain_elem_count;
extern double soapy_gain_val;
extern int    soapy_gain_explicit;
#define SOAPY_SETTINGS_MAX 8
extern char  *soapy_setting_keys[SOAPY_SETTINGS_MAX];
extern char  *soapy_setting_vals[SOAPY_SETTINGS_MAX];
extern int    soapy_setting_count;
extern char  *uhd_args;
extern double uhd_gain_db;
extern int   vita49_enabled;
extern char *vita49_endpoint;

/* Output sinks */
#define FEED_MAX 4
extern char *opt_feed_endpoint[FEED_MAX];
extern int   opt_feed_count;
extern char *opt_mqtt_host;
extern int   opt_mqtt_port;
extern char *opt_mqtt_topic;
extern char *opt_zmq_endpoint;
extern char *opt_cot_multicast;          /* "239.2.3.1:6969" or NULL */
extern int   opt_web_port;
extern char *opt_station_id;
extern char *opt_gpsd_endpoint;          /* "host:port"; NULL = disabled */
extern char *opt_api_token;              /* bearer token for /api/*; NULL = unauthenticated */

int  options_parse(int argc, char **argv);
void options_print_help(const char *prog);

#endif /* OPTIONS_H */
