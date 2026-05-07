/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * SoapySDR backend for inmarsat-sniffer
 *
 */

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <SoapySDR/Device.h>
#include <SoapySDR/Formats.h>
#include <SoapySDR/Version.h>

#include "sdr.h"

extern sig_atomic_t running;
extern pid_t self_pid;
extern double samp_rate;
extern double center_freq;
extern double soapy_gain_val;
extern int bias_tee;
extern int verbose;

#define SOAPY_SETTINGS_MAX 8
extern char *soapy_setting_keys[SOAPY_SETTINGS_MAX];
extern char *soapy_setting_vals[SOAPY_SETTINGS_MAX];
extern int soapy_setting_count;

#define SOAPY_GAINS_MAX 8
extern char *soapy_gain_elem_names[SOAPY_GAINS_MAX];
extern double soapy_gain_elem_vals[SOAPY_GAINS_MAX];
extern int soapy_gain_elem_count;

static int sample_mode = 0;  /* 0=CS8, 1=CF32, 2=CS16 (fallback) */

void soapy_list(void) {
    size_t length;
    SoapySDRKwargs *results = SoapySDRDevice_enumerate(NULL, &length);

    for (size_t i = 0; i < length; ++i) {
        char *driver = NULL;
        char *label = NULL;
        char *dev_serial = NULL;

        for (size_t j = 0; j < results[i].size; ++j) {
            if (strcmp(results[i].keys[j], "driver") == 0)
                driver = results[i].vals[j];
            if (strcmp(results[i].keys[j], "label") == 0)
                label = results[i].vals[j];
            if (strcmp(results[i].keys[j], "serial") == 0)
                dev_serial = results[i].vals[j];
        }

        {
            char val[32];
            snprintf(val, sizeof(val), "soapy-%zu", i);
            printf("  %-24s %s%s%s\n", val,
                   driver ? driver : "SoapySDR",
                   label ? " - " : "",
                   label ? label : "");
        }

        if (driver || dev_serial) {
            char args[256] = "soapy:";
            size_t off = 6;
            if (driver)
                off += snprintf(args + off, sizeof(args) - off, "driver=%s", driver);
            if (dev_serial)
                off += snprintf(args + off, sizeof(args) - off, "%sserial=%s",
                                driver ? "," : "", dev_serial);
            printf("  %-24s  (alternate)\n", args);
        }
    }

    SoapySDRKwargsList_clear(results, length);
}

SoapySDRDevice *soapy_setup(int id, const char *args) {
    SoapySDRDevice *device;
    char **formats;
    size_t num_formats;

    if (args) {
        device = SoapySDRDevice_makeStrArgs(args);
        if (device == NULL)
            errx(1, "Unable to open SoapySDR device with args '%s': %s",
                 args, SoapySDRDevice_lastError());
        if (verbose)
            fprintf(stderr, "SoapySDR: opened device with args: %s\n", args);
    } else {
        size_t length;
        SoapySDRKwargs *results = SoapySDRDevice_enumerate(NULL, &length);

        if (id < 0 || (size_t)id >= length) {
            SoapySDRKwargsList_clear(results, length);
            errx(1, "Invalid SoapySDR device index: %d (found %zu devices)", id, length);
        }

        device = SoapySDRDevice_make(&results[id]);
        SoapySDRKwargsList_clear(results, length);

        if (device == NULL)
            errx(1, "Unable to open SoapySDR device: %s", SoapySDRDevice_lastError());
    }

    /* Check supported formats: prefer CS8, then CF32, then CS16 */
    formats = SoapySDRDevice_getStreamFormats(device, SOAPY_SDR_RX, 0, &num_formats);
    sample_mode = 2;  /* CS16 fallback */
    for (size_t i = 0; i < num_formats; ++i) {
        if (strcmp(formats[i], SOAPY_SDR_CS8) == 0) {
            sample_mode = 0;
            break;
        }
        if (strcmp(formats[i], SOAPY_SDR_CF32) == 0)
            sample_mode = 1;
    }
    SoapySDRStrings_clear(&formats, num_formats);

    if (verbose) {
        const char *fmt_name[] = { "CS8", "CF32", "CS16" };
        fprintf(stderr, "SoapySDR: using %s format\n", fmt_name[sample_mode]);
    }

    /* Query max sample rate if user didn't specify one */
    if (samp_rate == 0 || samp_rate == 2400000) {
        size_t num_ranges = 0;
        SoapySDRRange *ranges = SoapySDRDevice_getSampleRateRange(
            device, SOAPY_SDR_RX, 0, &num_ranges);
        if (ranges && num_ranges > 0) {
            double max_rate = ranges[num_ranges - 1].maximum;
            if (verbose)
                fprintf(stderr, "SoapySDR: max sample rate: %.3f MHz\n",
                        max_rate / 1e6);
            /* Cap at 10 MHz -- higher is overkill for L-band */
            if (max_rate > 10e6)
                max_rate = 10e6;
            if (samp_rate < max_rate)
                samp_rate = max_rate;
        }
        free(ranges);
    }

    if (SoapySDRDevice_setSampleRate(device, SOAPY_SDR_RX, 0, samp_rate) != 0)
        errx(1, "Unable to set SoapySDR sample rate: %s", SoapySDRDevice_lastError());

    fprintf(stderr, "SoapySDR: sample rate: %.3f MHz\n", samp_rate / 1e6);

    if (SoapySDRDevice_setFrequency(device, SOAPY_SDR_RX, 0, center_freq, NULL) != 0)
        errx(1, "Unable to set SoapySDR frequency: %s", SoapySDRDevice_lastError());

    /* List available gain elements in verbose mode */
    if (verbose) {
        size_t num_gains = 0;
        char **gains = SoapySDRDevice_listGains(device, SOAPY_SDR_RX, 0, &num_gains);
        if (gains && num_gains > 0) {
            fprintf(stderr, "SoapySDR: available gain elements:");
            for (size_t i = 0; i < num_gains; ++i) {
                SoapySDRRange r = SoapySDRDevice_getGainElementRange(
                    device, SOAPY_SDR_RX, 0, gains[i]);
                fprintf(stderr, " %s[%.0f-%.0f]", gains[i], r.minimum, r.maximum);
            }
            fprintf(stderr, "\n");
        }
        SoapySDRStrings_clear(&gains, num_gains);
    }

    /* Disable AGC before setting gain -- SDRplay devices require this */
    if (SoapySDRDevice_hasGainMode(device, SOAPY_SDR_RX, 0)) {
        SoapySDRDevice_setGainMode(device, SOAPY_SDR_RX, 0, false);
        if (verbose)
            fprintf(stderr, "SoapySDR: disabled AGC for manual gain control\n");
    }

    if (soapy_gain_elem_count > 0) {
        for (int i = 0; i < soapy_gain_elem_count; ++i) {
            if (SoapySDRDevice_setGainElement(device, SOAPY_SDR_RX, 0,
                    soapy_gain_elem_names[i], soapy_gain_elem_vals[i]) != 0) {
                warnx("Unable to set SoapySDR gain element %s=%.1f",
                      soapy_gain_elem_names[i], soapy_gain_elem_vals[i]);
            } else if (verbose) {
                fprintf(stderr, "SoapySDR: set gain %s=%.1f dB\n",
                        soapy_gain_elem_names[i], soapy_gain_elem_vals[i]);
            }
        }
    } else {
        if (SoapySDRDevice_setGain(device, SOAPY_SDR_RX, 0, soapy_gain_val) != 0) {
            if (verbose)
                warnx("Unable to set SoapySDR gain (continuing anyway)");
        }
    }

    if (SoapySDRDevice_setBandwidth(device, SOAPY_SDR_RX, 0, samp_rate) != 0) {
        if (verbose)
            warnx("Unable to set SoapySDR bandwidth (continuing anyway)");
    }

    return device;
}

/* Apply bias tee and custom device settings after stream activation */
static void soapy_apply_settings(SoapySDRDevice *device) {
    if (bias_tee) {
        size_t num_settings = 0;
        SoapySDRArgInfo *settings = SoapySDRDevice_getSettingInfo(device, &num_settings);
        int found = 0;
        if (!settings) num_settings = 0;
        for (size_t i = 0; i < num_settings; ++i) {
            if (strstr(settings[i].key, "bias") && strstr(settings[i].key, "rx")) {
                SoapySDRDevice_writeSetting(device, settings[i].key, "true");
                if (verbose)
                    fprintf(stderr, "SoapySDR: enabled bias tee via %s\n", settings[i].key);
                found = 1;
                break;
            }
        }
        if (!found) {
            for (size_t i = 0; i < num_settings; ++i) {
                if (strstr(settings[i].key, "bias") &&
                    !strstr(settings[i].key, "tx")) {
                    SoapySDRDevice_writeSetting(device, settings[i].key, "true");
                    if (verbose)
                        fprintf(stderr, "SoapySDR: enabled bias tee via %s\n",
                                settings[i].key);
                    found = 1;
                    break;
                }
            }
        }
        for (size_t i = 0; i < num_settings; ++i)
            SoapySDRArgInfo_clear(&settings[i]);
        free(settings);
        if (!found && verbose)
            warnx("No bias tee setting found for this SoapySDR device");
    }

    for (int i = 0; i < soapy_setting_count; ++i) {
        if (SoapySDRDevice_writeSetting(device, soapy_setting_keys[i],
                                        soapy_setting_vals[i]) != 0) {
            if (verbose)
                warnx("Unable to set SoapySDR setting %s=%s (continuing anyway)",
                      soapy_setting_keys[i], soapy_setting_vals[i]);
        } else if (verbose) {
            fprintf(stderr, "SoapySDR: set %s=%s\n",
                    soapy_setting_keys[i], soapy_setting_vals[i]);
        }
    }
}

static void soapy_cs16_to_float(int16_t *in, float *out, size_t num_samples) {
    for (size_t i = 0; i < num_samples * 2; ++i)
        out[i] = in[i] * (1.0f / 32768.0f);
}

void *soapy_stream_thread(void *arg) {
    SoapySDRDevice *device = (SoapySDRDevice *)arg;
    SoapySDRStream *stream;
    size_t channel = 0;
    int flags;
    long long time_ns;
    const char *format;
    size_t mtu;

    if (sample_mode == 0) {
        format = SOAPY_SDR_CS8;
        stream = SoapySDRDevice_setupStream(device, SOAPY_SDR_RX, format,
                                             &channel, 1, NULL);
        if (stream == NULL) {
            if (verbose)
                warnx("CS8 stream failed, trying CF32");
            sample_mode = 1;
        }
    } else {
        stream = NULL;
    }

    if (stream == NULL && sample_mode == 1) {
        format = SOAPY_SDR_CF32;
        stream = SoapySDRDevice_setupStream(device, SOAPY_SDR_RX, format,
                                             &channel, 1, NULL);
        if (stream == NULL) {
            if (verbose)
                warnx("CF32 stream failed, falling back to CS16");
            sample_mode = 2;
        }
    }

    if (stream == NULL) {
        format = SOAPY_SDR_CS16;
        stream = SoapySDRDevice_setupStream(device, SOAPY_SDR_RX, format,
                                             &channel, 1, NULL);
        if (stream == NULL)
            errx(1, "Unable to setup SoapySDR stream: %s", SoapySDRDevice_lastError());
    }

    if (verbose)
        fprintf(stderr, "SoapySDR: streaming with %s format\n", format);

    mtu = SoapySDRDevice_getStreamMTU(device, stream);
    if (mtu == 0)
        mtu = 65536;

    if (SoapySDRDevice_activateStream(device, stream, 0, 0, 0) != 0)
        errx(1, "Unable to activate SoapySDR stream: %s", SoapySDRDevice_lastError());

    /* Apply settings after stream activation (SDRPlay compatibility) */
    soapy_apply_settings(device);

    int16_t *cs16_buf = NULL;
    if (sample_mode == 2) {
        cs16_buf = malloc(mtu * 2 * sizeof(int16_t));
        if (cs16_buf == NULL)
            errx(1, "Unable to allocate CS16 buffer");
    }

    size_t sample_size = (sample_mode == 0) ? 2 * sizeof(int8_t)
                                            : 2 * sizeof(float);

    while (running) {
        sample_buf_t *s = malloc(sizeof(*s) + mtu * sample_size);
        if (s == NULL) {
            warnx("Unable to allocate sample buffer");
            break;
        }

        void *buffs[1];
        int ret;

        if (sample_mode == 2) {
            buffs[0] = cs16_buf;
            ret = SoapySDRDevice_readStream(device, stream, buffs, mtu,
                                             &flags, &time_ns, 100000);
            if (ret > 0)
                soapy_cs16_to_float(cs16_buf, (float *)s->samples, ret);
        } else if (sample_mode == 1) {
            buffs[0] = s->samples;
            ret = SoapySDRDevice_readStream(device, stream, buffs, mtu,
                                             &flags, &time_ns, 100000);
        } else {
            buffs[0] = s->samples;
            ret = SoapySDRDevice_readStream(device, stream, buffs, mtu,
                                             &flags, &time_ns, 100000);
        }

        if (ret < 0) {
            if (ret == SOAPY_SDR_TIMEOUT) {
                free(s);
                continue;
            }
            if (ret == SOAPY_SDR_OVERFLOW) {
                if (verbose)
                    warnx("SoapySDR overflow");
                free(s);
                continue;
            }
            warnx("SoapySDR read error: %d", ret);
            free(s);
            break;
        }

        s->format = (sample_mode == 0) ? SAMPLE_FMT_INT8 : SAMPLE_FMT_FLOAT;
        s->num = ret;
        s->hw_timestamp_ns = (time_ns > 0) ? (uint64_t)time_ns : 0;
        if (running)
            push_samples(s);
        else
            free(s);
    }

    free(cs16_buf);

    SoapySDRDevice_deactivateStream(device, stream, 0, 0);
    SoapySDRDevice_closeStream(device, stream);

    running = 0;
    kill(self_pid, SIGINT);

    return NULL;
}

void soapy_close(SoapySDRDevice *device) {
    SoapySDRDevice_unmake(device);
}
