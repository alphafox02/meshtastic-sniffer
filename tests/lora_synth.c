/* lora_synth -- standalone LoRa preamble synthesizer (cf32).
 *
 * Emits a pure LoRa preamble (K upchirps, symbol value 0) at a configurable
 * in-band SNR, as complex float32 at the SDR sample rate, centered at the
 * channel frequency (so the preamble sits at baseband DC and routes to PFB
 * bin 0). Used to validate meshtastic-sniffer's coherent preamble detector:
 * an SNR sweep measures the detector's sensitivity gain over the single-
 * symbol 6 dB floor directly.
 *
 * Pure generator: only math.h + stdio, links nothing but libm (no FFTW, no
 * lora.c). Build via the CMake `lora_synth` target.
 *
 * Chirp phase at the SDR rate (M = os*N, os = rate/bw):
 *     phi[k] = 2*pi * (bw/rate) * (k^2/(2M) - k/2),  k = 0..M-1
 * which reduces exactly to lora.c build_chirps `phi[n] = 2*pi*(n^2/(2N) - n/2)`
 * when rate == bw (os == 1). After the channelizer decimates rate->bw (by os),
 * the surviving every-os-th sample has phase 2*pi*(m^2/(2N) - m/2) -- i.e. the
 * decoder's own reference upchirp -- so dechirp concentrates all 8 symbols in
 * one stable FFT bin and the coherent detector fires. Constant PFB
 * phase/delay shifts every symbol identically, so bin stability is preserved.
 *
 * AWGN model: "SNR" is the IN-BAND (bw-width) SNR, matching what the demod
 * measures. The signal (upchirp) has unit amplitude, so signal power = 1 per
 * sample. White complex noise at the SDR rate with per-real-component variance
 * s^2 has total per-sample variance 2*s^2 and, after ideal band-limiting to bw
 * and decimation by os, in-band per-sample variance = 2*s^2 * (bw/rate) =
 * 2*s^2/os. So in-band SNR = 1 / (2*s^2/os) = os/(2*s^2) = rho. Solving:
 *     s = sqrt(os / (2*rho)),  rho = 10^(snr_db/10)
 * i.e. sigma_real = sigma_imag = sqrt(os/(2*rho)). For the default 2 Msps /
 * 250 kHz (os=8) case this is sqrt(4/rho) = 2/sqrt(rho), i.e. the total 2 MHz
 * noise is 8x the in-band noise -- the factor-of-os headroom is what the
 * channelizer throws away, leaving the in-band SNR exactly as requested.
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* Box-Muller Gaussian, seeded for reproducibility (rand is fine here -- this
 * is a deterministic test generator, not crypto). */
static double gauss(void)
{
    double u1 = ((double)(rand() % 1000000) + 1.0) / 1000001.0;
    double u2 = ((double)(rand() % 1000000) + 1.0) / 1000001.0;
    return sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
}

static void write_cf32(FILE *fp, float re, float im)
{
    /* little-endian float32; on any little-endian host this is a raw write. */
    fwrite(&re, sizeof(float), 1, fp);
    fwrite(&im, sizeof(float), 1, fp);
}

int main(int argc, char **argv)
{
    double snr_db   = -10.0;
    const char *out = NULL;
    long   rate     = 2000000;
    int    sf       = 11;
    long   bw       = 250000;
    int    symbols  = 8;
    long   post_ms  = 30;       /* enough tail noise for the detector window to flush + arm */
    long   seed     = 1;

    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if (!strncmp(a, "--snr=",     6)) snr_db   = atof(a + 6);
        else if (!strncmp(a, "--out=",     6)) out      = a + 6;
        else if (!strncmp(a, "--rate=",    7)) rate     = atol(a + 7);
        else if (!strncmp(a, "--sf=",      5)) sf       = atoi(a + 5);
        else if (!strncmp(a, "--bw=",      5)) bw       = atol(a + 5);
        else if (!strncmp(a, "--symbols=",10)) symbols  = atoi(a + 10);
        else if (!strncmp(a, "--post=",    7)) post_ms  = atol(a + 7);
        else if (!strncmp(a, "--seed=",    7)) seed     = atol(a + 7);
        else {
            fprintf(stderr,
                "usage: lora_synth --snr=DB --out=PATH [--rate=2000000] "
                "[--sf=11] [--bw=250000] [--symbols=8] [--post=30] [--seed=1]\n"
                "\n"
                "Emits a pure LoRa preamble (K upchirps, symbol value 0) at the\n"
                "given in-band SNR. Used to validate the coherent multi-symbol\n"
                "preamble detector (MESHTASTIC_COHERENT_PREAMBLE=1):\n"
                "  - K defaults to 8 (matches detector K-window size)\n"
                "  - 1ms pre-roll noise so the K-window is not all-signal\n"
                "  - 30ms post noise so the K-window flushes the chirps\n"
                "    and the detector's refractory re-arms cleanly\n"
                "Stage-2 wire-in validation: confirm the coh fire seeds\n"
                "STATE_PREAMBLE_OK and the lock callback runs (look for\n"
                "coherent_preamble_locks + preamble_locks in the sniffer stats).\n");
            return 2;
        }
    }
    if (!out) { fprintf(stderr, "lora_synth: --out=PATH is required\n"); return 2; }
        if (sf < 7 || sf > 12) { fprintf(stderr, "lora_synth: bad sf %d\n", sf); return 2; }
    if (rate <= 0 || bw <= 0 || rate % bw != 0) {
        fprintf(stderr, "lora_synth: rate must be an integer multiple of bw\n");
        return 2;
    }

    srand((unsigned)seed);
    const int    os  = (int)(rate / bw);
    const int    N   = 1 << sf;
    const int    M   = os * N;                 /* samples per symbol at SDR rate */
    const double bws = (double)bw / (double)rate;   /* bw/rate */

    /* AWGN per-real-component std (see header): s = sqrt(os/(2*rho)). */
    double rho = pow(10.0, snr_db / 10.0);
    double s   = sqrt((double)os / (2.0 * rho));

    FILE *fp = fopen(out, "wb");
    if (!fp) { fprintf(stderr, "lora_synth: cannot open %s\n", out); return 1; }

    /* Pre-roll ~1 ms of pure noise so the detector window fills with noise
     * before the preamble arrives (realistic, and keeps the first symbol's
     * FFT honest). */
    long pre = rate / 1000;
    for (long k = 0; k < pre; ++k)
        write_cf32(fp, (float)(s * gauss()), (float)(s * gauss()));

    /* Preamble: `symbols` upchirps, symbol value 0. */
    for (int sym = 0; sym < symbols; ++sym) {
        for (int k = 0; k < M; ++k) {
            double kk = (double)k;
            double phase = 2.0 * M_PI * bws * (kk * kk / (2.0 * (double)M) - kk * 0.5);
            float re = (float)cos(phase) + (float)(s * gauss());
            float im = (float)sin(phase) + (float)(s * gauss());
            write_cf32(fp, re, im);
        }
    }

    /* post_ms of silence (noise only) so the K-window flushes the preamble
     * and the detector's refractory re-arms cleanly. Default 30 ms ~= 30
     * symbols -- plenty of headroom for K=8 window + COH_STABLE_MIN=3 ticks
     * plus extra to confirm "fire once per preamble". */
    long post = (post_ms * rate) / 1000;
    for (long k = 0; k < post; ++k)
        write_cf32(fp, (float)(s * gauss()), (float)(s * gauss()));

    fclose(fp);
    fprintf(stderr, "lora_synth: wrote %s (sf=%d bw=%ld rate=%ld os=%d "
            "symbols=%d snr=%.1f dB, sigma=%.4f)\n",
            out, sf, bw, rate, os, symbols, snr_db, s);
    return 0;
}