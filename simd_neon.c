/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (c) 2026 CEMAXECUTER LLC
 *
 * ARM NEON SIMD kernel implementations.
 *
 * Compiled on AArch64 only. NEON is mandatory on AArch64 -- it is part of
 * the base ISA, not an optional extension. No -mfpu=neon flag is needed.
 * Include <arm_neon.h> and the compiler emits SIMD instructions directly.
 *
 * Register model: float32x4_t holds 4 x float32 = 128 bits = 2 complex
 * samples (interleaved re/im layout). This is identical in width to SSE's
 * __m128, so all kernels vectorize at the same granularity as the SSE4.2
 * tier -- with the bonus of hardware-native FMA (vfmaq_f32) on every core.
 *
 * Key differences from x86:
 *   - FMA is always available (AArch64 base ISA); no separate detection.
 *   - vdivq_f32 is a single hardware instruction (vs reciprocal estimate on ARMv7).
 *   - vuzp1q_f32 / vuzp2q_f32 deinterleave re/im cleanly without shuffles.
 *   - vmaxvq_f32 reduces a vector to its horizontal max in one instruction.
 *   - vld1q_f32 / vst1q_f32 handle alignment naturally; no _loadu_ needed.
 *
 * All functions match the signatures in simd_kernels.h exactly.
 */

#if defined(__aarch64__) || defined(_M_ARM64)

#include <arm_neon.h>
#include <complex.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "simd_kernels.h"

/* ---- Complex FIR filter (real taps * complex input) ----
 *
 * Process 2 complex outputs per iteration (float32x4_t = 2 complex values).
 * For each tap k: broadcast taps[k] to 4 lanes, load 2 complex inputs,
 * fused multiply-add into accumulator. vfmaq_f32 is mandatory on AArch64
 * (single roundoff vs separate vmulq+vaddq on SSE4.2).
 */
void neon_fir_ccf(const float *taps, int ntaps,
                  const float complex *in, float complex *out, int n) {
    const float *inp = (const float *)in;
    float *outp = (float *)out;
    int i = 0;

    for (; i + 1 < n; i += 2) {
        float32x4_t acc = vdupq_n_f32(0.0f);
        for (int k = 0; k < ntaps; k++) {
            float32x4_t coeff = vdupq_n_f32(taps[k]);
            float32x4_t data  = vld1q_f32(&inp[(i + k) * 2]);
            acc = vfmaq_f32(acc, coeff, data);
        }
        vst1q_f32(&outp[i * 2], acc);
    }

    /* Scalar tail */
    for (; i < n; i++) {
        float acc_re = 0.0f, acc_im = 0.0f;
        for (int k = 0; k < ntaps; k++) {
            acc_re += taps[k] * inp[(i + k) * 2];
            acc_im += taps[k] * inp[(i + k) * 2 + 1];
        }
        outp[i * 2]     = acc_re;
        outp[i * 2 + 1] = acc_im;
    }
}

/* ---- Decimating complex FIR ----
 *
 * vld2q_f32 deinterleaves 4 complex inputs in hardware:
 *   pair.val[0] = [re_k,  re_{k+1},  re_{k+2},  re_{k+3}]
 *   pair.val[1] = [im_k,  im_{k+1},  im_{k+2},  im_{k+3}]
 * No vdup_lane/vcombine shuffles needed.  Separate re/im accumulators give
 * two independent FMA chains.  8-tap unroll with 4 accumulators hides the
 * 4-cycle FMA latency on M3 (4 independent chains = steady-state throughput
 * limited by memory bandwidth, not latency).
 */
void neon_fir_ccf_dec(const float *taps, int ntaps,
                      const float complex *in, float complex *out,
                      int n_out, int decimation) {
    const float *inp = (const float *)in;
    float *outp = (float *)out;

    for (int i = 0; i < n_out; i++) {
        const float *p = &inp[i * decimation * 2];
        float32x4_t acc_re0 = vdupq_n_f32(0.0f);
        float32x4_t acc_im0 = vdupq_n_f32(0.0f);
        float32x4_t acc_re1 = vdupq_n_f32(0.0f);
        float32x4_t acc_im1 = vdupq_n_f32(0.0f);
        int k = 0;

        /* 8-tap main loop: 2 × vld2q + 2 × vld1q + 4 × vfmaq per iter */
        for (; k + 7 < ntaps; k += 8) {
            float32x4x2_t d0 = vld2q_f32(&p[k * 2]);
            float32x4x2_t d1 = vld2q_f32(&p[(k + 4) * 2]);
            float32x4_t   t0 = vld1q_f32(&taps[k]);
            float32x4_t   t1 = vld1q_f32(&taps[k + 4]);
            acc_re0 = vfmaq_f32(acc_re0, d0.val[0], t0);
            acc_im0 = vfmaq_f32(acc_im0, d0.val[1], t0);
            acc_re1 = vfmaq_f32(acc_re1, d1.val[0], t1);
            acc_im1 = vfmaq_f32(acc_im1, d1.val[1], t1);
        }

        /* 4-tap tail */
        for (; k + 3 < ntaps; k += 4) {
            float32x4x2_t dx = vld2q_f32(&p[k * 2]);
            float32x4_t   tx = vld1q_f32(&taps[k]);
            acc_re0 = vfmaq_f32(acc_re0, dx.val[0], tx);
            acc_im0 = vfmaq_f32(acc_im0, dx.val[1], tx);
        }

        /* Merge accumulators → scalars */
        float acc_re = vaddvq_f32(vaddq_f32(acc_re0, acc_re1));
        float acc_im = vaddvq_f32(vaddq_f32(acc_im0, acc_im1));

        /* Scalar tail (< 4 remaining taps) */
        for (; k < ntaps; k++) {
            acc_re += taps[k] * p[k * 2];
            acc_im += taps[k] * p[k * 2 + 1];
        }

        outp[i * 2]     = acc_re;
        outp[i * 2 + 1] = acc_im;
    }
}

/* ---- Real FIR filter ----
 *
 * Process 4 real outputs per iteration. For each tap: broadcast, load 4
 * consecutive input samples, FMA.
 */
void neon_fir_fff(const float *taps, int ntaps,
                  const float *in, float *out, int n) {
    int i = 0;

    for (; i + 3 < n; i += 4) {
        float32x4_t acc = vdupq_n_f32(0.0f);
        for (int k = 0; k < ntaps; k++) {
            float32x4_t coeff = vdupq_n_f32(taps[k]);
            float32x4_t data  = vld1q_f32(&in[i + k]);
            acc = vfmaq_f32(acc, coeff, data);
        }
        vst1q_f32(&out[i], acc);
    }

    /* Scalar tail */
    for (; i < n; i++) {
        float acc = 0.0f;
        for (int k = 0; k < ntaps; k++)
            acc += taps[k] * in[i + k];
        out[i] = acc;
    }
}

/* ---- Window multiply: complex * real ----
 *
 * Load 4 complex (8 floats) across two registers; load 4 window values;
 * interleave window into [w0,w0,w1,w1] and [w2,w2,w3,w3] using vzip1q/2q;
 * multiply. Processes 4 complex samples per iteration.
 */
void neon_window_cf(const float complex *samples, const float *window,
                    float complex *out, int n) {
    const float *sp = (const float *)samples;
    float *op = (float *)out;
    int i = 0;

    for (; i + 3 < n; i += 4) {
        float32x4_t a = vld1q_f32(&sp[i * 2]);      /* [re0,im0,re1,im1] */
        float32x4_t b = vld1q_f32(&sp[i * 2 + 4]);  /* [re2,im2,re3,im3] */
        float32x4_t w = vld1q_f32(&window[i]);       /* [w0, w1, w2, w3]  */

        /* Duplicate each window value into both re and im lanes */
        float32x4_t w_lo = vzip1q_f32(w, w);  /* [w0,w0,w1,w1] */
        float32x4_t w_hi = vzip2q_f32(w, w);  /* [w2,w2,w3,w3] */

        vst1q_f32(&op[i * 2],     vmulq_f32(a, w_lo));
        vst1q_f32(&op[i * 2 + 4], vmulq_f32(b, w_hi));
    }

    /* Scalar tail */
    for (; i < n; i++)
        out[i] = samples[i] * window[i];
}

/* ---- fftshift + magnitude-squared combined ----
 *
 * Input:  fft_out[0..fft_size-1] (complex)
 * Output: mag_shifted[0..fft_size-1] (float)
 *
 * mag_shifted[i]        = |fft_out[half+i]|^2   (positive freq → front)
 * mag_shifted[half+i]   = |fft_out[i]|^2         (negative freq → back)
 *
 * Process 4 complex → 4 magnitudes per half per iteration.
 * vuzp1q deinterleaves even (re) lanes, vuzp2q odd (im) lanes.
 * vfmaq_f32 computes re*re + im*im in a single fused instruction.
 */
void neon_fftshift_mag(const float complex *fft_out,
                       float *mag_shifted, int fft_size) {
    int half = fft_size / 2;
    const float *fp = (const float *)fft_out;
    int i = 0;

    for (; i + 3 < half; i += 4) {
        /* Positive freqs: fft_out[half+i .. half+i+3] */
        float32x4_t a = vld1q_f32(&fp[(half + i) * 2]);
        float32x4_t b = vld1q_f32(&fp[(half + i + 2) * 2]);
        float32x4_t re = vuzp1q_f32(a, b);  /* [re0, re1, re2, re3] */
        float32x4_t im = vuzp2q_f32(a, b);  /* [im0, im1, im2, im3] */
        vst1q_f32(&mag_shifted[i],
                  vfmaq_f32(vmulq_f32(re, re), im, im));

        /* Negative freqs: fft_out[i .. i+3] */
        float32x4_t c = vld1q_f32(&fp[i * 2]);
        float32x4_t d = vld1q_f32(&fp[(i + 2) * 2]);
        float32x4_t re_n = vuzp1q_f32(c, d);
        float32x4_t im_n = vuzp2q_f32(c, d);
        vst1q_f32(&mag_shifted[half + i],
                  vfmaq_f32(vmulq_f32(re_n, re_n), im_n, im_n));
    }

    /* Scalar tail */
    for (; i < half; i++) {
        float re, im;
        re = crealf(fft_out[half + i]);
        im = cimagf(fft_out[half + i]);
        mag_shifted[i] = re * re + im * im;

        re = crealf(fft_out[i]);
        im = cimagf(fft_out[i]);
        mag_shifted[half + i] = re * re + im * im;
    }
}

/* ---- Baseline update: sum[i] = sum[i] - old[i] + new[i] ---- */
void neon_baseline_update(float *sum, const float *old_hist,
                          const float *new_mag, int n) {
    int i = 0;
    for (; i + 3 < n; i += 4) {
        float32x4_t s = vld1q_f32(&sum[i]);
        float32x4_t o = vld1q_f32(&old_hist[i]);
        float32x4_t m = vld1q_f32(&new_mag[i]);
        vst1q_f32(&sum[i], vaddq_f32(vsubq_f32(s, o), m));
    }
    for (; i < n; i++) {
        sum[i] -= old_hist[i];
        sum[i] += new_mag[i];
    }
}

/* ---- Relative magnitude with zero check ----
 *
 * out[i] = mag[i] / baseline[i]  if baseline[i] > 0, else 0.
 *
 * vcgtq_f32 produces a bitmask (all-1s = true, all-0s = false). AND the
 * division result against it to zero out lanes where baseline was 0.
 * vdivq_f32 is a single-cycle hardware instruction on AArch64 (Cortex-A and
 * Apple Silicon alike), unlike ARMv7 which requires reciprocal iteration.
 */
void neon_relative_mag(const float *mag, const float *baseline,
                       float *out, int n) {
    float32x4_t zero = vdupq_n_f32(0.0f);
    int i = 0;
    for (; i + 3 < n; i += 4) {
        float32x4_t m    = vld1q_f32(&mag[i]);
        float32x4_t b    = vld1q_f32(&baseline[i]);
        uint32x4_t  mask = vcgtq_f32(b, zero);
        float32x4_t div  = vdivq_f32(m, b);
        float32x4_t result = vreinterpretq_f32_u32(
                                 vandq_u32(vreinterpretq_u32_f32(div), mask));
        vst1q_f32(&out[i], result);
    }
    for (; i < n; i++)
        out[i] = (baseline[i] > 0.0f) ? mag[i] / baseline[i] : 0.0f;
}

/* ---- int8 IQ pairs → float complex ----
 *
 * This is the highest-throughput kernel: called at 10 MHz on every
 * sample buffer. At 10 MSPS, 10 million IQ pairs per second must be
 * sign-extended and scaled. Processing 8 complex samples per iteration
 * (16 int8 → 16 float32 outputs) using a three-level sign-extension chain:
 *
 *   int8x16 → split → 2× int8x8 → vmovl_s8 → 2× int16x8
 *           → split each → 4× int16x4 → vmovl_s16 → 4× int32x4
 *           → vcvtq_f32_s32 + vmulq → 4× float32x4 → 64 bytes output
 *
 * The scalar fallback does the same iq[2i]/128.0f division with a loop.
 * NEON eliminates every branch and does 16 FP multiplies per iteration.
 */
void neon_convert_i8_cf(const int8_t *iq, float complex *out, size_t n) {
    float *outp = (float *)out;
    float32x4_t scale = vdupq_n_f32(1.0f / 128.0f);
    size_t i = 0;

    /* Process 8 complex samples (16 int8 values) per iteration */
    for (; i + 7 < n; i += 8) {
        int8x16_t  bytes  = vld1q_s8(&iq[i * 2]);

        /* Sign-extend lower 8 bytes to int16 */
        int16x8_t  i16_lo = vmovl_s8(vget_low_s8(bytes));
        /* Sign-extend upper 8 bytes to int16 */
        int16x8_t  i16_hi = vmovl_s8(vget_high_s8(bytes));

        /* Sign-extend int16 quads to int32 */
        int32x4_t  i32_0  = vmovl_s16(vget_low_s16(i16_lo));
        int32x4_t  i32_1  = vmovl_s16(vget_high_s16(i16_lo));
        int32x4_t  i32_2  = vmovl_s16(vget_low_s16(i16_hi));
        int32x4_t  i32_3  = vmovl_s16(vget_high_s16(i16_hi));

        /* Convert and scale → 4 groups of 4 floats = 8 complex outputs */
        vst1q_f32(&outp[i * 2],      vmulq_f32(vcvtq_f32_s32(i32_0), scale));
        vst1q_f32(&outp[i * 2 + 4],  vmulq_f32(vcvtq_f32_s32(i32_1), scale));
        vst1q_f32(&outp[i * 2 + 8],  vmulq_f32(vcvtq_f32_s32(i32_2), scale));
        vst1q_f32(&outp[i * 2 + 12], vmulq_f32(vcvtq_f32_s32(i32_3), scale));
    }

    /* Scalar tail */
    for (; i < n; i++) {
        outp[i * 2]     = iq[2 * i]     / 128.0f;
        outp[i * 2 + 1] = iq[2 * i + 1] / 128.0f;
    }
}

/* ---- Magnitude-squared of complex array ----
 *
 * Process 4 complex → 4 magnitudes per iteration.
 * vuzp1q/vuzp2q cleanly separate interleaved re/im into two vectors;
 * vfmaq_f32 computes re*re + im*im as a fused operation.
 */
void neon_mag_squared(const float complex *in, float *out, int n) {
    const float *inp = (const float *)in;
    int i = 0;

    for (; i + 3 < n; i += 4) {
        float32x4_t a  = vld1q_f32(&inp[i * 2]);      /* [re0,im0,re1,im1] */
        float32x4_t b  = vld1q_f32(&inp[i * 2 + 4]);  /* [re2,im2,re3,im3] */
        float32x4_t re = vuzp1q_f32(a, b);              /* [re0,re1,re2,re3] */
        float32x4_t im = vuzp2q_f32(a, b);              /* [im0,im1,im2,im3] */
        vst1q_f32(&out[i], vfmaq_f32(vmulq_f32(re, re), im, im));
    }

    for (; i < n; i++) {
        float re = inp[i * 2];
        float im = inp[i * 2 + 1];
        out[i] = re * re + im * im;
    }
}

/* ---- Find maximum float ----
 *
 * vmaxvq_f32 is a single AArch64 instruction that extracts the horizontal
 * maximum of all 4 lanes — no multi-step shuffle-and-compare needed.
 */
float neon_max_float(const float *in, int n) {
    float32x4_t vmax = vdupq_n_f32(-1e30f);
    int i = 0;
    for (; i + 3 < n; i += 4)
        vmax = vmaxq_f32(vmax, vld1q_f32(&in[i]));

    float max_val = vmaxvq_f32(vmax);  /* horizontal reduction, one instruction */

    for (; i < n; i++) {
        if (in[i] > max_val) max_val = in[i];
    }
    return max_val;
}

/* ---- Complex square with window: out[i] = in[i]^2 * window[i] ----
 *
 * (a + bi)^2 = (a^2 - b^2) + 2ab·i
 * Then multiply both parts by the real window value.
 *
 * Process 4 complex per iteration using vuzp (deinterleave), compute, then
 * vzip (re-interleave) back to the canonical [re,im,re,im,...] layout.
 */
void neon_csquare_window(const float complex *in, const float *window,
                         float complex *out, int n) {
    const float *inp = (const float *)in;
    float *outp = (float *)out;
    int i = 0;

    for (; i + 3 < n; i += 4) {
        float32x4_t a  = vld1q_f32(&inp[i * 2]);      /* [re0,im0,re1,im1] */
        float32x4_t b  = vld1q_f32(&inp[i * 2 + 4]);  /* [re2,im2,re3,im3] */

        float32x4_t re = vuzp1q_f32(a, b);  /* [re0,re1,re2,re3] */
        float32x4_t im = vuzp2q_f32(a, b);  /* [im0,im1,im2,im3] */

        /* sq_re = re^2 - im^2 */
        float32x4_t sq_re = vsubq_f32(vmulq_f32(re, re), vmulq_f32(im, im));

        /* sq_im = 2*re*im */
        float32x4_t sq_im = vmulq_n_f32(vmulq_f32(re, im), 2.0f);

        /* Apply window */
        float32x4_t w = vld1q_f32(&window[i]);
        sq_re = vmulq_f32(sq_re, w);
        sq_im = vmulq_f32(sq_im, w);

        /* Re-interleave: [re0,im0,re1,im1] and [re2,im2,re3,im3] */
        vst1q_f32(&outp[i * 2],     vzip1q_f32(sq_re, sq_im));
        vst1q_f32(&outp[i * 2 + 4], vzip2q_f32(sq_re, sq_im));
    }

    for (; i < n; i++) {
        float a = inp[i * 2];
        float b = inp[i * 2 + 1];
        outp[i * 2]     = (a * a - b * b) * window[i];
        outp[i * 2 + 1] = (2.0f * a * b)  * window[i];
    }
}

#endif /* __aarch64__ || _M_ARM64 */
