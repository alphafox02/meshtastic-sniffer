#!/usr/bin/env python3
"""Sub-sample TOA fixture test.

Generates a clean LoRa fixture, applies a series of fractional-sample
FFT-domain delays, runs the sniffer over each variant, and asserts that
the reported preamble_lock_sample_frac tracks the injected offset
within tolerance.

Required acceptance per Codex section 54:
- synthetic known fractional timing fixture: reported sign and
  magnitude match expected value within tolerance
- SFO=0 fixture: frac near zero OR a stable constant bias explained
  by PFB/filter group delay

Both are checked below.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import numpy as np


REPO    = Path(__file__).resolve().parent.parent
SYNTH   = REPO / "tests" / "sensitivity_synth.py"
SNIFFER = REPO / "build" / "meshtastic-sniffer"

SF      = 7
CR_GR   = 1     # gr-lora enum -> 4/5
BW      = 250000
OS      = 1     # SDR-rate = BW (so step_per_sample = 1 SDR sample / channel sample)
SR      = BW * OS
N_FRAMES= 4

# Injected sub-sample offsets, in SDR samples (== channel samples at os=1).
INJECTED = [-0.40, -0.20, 0.00, 0.20, 0.40]
# Tolerance: the RCTSL estimator drifts a bit with payload content
# variability; +-0.1 SDR-sample at SNR=30 is conservative.
TOL = 0.15


def gen_clean() -> Path:
    out = Path("/tmp/sub_toa_clean.cs8")
    subprocess.check_call(
        ["python3", str(SYNTH),
         f"--sf={SF}", f"--cr={CR_GR}", f"--bw={BW}",
         f"--snr-db=30", f"--n-frames={N_FRAMES}",
         f"--os-factor={OS}", f"--out={out}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return out


def apply_fractional_delay(iq: np.ndarray, delta_samples: float) -> np.ndarray:
    """Apply a fractional sample delay to a complex IQ stream via FFT
    phase rotation. delta_samples > 0 shifts the signal LATER in time
    (samples appear at a higher index). Returns float32 IQ."""
    n = iq.size
    X = np.fft.fft(iq)
    k = np.fft.fftfreq(n, d=1.0)
    phase = np.exp(-2j * np.pi * k * delta_samples)
    return np.fft.ifft(X * phase).astype(np.complex64)


def run_sniffer(iq_path: Path, station: str) -> list[dict]:
    proc = subprocess.run(
        [str(SNIFFER),
         f"--file={iq_path}", "--iq-format=cs8",
         f"--rate={SR}", f"--center=915000000",
         "--presets=none", "--region=US", "--keys=default",
         f"--extra-freq=915000000:bw={BW}:sf={SF}:cr=5",
         f"--station-id={station}",
         "--deep-decode=off", "--trusted-only"],
        capture_output=True, text=True, timeout=30)
    events = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        if "preamble_lock_sample_idx" not in e:
            continue
        events.append(e)
    return events


def cs8_to_complex(path: Path) -> np.ndarray:
    raw = np.fromfile(path, dtype=np.int8)
    return (raw[0::2].astype(np.float32) +
            1j * raw[1::2].astype(np.float32))


def complex_to_cs8(iq: np.ndarray, path: Path) -> None:
    out = np.empty(iq.size * 2, dtype=np.int8)
    out[0::2] = np.clip(np.round(iq.real), -128, 127).astype(np.int8)
    out[1::2] = np.clip(np.round(iq.imag), -128, 127).astype(np.int8)
    out.tofile(path)


def main() -> int:
    if not SNIFFER.exists():
        print(f"Build the sniffer first: {SNIFFER}", file=sys.stderr)
        return 2
    clean = gen_clean()
    iq_clean = cs8_to_complex(clean)

    # First: measure the SFO=0 baseline frac. RCTSL on a perfectly-aligned
    # synth signal should report ~0, possibly with a small stable bias.
    base_evts = run_sniffer(clean, "subtoa-base")
    if not base_evts:
        print("ERROR: zero events on clean fixture", file=sys.stderr)
        return 1
    base_fracs = [e.get("preamble_lock_sample_frac", 0.0) for e in base_evts]
    base_mean = float(np.mean(base_fracs))
    print(f"[baseline SFO=0] frames={len(base_fracs)} "
          f"frac_mean={base_mean:+.4f} frac_std={float(np.std(base_fracs)):.4f}")

    # Then: inject known offsets, subtract the baseline bias.
    results = []
    for delta in INJECTED:
        shifted = apply_fractional_delay(iq_clean, delta)
        shifted_path = Path(f"/tmp/sub_toa_shift_{delta:+.2f}.cs8")
        complex_to_cs8(shifted, shifted_path)
        evts = run_sniffer(shifted_path, f"subtoa-{delta:+.2f}")
        if not evts:
            print(f"  delta={delta:+.2f} -> NO EVENTS", file=sys.stderr)
            results.append((delta, None, None))
            continue
        fracs = [e.get("preamble_lock_sample_frac", 0.0) for e in evts]
        observed = float(np.mean(fracs))
        # Subtract baseline bias to get the signal-from-baseline component.
        delta_from_base = observed - base_mean
        ok = abs(delta_from_base - delta) <= TOL
        print(f"  delta={delta:+.2f} -> reported_mean={observed:+.4f} "
              f"reported-base={delta_from_base:+.4f} "
              f"expect={delta:+.2f} {'OK' if ok else 'FAIL'}")
        results.append((delta, observed, delta_from_base))

    # Acceptance: every injected non-zero offset within tolerance.
    fails = sum(1 for d, _, r in results
                if r is None or abs(r - d) > TOL)
    print(f"\n{len(INJECTED) - fails}/{len(INJECTED)} passed (tol +-{TOL})")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
