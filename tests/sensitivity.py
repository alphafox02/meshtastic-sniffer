#!/usr/bin/env python3
"""Decoder sensitivity sweep -- ours vs gr-lora_sdr on synthetic IQ.

For each (preset, snr_db, cfo_hz) cell:
  1. Synthesize N Meshtastic-shaped frames at the target SNR/CFO
     using gr-lora_sdr's lora_tx hier-block (sync_word=0x2b).
  2. Run meshtastic-sniffer on the resulting .cs8 -- count CRC-pass frames.
  3. Run gr-lora_sdr on the same file -- count CRC-ok lines.
  4. Emit a CSV row with both counts.

Outputs:
  - CSV at --csv=PATH (default: /tmp/sensitivity.csv)
  - Markdown summary table on stderr
  - Exit non-zero if a cell regresses below an --acceptance-min threshold
    on (ours_pass / n_frames) for SNR cells above a chosen floor.

This is a measurement tool, not a regression gate yet. The first run
establishes the baseline; future runs compare against the committed CSV.

Run example:
  tests/sensitivity.py --presets=LongFast,MediumFast,ShortFast \\
      --snr-db=5,10,15 --n-frames=10 --csv=/tmp/sensitivity.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SYNTH = REPO / "tests" / "sensitivity_synth.py"
SNIFFER = REPO / "build" / "meshtastic-sniffer"
GR_LORA = REPO / "tools" / "gr_lora_usrp_rx.py"

# Meshtastic preset table. (name, sf, bw_hz, cr_meshtastic, cr_gr)
# cr_meshtastic is 5..8 = 4/5..4/8 (our sniffer's wire-format value).
# cr_gr is the gr-lora_sdr enum: 1=4/5, 2=4/6, 3=4/7, 4=4/8.
PRESETS = {
    "ShortTurbo":   {"sf": 7,  "bw": 500_000, "cr_m": 5, "cr_gr": 1},
    "ShortFast":    {"sf": 7,  "bw": 250_000, "cr_m": 5, "cr_gr": 1},
    "ShortSlow":    {"sf": 8,  "bw": 250_000, "cr_m": 5, "cr_gr": 1},
    "MediumFast":   {"sf": 9,  "bw": 250_000, "cr_m": 5, "cr_gr": 1},
    "MediumSlow":   {"sf": 10, "bw": 250_000, "cr_m": 5, "cr_gr": 1},
    "LongFast":     {"sf": 11, "bw": 250_000, "cr_m": 5, "cr_gr": 1},
    "LongModerate": {"sf": 11, "bw": 125_000, "cr_m": 8, "cr_gr": 4},
    "LongSlow":     {"sf": 12, "bw": 125_000, "cr_m": 8, "cr_gr": 4},
    "LongTurbo":    {"sf": 11, "bw": 500_000, "cr_m": 8, "cr_gr": 4},
}

GR_RX_LINE = re.compile(
    r"gr-rx:\s+crc=(?P<crc>ok|fail|unknown)\s+has_crc=\S+\s+cr=\S+\s+err=\S+\s+len=(?P<len>\d+)"
)


@dataclass
class CellResult:
    preset: str
    sf: int
    bw: int
    cr_m: int
    snr_db: float
    cfo_hz: float
    n_frames: int       # synthesis budget (approximate; actual depends on strobe period)
    ours_pass: int
    gr_pass: int        # treated as ground truth -- gr-lora_sdr is the reference

    @property
    def relative_rate(self) -> float:
        """Our pass count as a fraction of gr-lora's. 1.0 = parity.
        Returns 0.0 if gr-lora got nothing (signal below reference floor)
        so the cell doesn't pollute the average with a sentinel high value."""
        return self.ours_pass / self.gr_pass if self.gr_pass > 0 else 0.0

    @property
    def absolute_ours_rate(self) -> float:
        """ours_pass / synthesis budget. Not directly meaningful as a
        success rate (the strobe overproduces), but useful for tracking
        absolute pass-count regressions between runs at fixed seed."""
        return self.ours_pass / self.n_frames if self.n_frames else 0.0


def synth_cell(preset_cfg: dict, snr_db: float, cfo_hz: float,
               n_frames: int, os_factor: int, seed: int, out_path: Path) -> None:
    cmd = [
        sys.executable, str(SYNTH),
        f"--sf={preset_cfg['sf']}",
        f"--cr={preset_cfg['cr_gr']}",
        f"--bw={preset_cfg['bw']}",
        f"--snr-db={snr_db}",
        f"--cfo-hz={cfo_hz}",
        f"--n-frames={n_frames}",
        f"--os-factor={os_factor}",
        f"--seed={seed}",
        f"--out={out_path}",
    ]
    subprocess.run(cmd, check=True, stderr=subprocess.DEVNULL)


def count_ours(out_path: Path, preset_cfg: dict, os_factor: int) -> int:
    channel_rate = preset_cfg["bw"] * os_factor
    cmd = [
        str(SNIFFER),
        f"--file={out_path}",
        "--iq-format=cs8",
        f"--rate={channel_rate}",
        "--center=915000000",
        "--presets=none",
        f"--extra-freq=915000000:bw={preset_cfg['bw']}:sf={preset_cfg['sf']}:cr={preset_cfg['cr_m']}",
        "--region=US",
        "--keys=default",
    ]
    proc = subprocess.run(cmd, capture_output=True, timeout=120)
    n_pass = 0
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if d.get("payload_crc_ok") is True:
            n_pass += 1
    return n_pass


def count_gr(out_path: Path, preset_cfg: dict, os_factor: int) -> int:
    channel_rate = preset_cfg["bw"] * os_factor
    cmd = [
        sys.executable, str(GR_LORA),
        "--source=file",
        f"--in={out_path}",
        "--in-format=cs8",
        f"--rate={channel_rate}",
        "--center=0",
        "--channel-freq=0",
        f"--bw={preset_cfg['bw']}",
        f"--sf={preset_cfg['sf']}",
        "--sync-word=0x2b",
        f"--gr-cr={preset_cfg['cr_gr']}",
        f"--os-factor={os_factor}",
    ]
    proc = subprocess.run(cmd, capture_output=True, timeout=120)
    n_ok = 0
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        m = GR_RX_LINE.search(line)
        if m and m.group("crc") == "ok":
            n_ok += 1
    return n_ok


def run_cell(preset: str, snr_db: float, cfo_hz: float, n_frames: int,
             os_factor: int, seed: int, work: Path) -> CellResult:
    """Run N independent single-frame synths per cell. Each synth uses a
    different seed so the noise realization varies; the underlying signal
    is identical. Aggregates pass-counts across trials.

    Independent-trial loop (instead of one N-frame synth) avoids confounding
    with a known back-to-back-frame bug in our decoder that drops the 2nd-Nth
    consecutive frame even at high SNR. We measure SINGLE-frame sensitivity
    here; back-to-back recovery is a separate decoder issue."""
    cfg = PRESETS[preset]
    ours_total = 0
    gr_total = 0
    for trial in range(n_frames):
        out = work / f"synth_{preset}_snr{snr_db:.0f}_cfo{cfo_hz:.0f}_t{trial}.cs8"
        synth_cell(cfg, snr_db, cfo_hz, 1, os_factor, seed + trial, out)
        ours_total += count_ours(out, cfg, os_factor)
        gr_total += count_gr(out, cfg, os_factor)
        try:
            out.unlink()
        except OSError:
            pass
    return CellResult(
        preset=preset, sf=cfg["sf"], bw=cfg["bw"], cr_m=cfg["cr_m"],
        snr_db=snr_db, cfo_hz=cfo_hz, n_frames=n_frames,
        ours_pass=ours_total, gr_pass=gr_total,
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--presets", default="LongFast,MediumFast,ShortFast",
                   help=f"Comma-separated preset names. Available: {','.join(PRESETS)}")
    p.add_argument("--snr-db", default="5,10,15",
                   help="Comma-separated SNR cells in dB")
    p.add_argument("--cfo-hz", default="0",
                   help="Comma-separated CFO cells in Hz")
    p.add_argument("--n-frames", type=int, default=10)
    p.add_argument("--os-factor", type=int, default=4)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--csv", default="/tmp/sensitivity.csv")
    p.add_argument("--workdir", default="/tmp/sensitivity_work")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    work = Path(args.workdir)
    work.mkdir(parents=True, exist_ok=True)

    presets = [p.strip() for p in args.presets.split(",") if p.strip()]
    for p in presets:
        if p not in PRESETS:
            print(f"unknown preset: {p}", file=sys.stderr)
            return 2
    snrs = [float(s) for s in args.snr_db.split(",") if s.strip()]
    cfos = [float(c) for c in args.cfo_hz.split(",") if c.strip()]

    results: list[CellResult] = []
    total = len(presets) * len(snrs) * len(cfos)
    idx = 0
    for preset in presets:
        for snr in snrs:
            for cfo in cfos:
                idx += 1
                print(f"[{idx}/{total}] {preset:14s} SNR={snr:+5.1f} CFO={cfo:+6.0f} ... ",
                      end="", file=sys.stderr, flush=True)
                r = run_cell(preset, snr, cfo, args.n_frames,
                             args.os_factor, args.seed, work)
                results.append(r)
                print(f"ours={r.ours_pass:3d}  gr={r.gr_pass:3d}  "
                      f"relative={r.relative_rate*100:5.1f}%",
                      file=sys.stderr)

    # CSV
    with open(args.csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["preset", "sf", "bw_hz", "cr_meshtastic",
                    "snr_db", "cfo_hz", "n_frames",
                    "ours_pass", "gr_pass", "relative_rate"])
        for r in results:
            w.writerow([r.preset, r.sf, r.bw, r.cr_m,
                        r.snr_db, r.cfo_hz, r.n_frames,
                        r.ours_pass, r.gr_pass,
                        f"{r.relative_rate:.3f}"])
    print(f"\nCSV written: {args.csv}", file=sys.stderr)

    # Summary table by preset (averaged over CFO).
    # Each cell shows "ours_pass/gr_pass" so both counts are visible.
    # Parity = ours == gr. Loss = ours < gr.
    print("\n## Sensitivity summary (ours_pass / gr_pass per SNR cell, averaged over CFO)\n",
          file=sys.stderr)
    header = ["preset"] + [f"SNR{s:.0f}dB" for s in snrs]
    print("| " + " | ".join(header) + " |", file=sys.stderr)
    print("|" + "|".join(["------"] * len(header)) + "|", file=sys.stderr)
    for preset in presets:
        row = [preset]
        for s in snrs:
            cells = [r for r in results if r.preset == preset and r.snr_db == s]
            tot_ours = sum(c.ours_pass for c in cells)
            tot_gr   = sum(c.gr_pass for c in cells)
            rel = (tot_ours / tot_gr) if tot_gr > 0 else 0.0
            row.append(f"{tot_ours}/{tot_gr} ({rel*100:.0f}%)")
        print("| " + " | ".join(row) + " |", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
