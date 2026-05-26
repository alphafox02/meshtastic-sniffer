#!/usr/bin/env python3
"""Cross-check meshtastic-sniffer against gr-lora_sdr on a recorded .cs8 capture.

Runs both decoders on the same IQ file, extracts distinct CRC-valid
(from, packet_id) tuples from each, and prints MATCH / MISSING / EXTRA.

MATCH    -- both decoders produced a CRC-valid frame with this (from, packet_id)
MISSING  -- gr-lora_sdr decoded it; meshtastic-sniffer did not  (sensitivity gap)
EXTRA    -- meshtastic-sniffer decoded it; gr-lora_sdr did not  (we caught more, or false positive)

A fixture can list expected_packet_ids. If set, the script enforces every
expected ID appears in both sides' CRC-valid sets and exits non-zero
otherwise -- this is what turns the gr-lora cross-check into a durable
regression fixture.

Usage:
    tests/gr_lora_diff.py b205_cluster2
    tests/gr_lora_diff.py --capture=/tmp/foo.cs8 --rate=20000000 \\
        --center=915000000 --channel-freq=906875000 --bw=250000 --sf=9
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GR_LORA = REPO / "tools" / "gr_lora_usrp_rx.py"
SNIFFER = REPO / "build" / "meshtastic-sniffer"


@dataclass
class Fixture:
    name: str
    capture: str
    rate: int
    center: int
    channel_freq: int
    bw: int
    sf: int
    os_factor: int = 4
    region: str = "US"
    presets: str = "all"
    keys: str = "default"
    # Set this to enforce a known-good acceptance fixture.
    expected_packet_ids: set[int] = field(default_factory=set)


# First acceptance fixture: matches gr-lora_sdr 4-of-4 on the b205 cluster
# capture after the chirp-ref reset fix (commit b528a60).
FIXTURES: dict[str, Fixture] = {
    "b205_cluster2": Fixture(
        name="b205_cluster2",
        capture="/tmp/b205_cluster2.cs8",
        rate=20_000_000,
        center=915_000_000,
        channel_freq=906_875_000,
        bw=250_000,
        sf=9,
        expected_packet_ids={0x6cad1c34, 0x7e5dd49a, 0xaafd23bc, 0xac0f0c29},
    ),
    # Other captures from the same session. expected_packet_ids left empty
    # until we have a confirmed gr-lora ground truth on each.
    "b205_loop": Fixture(
        name="b205_loop",
        capture="/tmp/b205_loop.cs8",
        rate=20_000_000,
        center=915_000_000,
        channel_freq=906_875_000,
        bw=250_000,
        sf=9,
    ),
    "b205_ab": Fixture(
        name="b205_ab",
        capture="/tmp/b205_ab.cs8",
        rate=20_000_000,
        center=915_000_000,
        channel_freq=906_875_000,
        bw=250_000,
        sf=9,
    ),
    "b205": Fixture(
        name="b205",
        capture="/tmp/b205.cs8",
        rate=20_000_000,
        center=915_000_000,
        channel_freq=906_875_000,
        bw=250_000,
        sf=9,
    ),
}


# Meshtastic radio header layout: 4B to | 4B from | 4B packet_id | 1B flags |
# 1B channel | 2B reserved, all little-endian.
GR_RX_LINE = re.compile(
    r"gr-rx:\s+crc=(?P<crc>ok|fail|unknown)\s+has_crc=\S+\s+cr=\S+\s+err=\S+\s+len=(?P<len>\d+)\s+payload=(?P<hex>[0-9a-fA-F]+)"
)


def parse_gr_lora_output(text: str) -> set[tuple[str, int]]:
    """Return distinct CRC-ok (from, packet_id) tuples from gr_lora_usrp_rx.py output."""
    out: set[tuple[str, int]] = set()
    for line in text.splitlines():
        m = GR_RX_LINE.search(line)
        if not m or m.group("crc") != "ok":
            continue
        payload = bytes.fromhex(m.group("hex"))
        if len(payload) < 12:
            continue
        frm = int.from_bytes(payload[4:8], "little")
        pid = int.from_bytes(payload[8:12], "little")
        out.add((f"!{frm:08x}", pid))
    return out


def parse_sniffer_output(text: str) -> set[tuple[str, int]]:
    """Return distinct CRC-pass (from, packet_id) tuples from meshtastic-sniffer JSON."""
    out: set[tuple[str, int]] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not ev.get("payload_crc_ok"):
            continue
        frm = ev.get("from")
        pid = ev.get("packet_id")
        if frm is None or pid is None:
            continue
        out.add((frm, int(pid)))
    return out


def collect_slots_from_jsonl(text: str) -> dict[tuple[int, int, int], dict]:
    """Group sniffer JSONL events by (freq_hz, bw_hz, sf). Each value is a dict
    with pass / fail event counts and the distinct (from, packet_id) tuples
    observed on that slot."""
    slots: dict[tuple[int, int, int], dict] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        freq = ev.get("freq_hz")
        bw = ev.get("bw_hz")
        sf = ev.get("sf")
        if not freq or not bw or not sf:
            continue
        key = (int(freq), int(bw), int(sf))
        s = slots.setdefault(key, {"pass": 0, "fail": 0, "pass_ids": set(), "fail_ids": set()})
        frm = ev.get("from")
        pid = ev.get("packet_id")
        crc = ev.get("payload_crc_ok")
        # Some events have no has_crc (implicit-header); skip those for this audit.
        if crc is True:
            s["pass"] += 1
            if frm and pid is not None:
                s["pass_ids"].add((frm, int(pid)))
        elif crc is False:
            s["fail"] += 1
            if frm and pid is not None:
                s["fail_ids"].add((frm, int(pid)))
    return slots


def run(cmd: list[str], stdout_path: Path, stderr_path: Path, timeout: float) -> int:
    """Run a subprocess with output redirected to files."""
    with open(stdout_path, "wb") as so, open(stderr_path, "wb") as se:
        try:
            return subprocess.run(cmd, stdout=so, stderr=se, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            # File replay should finish on EOF; if it didn't, treat as ok-ish
            # and let the caller decide based on captured output.
            return 124


def run_gr_lora(fix: Fixture, work: Path, timeout: float) -> set[tuple[str, int]]:
    out = work / "gr_lora.txt"
    err = work / "gr_lora.err"
    cmd = [
        sys.executable, str(GR_LORA),
        "--source=file",
        f"--in={fix.capture}",
        "--in-format=cs8",
        f"--rate={fix.rate}",
        f"--center={fix.center}",
        f"--channel-freq={fix.channel_freq}",
        f"--bw={fix.bw}",
        f"--sf={fix.sf}",
        "--sync-word=ignore",
        "--gr-cr=1",
        f"--os-factor={fix.os_factor}",
    ]
    print(f"[gr-lora] {' '.join(shlex.quote(c) for c in cmd)}", file=sys.stderr)
    rc = run(cmd, out, err, timeout)
    print(f"[gr-lora] exit={rc} stdout={out.stat().st_size}B stderr={err.stat().st_size}B", file=sys.stderr)
    return parse_gr_lora_output(out.read_text(errors="replace"))


def run_sniffer(fix: Fixture, work: Path, timeout: float) -> set[tuple[str, int]]:
    out = work / "sniffer.jsonl"
    err = work / "sniffer.err"
    cmd = [
        str(SNIFFER),
        f"--file={fix.capture}",
        "--iq-format=cs8",
        f"--rate={fix.rate}",
        f"--center={fix.center}",
        f"--presets={fix.presets}",
        f"--region={fix.region}",
        f"--keys={fix.keys}",
    ]
    print(f"[sniffer] {' '.join(shlex.quote(c) for c in cmd)}", file=sys.stderr)
    rc = run(cmd, out, err, timeout)
    print(f"[sniffer] exit={rc} stdout={out.stat().st_size}B stderr={err.stat().st_size}B", file=sys.stderr)
    return parse_sniffer_output(out.read_text(errors="replace"))


def fmt_set(s: set[tuple[str, int]]) -> str:
    if not s:
        return "  (none)"
    return "\n".join(f"  {frm}  0x{pid:08x}  ({pid})" for frm, pid in sorted(s))


def run_from_jsonl(args) -> int:
    """For every (freq, bw, sf) slot that had at least one CRC-fail event in
    the supplied sniffer JSONL, run gr-lora_sdr against the IQ recording at
    that slot. Print what each side decoded."""
    if not args.capture or not args.rate or not args.center:
        print("--from-jsonl requires --capture, --rate, --center", file=sys.stderr)
        return 2
    jsonl_path = Path(args.from_jsonl)
    if not jsonl_path.exists():
        print(f"jsonl not found: {jsonl_path}", file=sys.stderr)
        return 2
    if not Path(args.capture).exists():
        print(f"capture not found: {args.capture}", file=sys.stderr)
        return 2
    slots = collect_slots_from_jsonl(jsonl_path.read_text(errors="replace"))
    fail_slots = sorted(
        ((k, v) for k, v in slots.items() if v["fail"] > 0),
        key=lambda kv: (-kv[1]["fail"], kv[0]),
    )
    if not fail_slots:
        print("no CRC-fail slots found in jsonl")
        return 0
    workroot = Path(args.workdir or f"/tmp/gr_lora_diff_jsonl_{Path(args.capture).stem}")
    workroot.mkdir(parents=True, exist_ok=True)
    print(f"=== {len(fail_slots)} CRC-fail slot(s) from {jsonl_path} ===")
    print(f"  capture       : {args.capture}")
    print(f"  workroot      : {workroot}")
    rc_total = 0
    for (freq, bw, sf), counts in fail_slots:
        fix = Fixture(
            name=f"f{freq}_bw{bw}_sf{sf}",
            capture=args.capture,
            rate=args.rate, center=args.center,
            channel_freq=freq, bw=bw, sf=sf,
            os_factor=args.os_factor,
        )
        work = workroot / fix.name
        work.mkdir(parents=True, exist_ok=True)
        gr_set = run_gr_lora(fix, work, args.timeout)
        print()
        print(f"  slot {freq/1e6:.3f} MHz, BW {bw/1e3:g} kHz, SF{sf}")
        print(f"    sniffer:  pass={counts['pass']} fail={counts['fail']}  "
              f"distinct_pass={len(counts['pass_ids'])} distinct_fail={len(counts['fail_ids'])}")
        print(f"    gr-lora:  distinct CRC-ok={len(gr_set)}")
        sn_pass_set = counts["pass_ids"]
        sn_fail_set = counts["fail_ids"]
        missing = gr_set - sn_pass_set
        recovered = gr_set & sn_fail_set
        if missing:
            print(f"    MISSING (gr-lora got CRC-ok we didn't decode):")
            for frm, pid in sorted(missing):
                tag = " (we had CRC-fail copy)" if (frm, pid) in recovered else ""
                print(f"      {frm}  0x{pid:08x}{tag}")
            rc_total = 1
        else:
            print(f"    OK: every gr-lora CRC-ok also CRC-passed our decoder")
    print()
    return rc_total


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("fixture", nargs="?", default=None,
                   help=f"Named fixture: {', '.join(FIXTURES)}")
    p.add_argument("--capture", help="IQ file path (overrides fixture)")
    p.add_argument("--rate", type=int, help="Sample rate")
    p.add_argument("--center", type=int, help="Center frequency")
    p.add_argument("--channel-freq", type=int, help="LoRa slot center frequency")
    p.add_argument("--bw", type=int, help="LoRa bandwidth")
    p.add_argument("--sf", type=int, help="LoRa spreading factor")
    p.add_argument("--region", default=None)
    p.add_argument("--presets", default=None)
    p.add_argument("--keys", default=None)
    p.add_argument("--timeout", type=float, default=600.0,
                   help="Per-decoder timeout in seconds (default 600)")
    p.add_argument("--workdir", default=None,
                   help="Where to keep raw subprocess output (default: /tmp/gr_lora_diff_<fixture>)")
    p.add_argument("--no-strict", action="store_true",
                   help="Do not enforce expected_packet_ids from the fixture")
    p.add_argument("--skip-gr-lora", action="store_true",
                   help="Skip gr-lora_sdr (use cached gr_lora.txt in workdir)")
    p.add_argument("--skip-sniffer", action="store_true",
                   help="Skip meshtastic-sniffer (use cached sniffer.jsonl in workdir)")
    p.add_argument("--from-jsonl",
                   help="Path to a prior sniffer JSONL feed. The script reads every "
                        "(freq_hz, bw_hz, sf) slot that produced at least one "
                        "CRC-fail event, then runs gr-lora_sdr against the IQ "
                        "recording at each such slot. Requires --capture, --rate, --center.")
    p.add_argument("--os-factor", type=int, default=4,
                   help="gr-lora_sdr oversample factor (default 4)")
    args = p.parse_args()

    if args.from_jsonl:
        return run_from_jsonl(args)

    if args.fixture and args.fixture in FIXTURES:
        fix = FIXTURES[args.fixture]
    elif args.capture and args.rate and args.center and args.channel_freq and args.bw and args.sf:
        fix = Fixture(
            name=args.fixture or Path(args.capture).stem,
            capture=args.capture,
            rate=args.rate, center=args.center,
            channel_freq=args.channel_freq,
            bw=args.bw, sf=args.sf,
        )
    else:
        p.error("specify a known fixture name, or all of --capture/--rate/--center/--channel-freq/--bw/--sf")

    if args.region: fix.region = args.region
    if args.presets: fix.presets = args.presets
    if args.keys: fix.keys = args.keys

    work = Path(args.workdir or f"/tmp/gr_lora_diff_{fix.name}")
    work.mkdir(parents=True, exist_ok=True)

    if not Path(fix.capture).exists():
        print(f"capture not found: {fix.capture}", file=sys.stderr)
        return 2
    if not SNIFFER.exists():
        print(f"meshtastic-sniffer binary not built at {SNIFFER}", file=sys.stderr)
        return 2
    if not GR_LORA.exists():
        print(f"gr-lora cross-check tool missing: {GR_LORA}", file=sys.stderr)
        return 2

    if args.skip_gr_lora:
        gr_set = parse_gr_lora_output((work / "gr_lora.txt").read_text(errors="replace"))
    else:
        gr_set = run_gr_lora(fix, work, args.timeout)
    if args.skip_sniffer:
        sn_set = parse_sniffer_output((work / "sniffer.jsonl").read_text(errors="replace"))
    else:
        sn_set = run_sniffer(fix, work, args.timeout)

    match   = gr_set & sn_set
    missing = gr_set - sn_set
    extra   = sn_set - gr_set

    print()
    print(f"=== gr-lora_sdr vs meshtastic-sniffer on {fix.name} ===")
    print(f"  capture       : {fix.capture}")
    print(f"  slot          : {fix.channel_freq/1e6:.3f} MHz, BW {fix.bw/1e3:g} kHz, SF{fix.sf}")
    print(f"  gr-lora       : {len(gr_set)} distinct CRC-ok")
    print(f"  sniffer       : {len(sn_set)} distinct CRC-pass")
    print(f"  MATCH ({len(match)}):")
    print(fmt_set(match))
    print(f"  MISSING ({len(missing)})   (gr-lora got but we didn't):")
    print(fmt_set(missing))
    print(f"  EXTRA ({len(extra)})     (we got but gr-lora didn't):")
    print(fmt_set(extra))
    print(f"  workdir       : {work}")

    rc = 0
    if missing:
        rc = 1

    if fix.expected_packet_ids and not args.no_strict:
        gr_ids = {pid for _, pid in gr_set}
        sn_ids = {pid for _, pid in sn_set}
        miss_gr = fix.expected_packet_ids - gr_ids
        miss_sn = fix.expected_packet_ids - sn_ids
        print()
        print(f"  acceptance    : {len(fix.expected_packet_ids)} known packet IDs")
        if miss_gr:
            print(f"  FAIL: gr-lora_sdr did not decode: {', '.join(f'0x{p:08x}' for p in sorted(miss_gr))}")
            rc = 1
        if miss_sn:
            print(f"  FAIL: meshtastic-sniffer did not decode: {', '.join(f'0x{p:08x}' for p in sorted(miss_sn))}")
            rc = 1
        if not miss_gr and not miss_sn:
            print(f"  OK: all {len(fix.expected_packet_ids)} known packet IDs decoded by both")

    return rc


if __name__ == "__main__":
    sys.exit(main())
