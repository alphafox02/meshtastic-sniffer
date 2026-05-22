#!/usr/bin/env bash
# A/B regression harness for the channelizer.
#
# Usage: tests/ab_replay.sh <iq-file> <rate-hz> <center-hz> [<presets>]
#
# Runs the sniffer twice over the same IQ file with different
# environments and asserts both produce the same frame-event set
# (sorted, ignoring SNR fluctuations and timestamp jitter that the
# threading might reorder).
#
# Defaults: --presets=all so the heaviest config is exercised.
#
# Exit 0 if outputs match; non-zero on divergence.

set -eu

IQ="${1:?IQ file path required}"
RATE="${2:?sample rate Hz required}"
CENTER="${3:?center freq Hz required}"
PRESETS="${4:-all}"

if [ ! -r "$IQ" ]; then
    echo "iq file not readable: $IQ" >&2
    exit 1
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/build/meshtastic-sniffer"

if [ ! -x "$BIN" ]; then
    echo "build the sniffer first: $BIN not found" >&2
    exit 1
fi

OUT_A="/tmp/ab-replay-A.jsonl"
OUT_B="/tmp/ab-replay-B.jsonl"

# Detect IQ format from filename extension. .cs8 = ci8, .cf32 = cf32.
case "$IQ" in
    *.cs8)  IQ_FMT=cs8 ;;
    *.cf32) IQ_FMT=cf32 ;;
    *)      IQ_FMT=cs8 ;;
esac

run_one() {
    local label="$1"; shift
    local out="$1";   shift
    echo "=== $label ==="
    /usr/bin/time -f "  wall=%es cpu=%P max-rss=%MK" \
        "$BIN" --file="$IQ" --iq-format="$IQ_FMT" \
              --rate="$RATE" --center="$CENTER" \
              --presets="$PRESETS" --region=US --keys=default \
              --station-id="ab-$label" \
              "$@" \
              > "$out" 2> "$out.stderr"
    local frames
    frames=$(grep -c '"from":"!' "$out" || true)
    local decrypted
    decrypted=$(grep -c '"decrypted":true' "$out" || true)
    local final_stats
    final_stats=$(grep '\[stats\]' "$out.stderr" | tail -1)
    echo "  frames=$frames decrypted=$decrypted"
    echo "  final: $final_stats"
}

# Normalize: focus on CRC-PASSING frames only. Close-range desense
# produces bit-flipped phantom replicas whose tournament-winner is
# inherently non-deterministic across runs (the dedup drainer races
# with sample arrival; different phantoms win in different runs).
# CRC-passing frames are real, distant, deterministic -- the regression
# signal we actually care about.
#
# A frame "passes CRC" when payload_crc_ok is absent OR true.
# A frame "fails CRC" when payload_crc_ok is explicitly false.
normalize() {
    local in="$1"
    local out="$2"
    grep '"from":"!' "$in" | \
        python3 -c '
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line)
    except Exception:
        continue
    if "from" not in e:
        continue
    # Drop frames whose payload CRC failed -- these are bit-corrupted
    # phantoms whose identity is non-deterministic.
    if e.get("payload_crc_ok") is False:
        continue
    key = (
        e.get("from", ""),
        e.get("packet_id", 0),
        e.get("channel_hash", 0),
        e.get("preset", ""),
        e.get("sf", 0),
        e.get("bw_hz", 0),
        bool(e.get("decrypted", False)),
        e.get("port_name", ""),
    )
    print("\t".join(str(x) for x in key))
' | sort -u > "$out"
}

# Run A
run_one A "$OUT_A" "$@"
# Run B (same args by default; caller can override via env)
run_one B "$OUT_B" "$@"

normalize "$OUT_A" "$OUT_A.norm"
normalize "$OUT_B" "$OUT_B.norm"

A_COUNT=$(wc -l < "$OUT_A.norm")
B_COUNT=$(wc -l < "$OUT_B.norm")
echo
echo "=== Normalized frame-identity sets ==="
echo "  A: $A_COUNT unique frames"
echo "  B: $B_COUNT unique frames"

if diff -q "$OUT_A.norm" "$OUT_B.norm" >/dev/null; then
    echo "  MATCH"
    exit 0
fi

echo "  DIVERGE"
echo "--- in A but not B ---"
comm -23 "$OUT_A.norm" "$OUT_B.norm" | head -20
echo "--- in B but not A ---"
comm -13 "$OUT_A.norm" "$OUT_B.norm" | head -20
exit 1
