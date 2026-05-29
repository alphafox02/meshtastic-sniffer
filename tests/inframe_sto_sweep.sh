#!/usr/bin/env bash
# Continuous in-frame STO tracking acceptance test.
#
# At a non-zero sample-clock offset (SFO) the dechirp window drifts a
# fraction of a sample per symbol. A one-shot RCTSL sto_frac captured at
# preamble lock leaves the frame tail mis-aligned -- at SF9 / 25 ppm the
# drift reaches ~0.4 output samples by the last payload symbol, smearing
# those symbols off the bin grid. downsample_symbol folds the running
# drift accumulator (sfo_cum) into its per-symbol fine shift so the
# window tracks the drift across the whole frame.
#
# This test needs sub-sample resolution to act on, so it runs the decoder
# at os=4 (the per-symbol fine shift is quantised to 1/os output samples).
# It synthesises a 25 ppm SFO frame set with gr-lora_sdr's modulator
# (sensitivity_synth.py links SFO+CFO at the same ppm = same-crystal) and
# feeds the decoder directly with --no-ddc, isolating the decoder from the
# channelizer.
#
# Acceptance (deterministic, fixed synth seed):
#   - SF9  / 25 ppm / os=4 : crc_pass >= 8   (tracking ON = 10; OFF = 6)
#   - SF9  /  0 ppm / os=4 : crc_pass == 10  (SFO=0 inert, no regression)
#   - SF7  / 25 ppm / os=4 : crc_pass >= 9   (short-symbol broad health)
#
# Usage: tests/inframe_sto_sweep.sh [--keep]
#
# Copyright (c) 2026 CEMAXECUTER LLC
# SPDX-License-Identifier: GPL-3.0-or-later

set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TOOL="$REPO/build/test_oversample_self"
SYNTH="$REPO/tests/sensitivity_synth.py"

[ -x "$TOOL" ]  || { echo "build test_oversample_self first: $TOOL missing" >&2; exit 1; }
[ -f "$SYNTH" ] || { echo "tests/sensitivity_synth.py missing" >&2; exit 1; }

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

WORK="$(mktemp -d -t inframe-sto-XXXXXX)"
trap 'if [ "$KEEP" = 0 ]; then rm -rf "$WORK"; else echo "kept: $WORK"; fi' EXIT

# crc_pass count from the decoder's "crc_pass n=N [...]" histogram line.
crc_pass() { grep -oE 'crc_pass *n=[0-9]+' "$1" | grep -oE '[0-9]+$' | head -1; }

# synth + decode one cell. args: label sf cr bw sfo_ppm min_pass
declare -i fail_count=0
run_cell() {
    local label="$1" sf="$2" cr="$3" bw="$4" sfo="$5" min="$6"
    local rate=$((bw * 4))
    local f="$WORK/${label}.cs8" log="$WORK/${label}.log"
    python3 "$SYNTH" --sf="$sf" --cr="$cr" --bw="$bw" --snr-db=10 \
        --sfo-ppm="$sfo" --n-frames=10 --os-factor=4 --seed=42 \
        --out="$f" > "$WORK/${label}.synth.log" 2>&1 \
        || { echo "  $label: synth FAILED"; cat "$WORK/${label}.synth.log"; fail_count+=1; return; }
    "$TOOL" --file="$f" --fmt=cs8 --rate="$rate" --center=915000000 \
        --channel=915000000 --bw="$bw" --sf="$sf" --cr=$((cr+4)) --os=4 \
        --no-ddc > /dev/null 2> "$log"
    local n; n="$(crc_pass "$log")"; : "${n:=0}"
    local status="PASS"
    if [ "$n" -lt "$min" ]; then status="FAIL"; fail_count+=1; fi
    printf "  %-18s sf=%-2s sfo=%-3s os=4 : crc_pass=%-2s (need >=%s)  %s\n" \
        "$label" "$sf" "$sfo" "$n" "$min" "$status"
}

echo "in-frame STO tracking acceptance (os=4 direct, gr-lora synth):"
echo
run_cell "SF9-SFO25"  9  1 250000 25  8
run_cell "SF9-SFO0"   9  1 250000  0 10
run_cell "SF7-SFO25"  7  1 250000 25  9
echo
if [ "$fail_count" -eq 0 ]; then
    echo "  in-frame STO tracking: all cells PASS."
    exit 0
else
    echo "  in-frame STO tracking: ${fail_count} cell(s) FAILED."
    exit 1
fi
