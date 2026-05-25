#!/usr/bin/env bash
# CFO sweep regression test.
#
# Generates a long (188-byte) synthetic LoRa frame at SF11/CR4-5/BW250 and
# feeds it to the decoder through test_oversample_self with deliberate
# carrier offsets in [-15 kHz, +15 kHz]. Acceptance: every offset's
# payload_crc_pass counter must be 1.
#
# Today (pre-fix) the matrix is asymmetric: positive CFO passes cleanly,
# negative CFO fails at the header checksum. This script is the
# deterministic guardrail the negative-CFO sign fix is judged against.
#
# Usage:
#   tests/cfo_sweep.sh
#   tests/cfo_sweep.sh --keep    # keep the generated cf32 for inspection
#
# Copyright (c) 2026 CEMAXECUTER LLC
# SPDX-License-Identifier: GPL-3.0-or-later

set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TOOL="$REPO/build/test_oversample_self"
GEN="$REPO/tools/gen_meshtastic_iq.py"

[ -x "$TOOL" ] || { echo "build test_oversample_self first: $TOOL missing" >&2; exit 1; }
[ -f "$GEN"  ] || { echo "tools/gen_meshtastic_iq.py missing" >&2; exit 1; }

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

WORK="$(mktemp -d -t cfo-sweep-XXXXXX)"
trap 'if [ "$KEEP" = 0 ]; then rm -rf "$WORK"; else echo "kept: $WORK"; fi' EXIT

# 167-char ASCII text -> 172 byte ciphertext (varint length encoding) +
# 16-byte radio header = 188 byte LoRa payload. Long enough to exercise
# multi-block payload decode (~175 symbols at SF11/CR5) but short enough
# to keep the test fast.
TEXT="$(python3 - <<'PY'
parts = []
parts.append('HEAD-')
parts.append(''.join(chr(0x41 + i % 26) for i in range(40)))
parts.append('-MID1-')
parts.append(''.join(chr(0x30 + i % 10) for i in range(40)))
parts.append('-MID2-')
parts.append(''.join(chr(0x61 + i % 26) for i in range(40)))
parts.append('-T@!#$%^&*()_+=[]{}|;,./?-')
parts.append('END~')
print(''.join(parts), end='')
PY
)"

# Generate the synthetic cf32 at samp_rate = 4 * BW = 1 MHz so test_
# oversample_self can feed it with --no-ddc at os=4.
echo "cfo-sweep: generating 188-byte SF11/CR5/BW250 synthetic at 4*BW=1Msps..."
python3 "$GEN" --out "$WORK/synth.cf32" --text "$TEXT" --channel LongFast \
    --sf 11 --cr 5 --bw 250000 --samp-rate 1000000 > "$WORK/gen.log" 2>&1 \
    || { echo "gen_meshtastic_iq.py failed:"; cat "$WORK/gen.log"; exit 1; }

# Sweep CFO from -15k..+15k in 5 kHz steps. The current pre-fix matrix
# is asymmetric (positives pass, negatives fail at header); a CFO sign
# fix must make this matrix symmetric.
CFOS=(-15000 -10000 -5000 0 5000 10000 15000)

declare -i fail_count=0
declare -i pass_count=0
echo
printf "  %10s | %4s %4s %4s %4s %12s\n" "CFO_Hz" "lock" "hdr" "crc+" "crc-" "status"
echo   "  ---------------------------------------------------------"
for cfo in "${CFOS[@]}"; do
    out="$WORK/run_${cfo}.log"
    "$TOOL" --file="$WORK/synth.cf32" --fmt=cf32 --rate=1000000 --no-ddc \
        --bw=250000 --sf=11 --cr=5 --os=4 --duration=0 \
        --cfo="$cfo" > /dev/null 2> "$out"
    # Parse the SF11 column (index 5 of the 6 SF columns, 1-based field 6
    # after the stage name). Atomic counter columns are aligned %10llu.
    lock=$(awk '/preamble_locks/        { print $6 }' "$out")
    hdr=$(awk  '/header_checksum_pass/  { print $6 }' "$out")
    crcp=$(awk '/payload_crc_pass/      { print $6 }' "$out")
    crcf=$(awk '/payload_crc_fail/      { print $6 }' "$out")
    : "${lock:=?}"; : "${hdr:=?}"; : "${crcp:=?}"; : "${crcf:=?}"
    if [ "$crcp" = "1" ] && [ "$crcf" = "0" ]; then
        status="PASS"; pass_count+=1
    else
        status="FAIL"; fail_count+=1
    fi
    printf "  %10d | %4s %4s %4s %4s %12s\n" "$cfo" "$lock" "$hdr" "$crcp" "$crcf" "$status"
done
echo
echo "  summary: ${pass_count} pass / ${fail_count} fail out of ${#CFOS[@]}"
if [ "$fail_count" -eq 0 ]; then
    echo "  CFO sweep is SYMMETRIC: -15k..+15k all decode."
    exit 0
else
    echo "  CFO sweep is ASYMMETRIC; sign bug still present."
    exit 1
fi
