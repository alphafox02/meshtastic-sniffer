#!/usr/bin/env bash
# Per-Meshtastic-preset x CFO matrix.
#
# tests/all_sf_cfo_sweep.sh only covers the BW=250 kHz family. This
# script extends coverage to every Meshtastic preset, so the CFO
# fractional-cliff fix is verified across:
#
#   SHORT_TURBO    BW=500  SF=7   CR=5
#   SHORT_FAST     BW=250  SF=7   CR=5
#   SHORT_SLOW     BW=250  SF=8   CR=5
#   MEDIUM_FAST    BW=250  SF=9   CR=5
#   MEDIUM_SLOW    BW=250  SF=10  CR=5
#   LONG_FAST      BW=250  SF=11  CR=5
#   LONG_MODERATE  BW=125  SF=11  CR=8
#   LONG_SLOW      BW=125  SF=12  CR=8
#   LONG_TURBO     BW=500  SF=11  CR=8
#
# Bin width = BW / 2^SF, so a CFO injection of (frac * bin_width)
# tests the receiver's behavior at a known fractional bin offset.
#
# Exits 0 if every (preset, cfo_frac) cell decodes (CRC pass exactly 1,
# CRC fail 0). Exits 1 if any cell fails.

set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TOOL="$REPO/build/test_oversample_self"
GEN="$REPO/tools/gen_meshtastic_iq.py"
[ -x "$TOOL" ] || { echo "build test_oversample_self first" >&2; exit 1; }

WORK="$(mktemp -d -t presetcfo-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

OS=4
TEXT="HEAD-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
FRACS=(0 0.10 0.20 0.30 0.35 0.40 0.45)

# preset_name BW SF CR
PRESETS=(
    "SHORT_TURBO    500000  7   5"
    "SHORT_FAST     250000  7   5"
    "SHORT_SLOW     250000  8   5"
    "MEDIUM_FAST    250000  9   5"
    "MEDIUM_SLOW    250000  10  5"
    "LONG_FAST      250000  11  5"
    "LONG_MODERATE  125000  11  8"
    "LONG_SLOW      125000  12  8"
    "LONG_TURBO     500000  11  8"
)

# Compute the SF column in demod-stats output. SF7..SF12 -> columns 2..7
# (column 1 is the stage name).
sf_col() { echo $(( $1 - 7 + 2 )); }

# How wide to format the preset name column.
pad=15

echo
printf "  %-${pad}s | %4s/%-2s |" "preset" "BW" "SF"
printf " bin_Hz |"
for fr in "${FRACS[@]}"; do printf " %+6s |" "+${fr}"; done
echo
printf "  %-${pad}s | %4s/%-2s | %6s |" "" "" "" ""
for fr in "${FRACS[@]:1}"; do printf " %+6s |" "-${fr}"; done
echo
echo "  ----------------+---------+--------+$(printf -- "--------+%.0s" "${FRACS[@]}")"

any_fail=0

for spec in "${PRESETS[@]}"; do
    read -r NAME BW SF CR <<<"$spec"
    SAMP_RATE=$((OS * BW))
    BIN_HZ=$(python3 -c "print(int($BW / 2**$SF))")

    # Generate one synthetic per preset.
    OUT="$WORK/synth_${NAME}.cf32"
    python3 "$GEN" --out "$OUT" --text "$TEXT" --channel LongFast \
        --sf "$SF" --cr "$CR" --bw "$BW" --samp-rate "$SAMP_RATE" \
        > "$WORK/gen_${NAME}.log" 2>&1 \
        || { echo "gen failed for $NAME"; cat "$WORK/gen_${NAME}.log"; exit 1; }

    col=$(sf_col "$SF")

    # --no-sfo-inference: pure CFO sweep with no matching SFO. Without
    # it the decoder would derive sfo_hat from injected CFO under the
    # same-crystal assumption (correct for real radio, wrong for this
    # synthetic CFO-only injection).
    # Positive side
    printf "  %-${pad}s | %4d/%-2d | %6d |" "$NAME" "$BW" "$SF" "$BIN_HZ"
    for fr in "${FRACS[@]}"; do
        cfo=$(python3 -c "print(int(round($fr * $BIN_HZ)))")
        out=$("$TOOL" --file="$OUT" --fmt=cf32 --rate="$SAMP_RATE" --no-ddc \
            --bw="$BW" --sf="$SF" --cr="$CR" --os="$OS" --duration=0 \
            --no-sfo-inference \
            --cfo="$cfo" 2>&1)
        crcp=$(echo "$out" | awk -v c="$col" '/payload_crc_pass/  { print $c }')
        crcf=$(echo "$out" | awk -v c="$col" '/payload_crc_fail/  { print $c }')
        if [ "${crcp:-0}" = "1" ] && [ "${crcf:-0}" = "0" ]; then
            printf "   OK   |"
        else
            printf "  FAIL  |"
            any_fail=1
        fi
    done
    echo
    # Negative side
    printf "  %-${pad}s | %4s/%-2s | %6s |" "" "" "" ""
    for fr in "${FRACS[@]:1}"; do
        cfo=$(python3 -c "print(-int(round($fr * $BIN_HZ)))")
        out=$("$TOOL" --file="$OUT" --fmt=cf32 --rate="$SAMP_RATE" --no-ddc \
            --bw="$BW" --sf="$SF" --cr="$CR" --os="$OS" --duration=0 \
            --no-sfo-inference \
            --cfo="$cfo" 2>&1)
        crcp=$(echo "$out" | awk -v c="$col" '/payload_crc_pass/  { print $c }')
        crcf=$(echo "$out" | awk -v c="$col" '/payload_crc_fail/  { print $c }')
        if [ "${crcp:-0}" = "1" ] && [ "${crcf:-0}" = "0" ]; then
            printf "   OK   |"
        else
            printf "  FAIL  |"
            any_fail=1
        fi
    done
    echo
done
echo
if [ "$any_fail" -eq 0 ]; then
    echo "  All 9 Meshtastic presets decode at every |cfo_frac| cell."
    exit 0
else
    echo "  At least one preset/CFO cell fails -- coverage gap exposed."
    exit 1
fi
