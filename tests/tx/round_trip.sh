#!/bin/bash
# Real modulation round trip: tools/meshtastic_tx.py modulates with
# gr-lora_sdr, the sniffer's own demodulator decodes the IQ file. One case
# per preset (US has every preset) plus EU_868, covering every SF/BW/CR
# combination Meshtastic uses. Needs gr-lora_sdr + numpy + cryptography.
# Usage: round_trip.sh REPO_DIR SNIFFER_BINARY
R="$1"; BIN="$2"
W="$(mktemp -d /tmp/txrt.XXXXXX)"
trap 'rm -rf "$W"' EXIT
fails=0
cases="US:SHORT_TURBO US:SHORT_FAST US:SHORT_SLOW US:MEDIUM_FAST US:MEDIUM_SLOW
       US:LONG_FAST US:LONG_MODERATE US:LONG_SLOW US:LONG_TURBO EU_868:MEDIUM_FAST
       EU_433:LONG_FAST"
for c in $cases; do
    region="${c%%:*}"; preset="${c#*:}"; text="rt $region $preset"
    out="$(python3 "$R/tools/meshtastic_tx.py" --region "$region" --preset "$preset" \
           --text "$text" --dry-run --keep "$W/$c" 2>&1)"
    read -r -a verify <<< "$(printf '%s\n' "$out" | sed -n 's/.*verify: meshtastic-sniffer //p' | head -1)"
    if [ ${#verify[@]} -eq 0 ]; then
        echo "FAIL $region $preset: tool produced no IQ"; printf '%s\n' "$out" | tail -3
        fails=$((fails + 1)); continue
    fi
    got="$(timeout 180 "$BIN" "${verify[@]}" 2>/dev/null | python3 -c '
import json, sys
for line in sys.stdin:
    try: d = json.loads(line)
    except ValueError: continue
    if d.get("payload_crc_ok") and "text" in d:
        print(d["text"], "| SF%d CR4/%d BW%dk %.3f MHz" % (d["sf"], d["cr"], d["bw_hz"] // 1000,
                                                          d["freq_hz"] / 1e6)); break')"
    if [ "${got%% |*}" = "$text" ]; then
        echo "ok   $region $preset -> ${got#* | }"
    else
        echo "FAIL $region $preset: sniffer decoded '${got:-nothing}'"; fails=$((fails + 1))
    fi
done
echo "FAILS: $fails"
exit $((fails > 0))
