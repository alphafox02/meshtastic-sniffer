#!/usr/bin/env bash
# PFB cross-bin leakage probe.
#
# Generates one synthetic SF9/BW250 LoRa frame at 20 Msps, mixes it
# onto a known Meshtastic 250 kHz grid slot, replays through the live
# pipeline as if it were an SDR capture, and counts how many slot
# decoders fired on this single RF event.
#
# Expected (with a correctly-isolating polyphase filter): one slot
# (the target frequency's bin) fires. Up to a few adjacent slots may
# fire due to filter rolloff -- a healthy adjacent-channel rejection
# of 40+ dB would keep adjacent-bin decoder activity well below the
# preamble detector's above_floor threshold.
#
# 2026-05-25 baseline: one synthetic frame at 915.125 MHz caused 79
# of 80 MediumFast slot decoders to fire on a noiseless input.
# Important interpretation: this is NOT "PFB rejection is broken."
# The companion test_pfb_bin_power probe measured an actual filter
# rolloff -3.6 dB at adjacent bins down to -37 dB at the band edges
# -- a clean, monotonic Hamming-windowed sinc shape, math correct.
# What breaks is the LoRa decoder's preamble admission policy:
# noiseless coherent leakage at -37 dB still produces a clean
# peak-vs-bin-floor inside the dechirped FFT and locks the state
# machine. With realistic AWGN at 15 dB target SNR, only 10 slots
# fire (mostly bin-adjacent) and the feed has 0 CRC-fail phantoms.
#
# So the failure mode is strong-signal-close-range specific. The
# right fix is a pre-demod energy gate (drop samples whose RMS is
# well below the expected signal level), not a heavier PFB filter.
# The Tier-3 dedup rule (b7c7e42) protects the published feed in
# the meantime. This script reproduces the noiseless boundary case.
#
# Usage: tests/pfb_slot_leakage.sh
#
# Copyright (c) 2026 CEMAXECUTER LLC
# SPDX-License-Identifier: GPL-3.0-or-later

set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/build/meshtastic-sniffer"
GEN="$REPO/tools/gen_meshtastic_iq.py"
[ -x "$BIN" ] || { echo "build the sniffer first" >&2; exit 1; }

WORK="$(mktemp -d -t pfb-leak-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# Generate wideband synthetic centered at DC.
python3 "$GEN" --out "$WORK/synth_dc.cf32" --text "SLOTSWP" \
    --channel LongFast --sf 9 --cr 5 --bw 250000 --samp-rate 20000000 \
    > "$WORK/gen.log" 2>&1 || { cat "$WORK/gen.log"; exit 1; }

# Shift to +125 kHz (= Meshtastic 250 kHz grid slot 52 at US, freq
# 915.125 MHz when SDR center is 915 MHz) and quantize to cs8.
python3 - <<PY > "$WORK/shift.log"
import numpy as np
cf = np.fromfile('$WORK/synth_dc.cf32', dtype=np.complex64)
n = np.arange(len(cf), dtype=np.float64)
mix = np.exp(1j * 2 * np.pi * 125_000 * n / 20_000_000).astype(np.complex64)
shifted = cf * mix
peak = max(np.max(np.abs(shifted)), 1e-9)
scaled = shifted / peak * 0.7
i8 = np.empty((len(scaled), 2), dtype=np.int8)
i8[:, 0] = np.clip(np.round(np.real(scaled) * 127), -128, 127).astype(np.int8)
i8[:, 1] = np.clip(np.round(np.imag(scaled) * 127), -128, 127).astype(np.int8)
i8.tofile('$WORK/synth_at_915.125.cs8')
print(f"peak={peak:.3f} bytes={i8.nbytes}")
PY

# Replay through sniffer with dedup trace enabled so we can count
# unique slots that fired.
MESHTASTIC_DEBUG_DEDUP_TRACE=1 "$BIN" \
    --file="$WORK/synth_at_915.125.cs8" --iq-format=cs8 \
    --rate=20000000 --center=915000000 \
    --presets=all --region=US --keys=default --station-id=pfb-leak \
    > "$WORK/run.log" 2>&1

n_replicas=$(grep -c "^\[dedup\] slot=" "$WORK/run.log")
n_unique_slots=$(grep "^\[dedup\] slot=" "$WORK/run.log" | grep -oE "slot=[0-9]+" | sort -u | wc -l)
slot_min=$(grep "^\[dedup\] slot=" "$WORK/run.log" | grep -oE "slot=[0-9]+" | awk -F= '{print $2}' | sort -n | head -1)
slot_max=$(grep "^\[dedup\] slot=" "$WORK/run.log" | grep -oE "slot=[0-9]+" | awk -F= '{print $2}' | sort -n | tail -1)

echo "=== PFB slot-leakage probe: 1 synthetic SF9/BW250 frame at 915.125 MHz ==="
echo "  total replicas entering dedup:  $n_replicas"
echo "  unique channelizer slots fired: $n_unique_slots"
echo "  slot range:                     $slot_min .. $slot_max"
echo
echo "  per-SF preamble lock counts (from demod-stats):"
grep -E "preamble_locks|header_checksum_pass|payload_crc_pass" "$WORK/run.log" | head -3

if [ "$n_unique_slots" -le 3 ]; then
    echo
    echo "  PASS: <=3 slots fired (target + adjacent rolloff)"
    exit 0
else
    echo
    echo "  FAIL: $n_unique_slots slots fired on one RF event."
    echo "  This is the PFB inter-bin rejection bug. A clean PFB should"
    echo "  produce <=3 slot decoder activities for a single in-bin TX."
    exit 1
fi
