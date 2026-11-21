#!/bin/bash
# Offline tests for the transmit path (no HackRF, no gnuradio needed).
# Usage: tests/tx/run_tests.sh [/path/to/meshtastic-sniffer]   (or: make check_tx)
# Needs: gcc, python3, openssl CLI + libssl-dev. Node.js optional (JS checks).
# Exits non-zero if any check fails.
set -u
T="$(cd "$(dirname "$0")" && pwd)"
R="$(cd "${1:-$T/../..}" && pwd)"
B="$(mktemp -d /tmp/txtest.XXXXXX)"
trap 'rm -rf "$B"' EXIT
mkdir -p "$B/fakebin"
status=0

# Run a check, show only its non-"ok" lines, remember a failure. stderr
# (the tool's progress log) is shown only when the check fails.
run() {
    local out rc
    out="$("$@" 2>"$B/stderr.log")"; rc=$?
    printf '%s\n' "$out" | grep -vE "^ok" || true
    if [ $rc -ne 0 ]; then
        echo "!! failed (exit $rc): $*"; tail -20 "$B/stderr.log"; status=1
    fi
}
build() {
    if ! "$@"; then echo "!! build failed: $*"; status=1; return 1; fi
}

echo "### 1. frames from meshtastic_tx.py decode in the sniffer's C decoder"
if build gcc -std=gnu11 -O1 -I"$R" -o "$B/decode_harness" "$T/decode_harness.c" \
    "$R/mesh_packet.c" "$R/keyset.c" "$R/meshtastic.c" "$R/protobuf.c" "$R/recover/stubs.c" \
    "$R/pki.c" -lcrypto -lpthread -lm; then
    run python3 "$T/frame_test.py" "$R" "$B/decode_harness"
fi

echo "### 1b. TX/RX parity: tool's presets, regions, slots, hashes, ppm == receiver's"
if build gcc -std=gnu11 -Wall -Wextra -O1 -I"$R" -o "$B/params_check" "$T/params_check.c" \
    "$R/keyset.c" "$R/meshtastic.c" "$R/mesh_packet.c" "$R/protobuf.c" "$R/recover/stubs.c" \
    -lcrypto -lpthread -lm; then
    run python3 "$T/params_check.py" "$R/tools/meshtastic_tx.py" "$B/params_check"
fi

echo "### 1c. public-key DMs: pki.c vs the firmware's crypto test vectors"
if build gcc -std=gnu11 -Wall -Wextra -O1 -I"$R" -o "$B/test_pki" "$T/test_pki.c" "$R/pki.c" \
    "$R/mesh_packet.c" "$R/keyset.c" "$R/meshtastic.c" "$R/protobuf.c" "$R/recover/stubs.c" \
    -lcrypto -lpthread -lm; then
    run "$B/test_pki"
fi

echo "### 1d. built-in C engine: frames + IQ == tools/meshtastic_tx.py, symbols == gr-lora_sdr"
if build gcc -std=gnu11 -O2 -I"$R" -o "$B/mesh_tx_harness" "$T/mesh_tx_harness.c" "$R/mesh_tx.c" \
    "$R/lora_tx.c" "$R/lora.c" "$R/pki.c" "$R/meshtastic.c" -lfftw3f -lcrypto -lm -lpthread; then
    run python3 "$T/mesh_tx_check.py" "$R" "$B/mesh_tx_harness"
fi
if python3 -c "from gnuradio import lora_sdr; import numpy" 2>/dev/null; then
    if build gcc -std=gnu11 -O2 -I"$R" -o "$B/lora_tx_harness" "$T/lora_tx_harness.c" "$R/lora_tx.c" \
        "$R/lora.c" -lfftw3f -lm -lpthread; then
        run python3 "$T/lora_tx_check.py" "$B/lora_tx_harness"
    fi
else
    echo "(gr-lora_sdr not importable: symbol check against gr-lora_sdr skipped)"
fi

echo "### 2. POST /api/tx + C2 tx_send handler (tx.c), fallback + inline HackRF modes"
cat > "$B/fakebin/hackrf_transfer" <<'SH'
#!/bin/bash
echo "$*" >> "$HT_LOG"
while [ $# -gt 0 ]; do [ "$1" = "-t" ] && { [ -s "$2" ] || exit 9; }; shift; done
exit "${HT_RC:-0}"
SH
chmod +x "$B/fakebin/hackrf_transfer"
export PATH="$B/fakebin:$PATH" REAL_TOOL="$R/tools/meshtastic_tx.py"
export FAKE_LOG="$B/tool_argv.log" HT_LOG="$B/hackrf_transfer.log"
for variant in fallback inline; do
  defs=""; [ "$variant" = inline ] && defs="-DHAVE_HACKRF"
  echo "-- $variant"
  if build gcc -std=gnu11 -Wall -Wextra -O1 $defs -I"$R" -o "$B/test_tx_$variant" \
      "$T/test_tx.c" "$R/c2.c" "$R/meshtastic.c" "$R/pki.c" "$R/mesh_tx.c" "$R/lora_tx.c" "$R/lora.c" \
      -lfftw3f -lcrypto -lpthread -lm; then
    run "$B/test_tx_$variant" "$T/tool_wrapper.py"
  fi
done

echo "### 3. dashboard JS"
run python3 "$T/extract_js.py" "$R/web.c" "$B"
if command -v node >/dev/null; then
  run node -e "new Function(require('fs').readFileSync('$B/script0.js','utf8')); console.log('JS syntax OK')"
  run node "$T/js_tx_test.js" "$B/script0.js"
else
  echo "(node not installed: skipped JS checks)"
fi

echo "### 4. real modulation round trip: gr-lora_sdr TX -> sniffer RX, every preset"
BIN="${SNIFFER_BIN:-$R/build/meshtastic-sniffer}"
if ! python3 -c "from gnuradio import lora_sdr; import numpy, cryptography" 2>/dev/null; then
    echo "(gr-lora_sdr/numpy/cryptography not importable: skipped)"
elif [ ! -x "$BIN" ]; then
    echo "(no sniffer binary at $BIN; build first or set SNIFFER_BIN: skipped)"
else
    run bash "$T/round_trip.sh" "$R" "$BIN"
fi

echo "### 5. Android data path: sniffer as a library, samples pushed via --external-source"
if [ -n "${EXT_SRC_TEST:-}" ] && [ -x "$EXT_SRC_TEST" ]; then
    run "$EXT_SRC_TEST"
else
    echo "(test_ext_src not built: run through make check_tx)"
fi

[ $status -eq 0 ] && echo "### all TX tests passed" || echo "### TX tests FAILED"
exit $status
