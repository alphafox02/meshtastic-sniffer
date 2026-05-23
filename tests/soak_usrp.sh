#!/usr/bin/env bash
# Long-running stability + performance soak for the USRP path.
#
# Usage:
#   tests/soak_usrp.sh [out-dir]
#
# Defaults to /tmp/soak-<timestamp>. Launches meshtastic-sniffer against the
# B-series USRP at 26 Msps, sc8 wire format, US --presets=all. Samples
# /proc/<pid>/status every 30s into a CSV so memory/threads/fd-leak
# regressions show up as a slope. Writes a summary verdict on shutdown.
#
# Stop the run with Ctrl-C or `kill <pid>`; the wrapper traps the signal
# and sends SIGTERM to the sniffer so the worker pool prints its final
# submitted/completed/bp_waits/freebuf_waits counters on the way out.

set -u

OUT_DIR="${1:-/tmp/soak-$(date +%Y%m%dT%H%M%S)}"
mkdir -p "$OUT_DIR"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/build/meshtastic-sniffer"
[ -x "$BIN" ] || { echo "build the sniffer first: $BIN missing" >&2; exit 1; }

FRAMES="$OUT_DIR/frames.jsonl"
STDERR="$OUT_DIR/stderr.log"
PROC_CSV="$OUT_DIR/process.csv"
STATS_CSV="$OUT_DIR/stats.csv"
SUMMARY="$OUT_DIR/summary.txt"

echo "ts,rss_kb,vsz_kb,threads,open_fds" > "$PROC_CSV"

echo "soak: launching $BIN at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "soak: output dir = $OUT_DIR"

# Launch sniffer in its own process group so we can deliver SIGTERM
# cleanly to the whole tree on shutdown.
MESHTASTIC_PFB_STATS=1 \
setsid "$BIN" \
    --usrp --rate=26000000 --center=915000000 \
    --presets=all --region=US --keys=default \
    --usrp-otw=sc8 --gain=40 \
    --station-id=soak \
    > "$FRAMES" 2> "$STDERR" &
SNIFFER_PID=$!
SNIFFER_PGID=$(ps -o pgid= -p "$SNIFFER_PID" 2>/dev/null | tr -d ' ')
echo "soak: sniffer pid=$SNIFFER_PID pgid=$SNIFFER_PGID"

# Periodic /proc sampler. Stops when the sniffer is gone.
(
    while kill -0 "$SNIFFER_PID" 2>/dev/null; do
        TS=$(date +%s)
        if [ -d "/proc/$SNIFFER_PID" ]; then
            RSS=$(awk '/^VmRSS:/  {print $2}' "/proc/$SNIFFER_PID/status" 2>/dev/null)
            VSZ=$(awk '/^VmSize:/ {print $2}' "/proc/$SNIFFER_PID/status" 2>/dev/null)
            THR=$(awk '/^Threads:/{print $2}' "/proc/$SNIFFER_PID/status" 2>/dev/null)
            FDS=$(ls "/proc/$SNIFFER_PID/fd" 2>/dev/null | wc -l)
            echo "$TS,${RSS:-0},${VSZ:-0},${THR:-0},${FDS:-0}" >> "$PROC_CSV"
        fi
        sleep 30
    done
) &
MON_PID=$!

shutdown_sniffer() {
    if kill -0 "$SNIFFER_PID" 2>/dev/null; then
        echo "soak: sending SIGTERM to sniffer" >&2
        kill -TERM "-$SNIFFER_PGID" 2>/dev/null || kill -TERM "$SNIFFER_PID"
    fi
}
trap shutdown_sniffer INT TERM HUP

# Wait for sniffer (don't error if it exits cleanly).
wait "$SNIFFER_PID" 2>/dev/null
EXIT_CODE=$?
kill "$MON_PID" 2>/dev/null
wait "$MON_PID" 2>/dev/null

echo "soak: sniffer exited rc=$EXIT_CODE at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---- Post-mortem ----------------------------------------------------------
{
    echo "soak summary"
    echo "  run started:    $(awk -F, 'NR==2 {print strftime("%Y-%m-%dT%H:%M:%SZ", $1)}' "$PROC_CSV")"
    echo "  run ended:      $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "  exit code:      $EXIT_CODE"
    echo

    # Walltime
    if [ -s "$PROC_CSV" ]; then
        FIRST_TS=$(awk -F, 'NR==2 {print $1}' "$PROC_CSV")
        LAST_TS=$(awk -F, 'END   {print $1}' "$PROC_CSV")
        WALL=$((LAST_TS - FIRST_TS))
        echo "  wall seconds:   $WALL"
        echo
    fi

    echo "= memory / fd trend ="
    if [ "$(wc -l < "$PROC_CSV")" -ge 3 ]; then
        FIRST_RSS=$(awk -F, 'NR==2 {print $2}' "$PROC_CSV")
        LAST_RSS=$(awk -F,  'END   {print $2}' "$PROC_CSV")
        MAX_RSS=$(awk  -F, 'NR>1  {if ($2 > m) m=$2} END {print m}' "$PROC_CSV")
        FIRST_FDS=$(awk -F, 'NR==2 {print $5}' "$PROC_CSV")
        LAST_FDS=$(awk -F,  'END   {print $5}' "$PROC_CSV")
        FIRST_THR=$(awk -F, 'NR==2 {print $4}' "$PROC_CSV")
        LAST_THR=$(awk -F,  'END   {print $4}' "$PROC_CSV")
        echo "  RSS  start=${FIRST_RSS} KB  end=${LAST_RSS} KB  max=${MAX_RSS} KB  delta=$((LAST_RSS - FIRST_RSS)) KB"
        echo "  fds  start=${FIRST_FDS}  end=${LAST_FDS}  delta=$((LAST_FDS - FIRST_FDS))"
        echo "  thr  start=${FIRST_THR}  end=${LAST_THR}  delta=$((LAST_THR - FIRST_THR))"
        # Heuristic verdicts
        DELTA_RSS=$((LAST_RSS - FIRST_RSS))
        if [ $DELTA_RSS -gt $((FIRST_RSS / 4)) ]; then
            echo "  memory: SUSPECT (grew >25% from start) -- inspect process.csv"
        else
            echo "  memory: OK (no significant growth)"
        fi
        if [ $((LAST_FDS - FIRST_FDS)) -gt 32 ]; then
            echo "  fds: SUSPECT (grew by >32) -- inspect process.csv"
        else
            echo "  fds: OK"
        fi
        if [ $((LAST_THR - FIRST_THR)) -ne 0 ]; then
            echo "  threads: changed during run (start=$FIRST_THR end=$LAST_THR) -- worth checking"
        else
            echo "  threads: OK (constant)"
        fi
    else
        echo "  (not enough samples to derive trend; run was shorter than ~30s)"
    fi
    echo

    echo "= throughput ="
    # Parse [stats] lines: "[stats] 26.03 Msps in, 12 LoRa frames, 0 decrypted"
    grep -E "^\[stats\]" "$STDERR" | \
        awk '{
            for (i=1;i<=NF;i++) {
                if ($i=="Msps") msps=$(i-1);
                if ($i=="LoRa")  frames=$(i-1);
                if ($i=="decrypted") dec=$(i-1);
            }
            print msps, frames, dec
        }' > "$STATS_CSV.tmp"
    if [ -s "$STATS_CSV.tmp" ]; then
        echo "msps,frames_cum,decrypted_cum" > "$STATS_CSV"
        sed 's/ /,/g' "$STATS_CSV.tmp" >> "$STATS_CSV"
        rm "$STATS_CSV.tmp"
        SAMPLES=$(($(wc -l < "$STATS_CSV") - 1))
        if [ $SAMPLES -gt 0 ]; then
            MSPS_MEAN=$(awk -F, 'NR>1 {s+=$1; n++} END {printf "%.2f", s/n}' "$STATS_CSV")
            MSPS_MIN=$(awk -F,  'NR>1 {if ($1<m || m=="") m=$1} END {printf "%.2f", m}' "$STATS_CSV")
            MSPS_MAX=$(awk -F,  'NR>1 {if ($1>m)         m=$1} END {printf "%.2f", m}' "$STATS_CSV")
            LAST_FRAMES=$(awk -F, 'END {print $2}' "$STATS_CSV")
            LAST_DEC=$(awk    -F, 'END {print $3}' "$STATS_CSV")
            echo "  stats heartbeats: $SAMPLES"
            echo "  Msps  mean=$MSPS_MEAN  min=$MSPS_MIN  max=$MSPS_MAX  (target ~26.0)"
            echo "  total frames:    $LAST_FRAMES"
            echo "  total decrypted: $LAST_DEC"
            if awk -v m="$MSPS_MEAN" 'BEGIN {exit !(m+0 >= 25.5)}'; then
                echo "  throughput: OK (>=25.5 Msps sustained)"
            else
                echo "  throughput: BELOW TARGET (mean<25.5 Msps)"
            fi
        fi
    else
        echo "  (no [stats] lines parsed)"
    fi
    echo

    echo "= OOO overflow events ="
    # Count "OOOOO..." runs. Each character is a single overflow event.
    OOO_COUNT=$(grep -oE 'O+' "$STDERR" | grep -c '^O')
    OOO_CHARS=$(grep -oE 'O' "$STDERR" | wc -l)
    echo "  total O events emitted: $OOO_CHARS"
    if [ "$OOO_CHARS" -eq 0 ]; then
        echo "  ooo: OK (zero overflow)"
    else
        echo "  ooo: SAW $OOO_CHARS overflow chars -- inspect stderr.log for clustering"
    fi
    echo

    echo "= pipeline counters (MESHTASTIC_PFB_STATS) ="
    grep -E "^pfb sink pool|^sample-pump" "$STDERR" | tail -5
    SUB=$(grep -oE 'total submitted=[0-9]+'  "$STDERR" | tail -1 | grep -oE '[0-9]+')
    COMP=$(grep -oE 'completed=[0-9]+'        "$STDERR" | tail -1 | grep -oE '[0-9]+')
    BP=$(grep -oE 'queue_bp=[0-9]+'           "$STDERR" | tail -1 | grep -oE '[0-9]+')
    FBW=$(grep -oE 'freebuf_waits=[0-9]+'     "$STDERR" | tail -1 | grep -oE '[0-9]+')
    QW=$(grep -oE 'queue_waits=[0-9]+'        "$STDERR" | tail -1 | grep -oE '[0-9]+')
    PROC=$(grep -oE 'processed=[0-9]+'        "$STDERR" | tail -1 | grep -oE '[0-9]+')
    PUMP_SUB=$(grep -oE 'sample-pump: submitted=[0-9]+' "$STDERR" | tail -1 | grep -oE '[0-9]+')
    [ -n "${SUB:-}" ] && [ -n "${COMP:-}" ] && {
        if [ "$SUB" = "$COMP" ]; then echo "  sink pool drain:  OK (submitted=completed=$SUB)"
        else                          echo "  sink pool drain:  BAD ($SUB submitted vs $COMP completed; difference=$((SUB-COMP)))"
        fi
    }
    [ -n "${BP:-}" ] && {
        if [ "$BP" = "0" ]; then echo "  worker queue_bp:  OK (zero)"
        else                     echo "  worker queue_bp:  $BP wait events -- workers were pressured"
        fi
    }
    [ -n "${FBW:-}" ] && {
        if [ "$FBW" = "0" ]; then echo "  freebuf_waits:    OK (zero)"
        else                      echo "  freebuf_waits:    $FBW wait events -- sink pool ran dry at points"
        fi
    }
    [ -n "${QW:-}" ] && [ -n "${PUMP_SUB:-}" ] && [ -n "${PROC:-}" ] && {
        if [ "$PUMP_SUB" = "$PROC" ]; then echo "  sample-pump:      OK (submitted=processed=$PUMP_SUB)"
        else                               echo "  sample-pump:      submit/proc mismatch ($PUMP_SUB vs $PROC)"
        fi
        if [ "$QW" = "0" ]; then echo "  pump queue_waits: OK (zero)"
        else                     echo "  pump queue_waits: $QW backpressure events"
        fi
    }
    echo

    echo "= RF activity (JSON output) ="
    if [ -s "$FRAMES" ]; then
        TOTAL=$(grep -c '"from":' "$FRAMES" 2>/dev/null || echo 0)
        DISTINCT_FROM=$(grep -oE '"from":"[^"]+"' "$FRAMES" | sort -u | wc -l)
        DISTINCT_HASH=$(grep -oE '"channel_hash":[0-9]+' "$FRAMES" | sort -u | wc -l)
        DISTINCT_PRESET=$(grep -oE '"preset":"[^"]+"' "$FRAMES" | sort -u | wc -l)
        DECRYPTED=$(grep -c '"decrypted":true' "$FRAMES" 2>/dev/null || echo 0)
        echo "  total JSON frame events:  $TOTAL"
        echo "  distinct from= node IDs:  $DISTINCT_FROM"
        echo "  distinct channel_hash:    $DISTINCT_HASH"
        echo "  distinct preset:          $DISTINCT_PRESET"
        echo "  decrypted (key matched):  $DECRYPTED"
        if [ "$DISTINCT_FROM" -ge 1 ]; then
            echo "  rf: at least one neighbor was heard during the run"
        else
            echo "  rf: NO frames decoded -- either no nearby Meshtastic or a config problem"
        fi
    else
        echo "  (no JSONL output)"
    fi
    echo

    echo "soak: full logs under $OUT_DIR"
    echo "  process.csv   sampled every 30s"
    echo "  stats.csv     parsed throughput heartbeats"
    echo "  stderr.log    full sniffer stderr"
    echo "  frames.jsonl  raw JSON frame stream"
} | tee "$SUMMARY"

exit "$EXIT_CODE"
