#!/usr/bin/env bash
# Cheap pre-coding sweep: vary MESHTASTIC_SINK_WORKERS and OMP_NUM_THREADS,
# measure sustained Msps under live B205 capture before deciding whether
# to invest in a hand-written AVX2 polyphase kernel or a different DSP
# restructure.
#
# Per cell: 60 s settle + 180 s measurement. Total 15 cells = ~62 min.
# Output: /tmp/tuning-matrix-<ts>/results.csv plus per-cell stderr/frame logs.
set -u

OUT_DIR="/tmp/tuning-matrix-$(date +%Y%m%dT%H%M%S)"
mkdir -p "$OUT_DIR"
CSV="$OUT_DIR/results.csv"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/build/meshtastic-sniffer"
[ -x "$BIN" ] || { echo "build the sniffer first: $BIN missing" >&2; exit 1; }

echo "sink_workers,omp_threads,measure_s,msps_mean,msps_min,msps_max,ooo_chars,pool_sub,pool_comp,pool_queue_bp,pool_freebuf_waits,pump_sub,pump_proc,pump_queue_waits" > "$CSV"

SINK_WORKERS=(8 10 12 14 15)
OMP_THREADS=(1 2 3)
SETTLE=60
MEASURE=180

echo "tuning-matrix: $OUT_DIR"
echo "tuning-matrix: launching $((${#SINK_WORKERS[@]} * ${#OMP_THREADS[@]})) cells; ~$(( (${#SINK_WORKERS[@]} * ${#OMP_THREADS[@]}) * (SETTLE + MEASURE + 15) / 60 )) min total"
echo

for w in "${SINK_WORKERS[@]}"; do
    for o in "${OMP_THREADS[@]}"; do
        RUN="$OUT_DIR/w${w}_o${o}"
        mkdir -p "$RUN"
        STATION="tune-w${w}o${o}"
        printf "=== sink_workers=%d omp_threads=%d  " "$w" "$o"

        MESHTASTIC_PFB_STATS=1 \
        MESHTASTIC_SINK_WORKERS=$w \
        OMP_NUM_THREADS=$o \
        setsid "$BIN" \
            --usrp --rate=26000000 --center=915000000 \
            --presets=all --region=US --keys=default \
            --usrp-otw=sc8 --gain=40 \
            --station-id="$STATION" \
            > "$RUN/frames.jsonl" 2> "$RUN/stderr.log" &
        PID=$!
        PGID=$(ps -o pgid= -p "$PID" 2>/dev/null | tr -d ' ')

        sleep "$SETTLE"
        sleep "$MEASURE"

        # Graceful TERM so worker pool + sample-pump dump stats.
        kill -TERM "-$PGID" 2>/dev/null
        for _ in $(seq 1 15); do
            pgrep -f "$STATION" >/dev/null || break
            sleep 1
        done
        pgrep -f "$STATION" >/dev/null && { echo " (KILL)"; kill -KILL "-$PGID" 2>/dev/null; }

        # Msps: parse stats heartbeats, drop the first SETTLE/5 = 12 (settle window).
        grep -oE "\[stats\] [0-9.]+ Msps" "$RUN/stderr.log" 2>/dev/null \
            | awk '{print $2}' > "$RUN/msps_all.txt"
        tail -n +13 "$RUN/msps_all.txt" > "$RUN/msps_measure.txt"
        SAMPLES=$(wc -l < "$RUN/msps_measure.txt")
        if [ "$SAMPLES" -gt 0 ]; then
            MEAN=$(awk '{s+=$1; n++} END {printf "%.2f", s/n}' "$RUN/msps_measure.txt")
            MIN=$(awk  'NR==1 {m=$1} {if ($1<m) m=$1} END {printf "%.2f", m}' "$RUN/msps_measure.txt")
            MAX=$(awk  'NR==1 {m=$1} {if ($1>m) m=$1} END {printf "%.2f", m}' "$RUN/msps_measure.txt")
        else
            MEAN=0.00; MIN=0.00; MAX=0.00
        fi

        OOO=$(grep -oE 'O' "$RUN/stderr.log" 2>/dev/null | wc -l)

        # Pool counters
        POOL_LINE=$(grep 'pfb sink pool:' "$RUN/stderr.log" | tail -1)
        POOL_SUB=$(echo "$POOL_LINE"  | grep -oE 'total submitted=[0-9]+' | grep -oE '[0-9]+')
        POOL_COMP=$(echo "$POOL_LINE" | grep -oE 'completed=[0-9]+'       | grep -oE '[0-9]+')
        POOL_BP=$(echo "$POOL_LINE"   | grep -oE 'queue_bp=[0-9]+'        | grep -oE '[0-9]+')
        POOL_FBW=$(echo "$POOL_LINE"  | grep -oE 'freebuf_waits=[0-9]+'   | grep -oE '[0-9]+')

        # Pump counters
        PUMP_LINE=$(grep 'sample-pump:' "$RUN/stderr.log" | tail -1)
        PUMP_SUB=$(echo "$PUMP_LINE"  | grep -oE 'submitted=[0-9]+'   | grep -oE '[0-9]+')
        PUMP_PROC=$(echo "$PUMP_LINE" | grep -oE 'processed=[0-9]+'   | grep -oE '[0-9]+')
        PUMP_QW=$(echo "$PUMP_LINE"   | grep -oE 'queue_waits=[0-9]+' | grep -oE '[0-9]+')

        echo "$w,$o,$MEASURE,${MEAN},${MIN},${MAX},${OOO:-0},${POOL_SUB:-0},${POOL_COMP:-0},${POOL_BP:-0},${POOL_FBW:-0},${PUMP_SUB:-0},${PUMP_PROC:-0},${PUMP_QW:-0}" >> "$CSV"
        printf "msps=%s ooo=%d pump_qw=%s\n" "$MEAN" "${OOO:-0}" "${PUMP_QW:-0}"

        sleep 5
    done
done

echo
echo "=== TOP 5 by mean Msps ==="
echo "sink_workers,omp_threads,msps_mean,ooo_chars,pump_queue_waits"
sort -t, -k4,4 -rn "$CSV" | head -5 | awk -F, '{print $1","$2","$4","$7","$14}'

echo
echo "=== BOTTOM 3 by pump_queue_waits (least DSP pressure) ==="
echo "sink_workers,omp_threads,msps_mean,pump_queue_waits"
sort -t, -k14,14 -n "$CSV" | head -3 | awk -F, '{print $1","$2","$4","$14}'

echo
echo "tuning-matrix: full CSV $CSV"
