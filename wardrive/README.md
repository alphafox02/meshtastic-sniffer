# meshtastic-wardrive

> **Status: work in progress.** Phase 1 (format emitters) and Phase 2
> (live capture pipeline) are functional and tested end-to-end via
> `--self-test`. No real-world drive has been recorded yet.

Mobile single-node passive wardriving for [meshtastic-sniffer](../README.md).
Strap an SDR + GPS to a vehicle, drive around, build a Kismet-style
local SQLite of every Meshtastic node observed, estimate per-node
locations with an RSSI²-weighted centroid (plus 1-sigma uncertainty),
export to KML / CSV / JSON.

A separate Go binary so the radio + DSP stays in the C sniffer (where
it already lives, polyphase-channelized and bit-exact to gr-lora_sdr)
while the wardrive layer handles GPS, SQLite, and exports.

## What it does

- **Owns the radio via subprocess.** Launches `meshtastic-sniffer`
  as a child with `--zmq=tcp://127.0.0.1:7008` and subscribes to its
  ZMQ PUB feed. Any sniffer flag the operator passes on the wardrive
  command line is forwarded verbatim, so `--hackrf`, `--region=US`,
  `--presets=LongFast`, `--keys=default` etc. all just work.
- **gpsd client** parses TPV reports for lat/lon/altMSL/speed/track
  plus epx/epy/eph for AccuracyMeters. Stale-fix detection: a fix
  that hasn't updated in 30s is reported as invalid (no silent
  freezing).
- **SQLite local DB** with three tables: `sessions`, `tracks` (per
  GPS fix), `observations` (per frame heard). Pure-Go SQLite driver
  via `modernc.org/sqlite`; no cgo, single static binary.
- **Estimation** runs at export time, not during capture. Self-reported
  POSITION packets short-circuit to the node's broadcast coordinates;
  everything else uses RSSI²-weighted centroid with a 1-sigma "spread"
  radius floored at 50m. **The radius is a consistency metric, not a
  containment guarantee** — see *Honest limitations* below.
- **Native CSV format**: `MeshtasticWardrive-1.0` preamble + 26-column
  aggregated form (one row per node) and 22-column raw form (one row
  per observation). Designed natively for LoRa rather than shoehorned
  into the WigleWifi-1.6 Wi-Fi shape; WiGLE confirmed they want LoRa
  data but don't have an ingest path yet, so the format will iterate.
- **KML** with operator track polyline, per-node placemarks (color-coded
  by decrypted/encrypted/router role), and 1-sigma confidence rings as
  outlined polygons.
- **JSON sidecar** for downstream tooling.

## Quick start

Build:

```bash
cd wardrive
go build ./...
```

Self-test (no SDR, no GPS, no DB needed):

```bash
./meshtastic-wardrive --self-test --out-dir=/tmp/wardrive-out
```

Live capture (the real thing):

```bash
# in one terminal:
sudo gpsd /dev/ttyACM0 -N -n           # if not already running

# in another:
./meshtastic-wardrive --capture \
    --db=$HOME/wardrive.db \
    --station-id=mobile-rx \
    --gpsd=localhost:2947 \
    --notes='evening route 1' \
    -- \
    --hackrf --region=US --presets=LongFast --keys=default --rate=20000000
```

Anything after `--` is passed to the sniffer subprocess. The
sniffer's stderr (including its 5-second STATS heartbeats) is
forwarded to your terminal.

When you stop the capture (Ctrl-C), the session is closed cleanly.
Export afterwards:

```bash
./meshtastic-wardrive --export-from-db \
    --db=$HOME/wardrive.db \
    --out-dir=/tmp/run-1 \
    --export-session=1
```

Produces `wardrive-aggregated.csv`, `wardrive-raw.csv`,
`wardrive.kml`, `wardrive.json` in the output directory.
`--export-session=0` (default) concatenates every session in the DB
(without operator track polylines, which only make sense per-session).

## Flags

```
Modes (exactly one of):
  --self-test               synth fixture, write all four formats to --out-dir
  --capture                 live capture (sniffer + gpsd + ZMQ + DB)
  --export-from-db          read DB, write CSV/KML/JSON to --out-dir

Storage:
  --db=PATH                 SQLite database (default ./wardrive.db)
  --out-dir=DIR             export output directory (default .)
  --export-session=N        which session to export (0 = all)

Capture:
  --station-id=ID           rig label for the sessions table + exports
  --gpsd=HOST[:PORT]        gpsd endpoint (default localhost:2947)
  --sniffer=PATH            meshtastic-sniffer binary; empty = autodiscover
  --zmq=tcp://H:P           ZMQ endpoint used by sniffer + subscriber
  --notes=TEXT              free-text annotation saved on the session row

  Any flag not recognized above is forwarded to the sniffer subprocess.
  Typical invocation uses ' -- ' to separate, e.g.:
    --capture --db=X.db -- --hackrf --region=US --presets=LongFast
```

## Architecture

```
                          gpsd (TCP/JSON)
                              │
                              ▼
                       ┌──────────────┐
                       │ GPSDClient   │  maintains current fix
                       └──────────────┘
                              │
                              │ Current()
                              ▼
   meshtastic-sniffer  ──→  ZMQ PUB  ──→  ZMQSubscriber  ──→  Observations
        (child)        tcp://...:7008  parses JSON, tags
                                       with GPS at receive
                                                │
                                                ▼
                                          ┌─────────┐
                                          │ SQLite  │   sessions + tracks +
                                          │  DB     │   observations
                                          └─────────┘
                                                │
                          (offline, on demand)  │
                                                ▼
                                       ┌────────────────┐
                                       │ Aggregate +    │
                                       │ Estimate       │
                                       │ (centroid /    │
                                       │  self-report)  │
                                       └────────────────┘
                                                │
                                                ▼
                            CSV  /  KML  /  JSON  /  (future: WiGLE submit)
```

## Estimation accuracy: be honest

The README rule for this tool is: **never pretend we know more than we do.**

- A single drive-past gives a centroid biased toward the road. If you
  drove down one street, the estimate lies on that street — which can
  be 100s of meters off the true emitter location.
- The 1-sigma radius is the RSSI²-weighted standard distance of
  observations from the centroid. It's a measure of **internal
  consistency**, not a probability that the emitter is inside the
  ring. For a one-pass drive the radius can be tight while the actual
  location uncertainty is wide.
- A useful estimate requires a **closed loop** around each node you
  care about, ideally with multiple bearings through hearing range.
  Multi-pass coverage is how the Kismet/Wiggle-style methods earn
  their accuracy.
- **No direction-finding from a single antenna.** RSSI²-weighted
  centroid is the limit of one omnidirectional receiver. For real
  localization, use [meshtastic-fusion](../fusion/) with TDOA across
  3+ time-disciplined stations.

The KML description blocks include a one-line warning to the same
effect so anyone reading an export in Google Earth sees the caveat.

## On WiGLE submission

WiGLE confirmed they want LoRa observations but don't have a
submission path or a `Type=LORA` token yet (as of 2026-05). For
now the export format here is **not** WigleWifi-1.6-shaped; it's
designed natively for LoRa (full node id, channel name when
decrypted, preset, bandwidth, est_method, etc.). Sample CSVs from
`--self-test` were generated as the discussion starter; format will
iterate based on WiGLE feedback.

No `--wigle-submit` flag exists yet. Operators who want to share
data can mail/attach the CSV manually.

## Files

| File | What |
|---|---|
| `types.go` | `Observation`, `NodeAggregate`, `TrackPoint`, `Session` |
| `aggregate.go` | per-frame → per-node aggregation with metadata latching |
| `estimate.go` | RSSI²-weighted centroid + self-reported short-circuit |
| `csv.go` | aggregated + raw CSV emitters (with safe preamble) |
| `kml.go` | KML output with track polylines and confidence rings |
| `jsonout.go` | structured JSON sidecar |
| `db.go` | SQLite schema + prepared inserts + load functions |
| `gpsd.go` | TCP/JSON client for gpsd, parses TPV reports |
| `sniffer_proc.go` | spawn and manage the meshtastic-sniffer child |
| `zmq_sub.go` | subscribe to the sniffer feed, convert JSON to Observations |
| `capture.go` | orchestrate gpsd + sniffer + ZMQ + DB |
| `export.go` | re-runnable export from DB |
| `synthetic.go` | deterministic fixture for `--self-test` and tests |
| `main.go` | CLI dispatch (self-test / capture / export-from-db) |
| `*_test.go` | unit and integration tests |

## Tests

```bash
cd wardrive
go test ./...
```

Coverage spans estimator math (centroid converges to truth,
self-reported short-circuit, NaN-GPS filtering), CSV preamble +
header shape, KML XML validity + folder presence, JSON round-trip,
metadata latching, single-observation degeneracy, all-zero RSSI,
stress (10k observations aggregate in <10 ms), DB round-trip,
gpsd TPV parsing, and JSON → Observation conversion.

## Limitations

- **No live re-estimation.** The estimator runs at export time; the
  capture loop just writes raw observations. A web UI showing live
  estimates is a follow-on.
- **No path-loss inversion.** Centroid only in this release. A
  log-distance path-loss inversion estimator (with `--estimator=path-loss`
  and `--path-loss-n=` flags) is in the design notes; needs a
  calibration drive with a node at known coordinates to derive
  defaults for typical sub-GHz LoRa environments.
- **No KMZ packaging.** Plain `.kml` only. KMZ (zip with icon assets)
  is on the v1.1 list.
- **No automatic node-name anonymization.** Exports carry decrypted
  `long_name` / `short_name` verbatim. Privacy-conscious operators
  should consider this before publishing exports.
- **Sniffer subprocess assumes one radio.** If you want to wardrive
  across multiple SDRs simultaneously, launch multiple wardrive
  processes (one per radio, different `--db` files, different
  `--zmq` ports).

## License

GPL-3.0-or-later. Same as the parent project. See [../LICENSE](../LICENSE).
