# Clock-sync (cross-station TDOA without GPSDO)

Fusion can locate Meshtastic emitters from observations at multiple sniffer
stations even when the stations themselves do not have GPSDO/PPS hardware.
This is the same technique volunteer aviation MLAT networks (FlightAware,
OpenSky, ADS-B Exchange) use to reach useful precision with consumer
SDR receivers.

This page covers the operator-facing side: declaring anchors, placing them
sensibly, and understanding what `timestamp_class=sync` actually means.

---

## The core idea in one paragraph

When two stations hear the same packet, the time delta they measure is
**radio travel time + clock offset between the stations** combined into one
number — you cannot separate them from a single observation. If the
transmitter's position is known, you can *calculate* the radio travel
time exactly (distance ÷ speed of light) and whatever's left in the
measured delta is the pair's clock offset. Do this with several anchor
packets, take a robust median per station pair, and you have a calibrated
network clock. From there, **unknown-position emitters become TDOA-locatable**
using the same calibrated clocks.

The catch: fusion **must not** feed unknown-position traffic into the
clock-sync graph. The math entanglement is real — random Meshtastic packets
average geometry into the clock estimate and silently poison every later
solve. v1 is anchor-gated by design.

---

## Declaring anchors

There are two ways to register an anchor node with fusion:

### Repeatable CLI flag

```bash
meshtastic-fusion \
  --calibration-node=!abcd1234:lat=39.0:lon=-98.0 \
  --calibration-node=!cafe9999:lat=39.05:lon=-97.97:accuracy_ns=500 \
  ...
```

Each flag is a single anchor. Fields after the from-id are `key=value`,
order-insensitive:

| key | required | meaning |
|---|---|---|
| `lat` | yes | latitude in decimal degrees |
| `lon` | yes | longitude in decimal degrees |
| `alt` or `alt_m` | no | altitude in meters (default 0) |
| `accuracy_ns` | no | declared per-anchor timing accuracy in ns; 0 = solver default |

### Config file

```bash
meshtastic-fusion --calibration-config=/etc/meshtastic-fusion/anchors.json ...
```

JSON shape:

```json
[
  {"NodeID": "!abcd1234", "Lat": 39.0,  "Lon": -98.0,  "AltM": 100, "AccuracyNs": 0},
  {"NodeID": "!cafe9999", "Lat": 39.05, "Lon": -97.97, "AltM": 250, "AccuracyNs": 500}
]
```

CLI flags and the config file compose; both are applied. Operators on a
single host typically use the CLI flag; multi-host or many-anchor
deployments use a versioned config file.

### Modes

```text
--clock-sync=auto    (default) enabled iff any anchor was declared
--clock-sync=on      enabled even with zero anchors (graph will stay warming)
--clock-sync=off     disabled
```

---

## Anchor placement — read this before you put a node down

The math doesn't care about anchor power. The **receiver** does.

### Distance from the nearest sniffer station

| distance | what happens | use as anchor? |
|---|---|---|
| < 1 m | near-field, wavefront isn't planar | **NO** |
| 1–10 m | severe multipath, almost certain front-end saturation | **NO** |
| 10–30 m | depends on building; usually still bad | **NO** |
| 30–50 m | marginal — operator judgement | maybe |
| 50–200 m | line-of-sight from roof / yard usually clean | **YES** |
| 200 m+ | ideal for typical urban deployments | **YES** |

Fusion issues a startup warning (logged at `WARN clock-sync:`) if any
declared anchor is closer than 30 m to any registered sniffer station.
The warning names both the anchor's from-id and the sniffer station, and
points to this document. It does not refuse the config; some operators
have good reasons (test setups, intentional saturation testing).

### Why too close is bad, in plain terms

A 100 mW Meshtastic transmission at 1 m gives roughly **-1 dBm** at the
receiver. LoRa sensitivity floor is around **-140 dBm**. Most SDR front
ends compress around **-10 dBm**. So a node 1 m from the receiver pegs
the receiver's analog stage into limiting; the LNA's gain falls; the
preamble correlation peak broadens; sub-sample timing precision becomes
junk. Even **just standing in the same room** is enough multipath to
add tens of nanoseconds of bias from ceiling and wall reflections.

10 m gets you about -21 dBm — still high but usually under compression.
100 m → -41 dBm. 1 km → -61 dBm. 10 km → -81 dBm. The "clean" anchor
operating range starts where the received signal is well below the SDR's
1 dB compression point.

### Other placement notes

- **Stable position.** If you move the anchor (or it sits on a window
  where the curtain moves), the geometry shifts and the network's median
  clock-offset drifts. A fixed mount in a known place is best.
- **Line of sight to at least 2 sniffers**, ideally 3+. Don't put it
  behind a metal building roof that hides it from half the network.
- **Avoid co-linear placements** with the primary receiver pairs. If
  three stations and the anchor all sit on a straight line, the
  geometry is degenerate — clock-sync still works, but the calibrated
  network has weak positioning ability in directions perpendicular to
  the line.
- **No moving anchors.** A Meshtastic device on a vehicle is a target,
  not a calibration source.

### Special case: co-located with a sniffer

If a sniffer station has a Meshtastic device co-located on the same
site (operator owns both), declare the anchor with the sniffer's
known lat/lon. Co-located does **NOT** mean "on the same desk." It
means "same site, ≥ 30 m apart, clean RF path between them." A node
in the operator's garage and a sniffer on the rooftop is fine; a node
on the operator's desk next to the SDR antenna is not.

### Detecting bad placement at runtime

Even after a startup warning is dismissed, fusion runs an RSSI sanity
gate on every anchor observation:

```
default reject threshold: --clock-sync-max-rssi-dbm=-20
```

Anchor observations stronger than this are dropped from the pair-offset
estimator and counted under `clock_sync_rssi_rejected` in the runtime
stats. If you see that counter climbing, your anchor is too close to
that sniffer station and the pair-offsets touching it should be
distrusted.

---

## Anchor source policy

V1 accepts **only** these anchor sources. Everything else is silently
ignored for clock-sync purposes (frame still flows for solving):

1. **Operator-declared anchors** — explicit lat/lon by CLI or config file.
2. **Co-located sniffer anchors** — declared with `colocated_with=station_X`
   (planned for v1.1; not in this release).
3. **Solver-promoted anchors** — high-confidence solved positions used as
   secondary calibration (planned for v2; explicitly off in v1).

**Never** anchors:

- Arbitrary `POSITION_APP` from random nodes — easy to spoof.
- CRC-failed frames — content unreliable.
- Frames where `fields_trusted=false` — radio header may be garbled.

This isn't a configuration choice; it's a structural property of v1.
Loosening it requires solving the math gap (clock-offset ↔ propagation-delay
entanglement) without a known position, which is what graph-optimization
MLAT does. Fusion doesn't ship that yet.

---

## Reading the output

When clock-sync is converged for a solve, the GEOLOCATED event includes:

```json
{
  "event": "GEOLOCATED",
  "from": "!unknown1234",
  "packet_id": 9876,
  "lat": 39.012,
  "lon": -97.982,
  "uncertainty_m": 87.3,
  "timestamp_class": "sync",
  "clock_sync_pair_count": 3,
  "clock_sync_residual_ns": 412.0,
  "clock_sync_anchor_count": 1,
  "clock_sync_reference": "alpha"
}
```

| field | meaning |
|---|---|
| `timestamp_class` | best timestamp source consumed: `sync` > `software_lock` > `frame` |
| `clock_sync_pair_count` | how many converged station pairs touched this solve |
| `clock_sync_residual_ns` | worst MAD residual across those pairs — your timing-precision floor |
| `clock_sync_anchor_count` | how many distinct anchors fed the converged pairs |
| `clock_sync_reference` | the station chosen as the network time reference |

Pair status moves through:

```text
none      no anchor packets received yet for this pair
warming   has some samples, fewer than --clock-sync-min-n (default 10)
converged samples met AND MAD residual < --clock-sync-max-mad-ns (default 5000 ns)
stale     was converged but no new sample arrived for --clock-sync-max-age-s
          (default 600 s); position estimates from this pair are now suspect
rejected  enough samples but MAD persistently exceeds threshold — placement,
          multipath, or spoofing issue
```

A pair that stays `rejected` is fusion telling you something is wrong with
that station pair's geometry or anchor placement. Look at `clock_sync_
rssi_rejected` in runtime stats; usually it's the anchor being too close
to one of the stations in the pair.

---

## Tuning knobs (operator power-user territory)

```text
--clock-sync-min-n=N         min samples before a pair is converged (default 10)
--clock-sync-max-mad-ns=N    MAD residual ceiling for converged (default 5000)
--clock-sync-max-age-s=N     samples older than this expire (default 600)
--clock-sync-max-rssi-dbm=DB RSSI sanity gate (default -20 dBm)
```

Reasonable bounds:

- If your network is sparse and you only get a few anchor packets per
  minute, lower `--clock-sync-min-n` to 5. Convergence comes faster
  but a single bad observation has more weight.
- If your environment is noisy (urban, lots of multipath), raise
  `--clock-sync-max-mad-ns` to 20000 (20 us). You'll accept noisier
  clock-sync at the cost of larger position uncertainty on solves.
- Don't touch `--clock-sync-max-rssi-dbm` unless you know why. -20 dBm
  is already permissive; tighter (-30, -40) catches more bad placements.

---

## What clock-sync is NOT

- **Not GPSDO-grade timing.** Tier-1 timing comes from a sample-counter
  anchored to a PPS edge — that's the `tdoa-sample-epoch` work, planned
  but not in this release. Clock-sync without sample-epoch is "as good
  as your TCXO." Volunteer aviation MLAT reaches 50–200 m position
  accuracy on that alone.
- **Not a position fix on the anchor itself.** Anchor packets are
  calibration traffic. Fusion deliberately suppresses GEOLOCATED events
  for declared-anchor from-ids — the position is already known by
  declaration.
- **Not a lie detector for spoofed POSITION_APP.** A node claiming to
  be at the moon contributes to neither clock-sync (it's not in the
  anchor registry) nor to its own location (fusion solves it
  independently from station observations). The two answers may
  disagree — that's the operator's signal.

---

## Validating your deployment

A minimum-viable clock-sync deployment is:

```text
3 sniffer stations, each with --station-lat/--station-lon set
1 anchor Meshtastic node at a known position, ≥ 100 m from any sniffer
each station registered with the fusion (CLI args or /api/sensors)
fusion run with --calibration-node=!anchor_id:lat=Y:lon=X
```

Within ~10 anchor transmissions (which takes a few minutes for a typical
beaconing node), pair statuses should move from `warming` to `converged`.
Watch the fusion stderr log for the first `clock-sync: auto enabled` and
any `WARN clock-sync: anchor ... is N m from sniffer ...` lines.

After convergence, any GEOLOCATED event with `timestamp_class=sync`
includes a position estimate calibrated by clock-sync. Compare against
ground-truth positions for known emitters (e.g. a friend's phone running
a Meshtastic app whose GPS you trust) to validate accuracy.
