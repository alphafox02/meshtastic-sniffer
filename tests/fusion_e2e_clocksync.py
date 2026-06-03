#!/usr/bin/env python3
"""End-to-end clock-sync v1 acceptance harness.

Spawns the fusion binary, simulates N sniffer stations via pyzmq PUB
sockets, and verifies the full event-flow path:

    sniffer JSON -> ZMQ ingest -> cluster window -> anchor lookup ->
    pair convergence -> target solve -> GEOLOCATED event with
    timestamp_class=sync + diagnostic fields

The harness covers the clock-sync acceptance assertions. Each case runs
in its own subprocess-isolated test case so failures are scoped.

Usage:
    python3 tests/fusion_e2e_clocksync.py            # run all cases
    python3 tests/fusion_e2e_clocksync.py case_name  # run one
"""

from __future__ import annotations

import json
import math
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import zmq


REPO = Path(__file__).resolve().parent.parent
FUSION = REPO / "fusion" / "meshtastic-fusion"
SPEED_OF_LIGHT = 299_792_458.0

# Synthetic scene: 3 stations forming a triangle in Kansas, anchor at
# the centroid + offset, target some distance away. Coordinates chosen
# so the inter-station baselines are ~1-2 km (LoRa-realistic).
ANCHOR = {
    "from_id": "!cafe1234",
    "lat": 39.003,
    "lon": -97.999,
    "alt_m": 0,
}
TARGET = {
    "from_id": "!deadbeef",
    "lat": 38.997,
    "lon": -98.008,
    "alt_m": 0,
}
STATIONS = [
    {"name": "alpha", "lat": 39.010, "lon": -98.010},  # NW
    {"name": "bravo", "lat": 39.000, "lon": -97.988},  # E
    {"name": "delta", "lat": 38.988, "lon": -98.002},  # S
]


# ---------- helpers ----------

def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6_371_000.0
    rlat1 = math.radians(lat1)
    rlat2 = math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(rlat1) * math.cos(rlat2) * math.sin(dlon / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def find_free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class FakeStation:
    name: str
    lat: float
    lon: float
    endpoint: str
    sock: object
    clock_offset_ns: int = 0

    def emit(self, frame: dict) -> None:
        frame = dict(frame)
        frame.setdefault("station", self.name)
        frame.setdefault("station_lat", self.lat)
        frame.setdefault("station_lon", self.lon)
        frame.setdefault("station_t_acc_ns", 1_000)  # 1 us discipline
        # Apply station-local clock offset to lock-time AND frame-time.
        if "preamble_lock_t_ns" in frame:
            frame["preamble_lock_t_ns"] += self.clock_offset_ns
        if "station_t_ns" in frame:
            frame["station_t_ns"] += self.clock_offset_ns
        self.sock.send_string(json.dumps(frame))


def make_stations(ctx) -> list[FakeStation]:
    stations = []
    for s in STATIONS:
        port = find_free_port()
        sock = ctx.socket(zmq.PUB)
        sock.bind(f"tcp://127.0.0.1:{port}")
        # PUB needs a small delay before subscribers attach; we'll
        # sleep in emit_packet to give fusion time to subscribe.
        stations.append(FakeStation(
            name=s["name"], lat=s["lat"], lon=s["lon"],
            endpoint=f"tcp://127.0.0.1:{port}", sock=sock,
        ))
    return stations


def emit_packet_from(
    stations: list[FakeStation],
    sender: dict,
    packet_id: int,
    base_t_ns: int,
    *,
    preset: str = "MediumFast",
    sf: int = 9,
    bw_hz: int = 250_000,
    cr: int = 5,
    extra_demod_ms: int = 150,
    rssi_db: float = -90.0,
    snr_db: float = 20.0,
    fields_trusted: bool = True,
) -> None:
    """Emit one packet from `sender` (a dict with from_id + lat/lon)
    heard by every station with proper propagation delay."""
    for st in stations:
        dist_m = haversine_m(sender["lat"], sender["lon"], st.lat, st.lon)
        prop_ns = int(dist_m / SPEED_OF_LIGHT * 1e9)
        lock_t_ns = base_t_ns + prop_ns
        # Frame-emit time = lock + ~demod latency (per cluster2-measured
        # SF9/BW250 numbers: 145-281 ms; pick 150 ms representative).
        station_t_ns = lock_t_ns + extra_demod_ms * 1_000_000
        frame = {
            "from": sender["from_id"],
            "packet_id": packet_id,
            "preamble_lock_t_ns": lock_t_ns,
            "station_t_ns": station_t_ns,
            "preset": preset,
            "sf": sf,
            "cr": cr,
            "bw_hz": bw_hz,
            "rssi_db": rssi_db,
            "snr_db": snr_db,
            "fields_trusted": fields_trusted,
        }
        st.emit(frame)


# ---------- subprocess + SSE ----------

class FusionProcess:
    """Spawns the fusion binary and tails its /events SSE feed."""

    def __init__(
        self,
        endpoints: list[str],
        *,
        anchor_cli: list[str] = (),
        extra_args: list[str] = (),
        window_s: float = 0.25,
        clock_sync_min_n: int = 4,
        clock_sync_max_age_s: float = 600.0,
    ) -> None:
        self.listen_port = find_free_port()
        cmd = [
            str(FUSION),
            "--listen", f":{self.listen_port}",
            "--window", f"{window_s}s",
            "--clock-sync-min-n", str(clock_sync_min_n),
            "--clock-sync-max-age-s", str(clock_sync_max_age_s),
        ]
        for a in anchor_cli:
            cmd += ["--calibration-node", a]
        cmd += list(extra_args)
        cmd += endpoints
        self.cmd = cmd
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.stdout_lines: list[str] = []
        threading.Thread(target=self._drain_stdout, daemon=True).start()
        # Wait for the HTTP listener to open.
        for _ in range(80):
            try:
                with closing(socket.create_connection(("127.0.0.1", self.listen_port), timeout=0.2)):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            self.proc.kill()
            raise RuntimeError("fusion did not open listen port in 4 s")
        # Drain stderr in a background thread; surface on failure.
        self.stderr_lines: list[str] = []
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        self.events: list[dict] = []
        self._sse_stop = False
        self._sse_thread = threading.Thread(target=self._sse_loop, daemon=True)
        self._sse_thread.start()
        # Wait briefly for ZMQ subscribers to attach to the PUB sockets.
        time.sleep(0.3)

    def _drain_stderr(self) -> None:
        for line in self.proc.stderr:
            self.stderr_lines.append(line.rstrip("\n"))

    def _drain_stdout(self) -> None:
        for line in self.proc.stdout:
            self.stdout_lines.append(line.rstrip("\n"))

    def _sse_loop(self) -> None:
        url = f"http://127.0.0.1:{self.listen_port}/events"
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                while not self._sse_stop:
                    raw = r.readline()
                    if not raw:
                        return
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if line.startswith("data: "):
                        body = line[len("data: "):]
                        try:
                            ev = json.loads(body)
                        except json.JSONDecodeError:
                            continue
                        self.events.append(ev)
        except Exception:
            pass

    def wait_for_event(self, predicate, *, timeout_s: float = 5.0) -> Optional[dict]:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            for ev in list(self.events):
                if predicate(ev):
                    return ev
            time.sleep(0.05)
        return None

    def of_type(self, event_type: str) -> list[dict]:
        return [e for e in self.events if e.get("event") == event_type]

    def shutdown(self) -> None:
        self._sse_stop = True
        try:
            self.proc.send_signal(signal.SIGINT)
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()


# ---------- test cases ----------

def _check(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def case_no_anchor_no_sync():
    """Assertion 1: no anchors -> no sync class; legacy paths work."""
    ctx = zmq.Context.instance()
    stations = make_stations(ctx)
    fusion = FusionProcess([s.endpoint for s in stations], anchor_cli=[])
    try:
        # Emit a single target packet (no anchor). With 3 stations
        # carrying lat/lon + station_t_ns, fusion should still produce
        # a GEOLOCATED event with timestamp_class="software_lock".
        emit_packet_from(stations, TARGET, packet_id=1, base_t_ns=1_700_000_000_000_000_000)
        time.sleep(0.5)  # let cluster window expire
        geo = fusion.wait_for_event(lambda e: e.get("event") == "GEOLOCATED", timeout_s=3.0)
        _check(geo is not None, "expected a GEOLOCATED event with no anchor")
        _check(geo["timestamp_class"] == "software_lock",
               f"timestamp_class={geo['timestamp_class']!r}, want software_lock")
        _check(geo.get("clock_sync_pair_count", 0) == 0,
               "clock_sync_pair_count should be 0 when no anchors configured")
    finally:
        fusion.shutdown()


def case_anchor_declared_not_observed():
    """Assertion 2: anchor declared but never heard -> status stays none/warming."""
    ctx = zmq.Context.instance()
    stations = make_stations(ctx)
    anchor_cli = f"{ANCHOR['from_id']}:lat={ANCHOR['lat']}:lon={ANCHOR['lon']}"
    fusion = FusionProcess([s.endpoint for s in stations], anchor_cli=[anchor_cli])
    try:
        # Emit only target traffic; no anchor packets.
        for pid in range(1, 6):
            emit_packet_from(stations, TARGET, packet_id=pid, base_t_ns=1_700_000_000_000_000_000 + pid * 1_000_000)
            time.sleep(0.05)
        time.sleep(0.6)
        geo = fusion.wait_for_event(lambda e: e.get("event") == "GEOLOCATED", timeout_s=3.0)
        _check(geo is not None, "expected GEOLOCATED for target")
        _check(geo["timestamp_class"] in ("software_lock", "frame"),
               f"timestamp_class={geo['timestamp_class']!r}, want software_lock or frame")
        _check(geo.get("clock_sync_pair_count", 0) == 0,
               "no anchor heard -> no converged pairs")
    finally:
        fusion.shutdown()


def case_anchor_observed_convergence_and_target():
    """Assertions 3, 4, 5: anchor observed -> convergence; target before vs after."""
    ctx = zmq.Context.instance()
    stations = make_stations(ctx)
    # Inject per-station clock offsets so clock-sync has something to recover.
    stations[0].clock_offset_ns = 0          # alpha = reference
    stations[1].clock_offset_ns = 50_000     # bravo +50 us
    stations[2].clock_offset_ns = -30_000    # delta -30 us
    anchor_cli = f"{ANCHOR['from_id']}:lat={ANCHOR['lat']}:lon={ANCHOR['lon']}"
    fusion = FusionProcess([s.endpoint for s in stations], anchor_cli=[anchor_cli], clock_sync_min_n=4)
    try:
        # Phase 1: target packet BEFORE any anchor traffic.
        emit_packet_from(stations, TARGET, packet_id=10, base_t_ns=1_700_000_000_000_000_000)
        time.sleep(0.5)
        early = fusion.wait_for_event(
            lambda e: e.get("event") == "GEOLOCATED" and e.get("packet_id") == 10,
            timeout_s=3.0,
        )
        _check(early is not None, "expected GEOLOCATED for target before convergence")
        _check(early["timestamp_class"] in ("software_lock", "frame"),
               f"pre-convergence class={early['timestamp_class']!r}, want software_lock/frame")
        # Phase 2: feed enough anchor packets to converge (min-N=4 here, do 8).
        base = 1_700_000_001_000_000_000
        for i in range(8):
            emit_packet_from(stations, ANCHOR, packet_id=100 + i, base_t_ns=base + i * 5_000_000)
            time.sleep(0.05)
        time.sleep(0.8)
        # Phase 3: target packet AFTER convergence.
        emit_packet_from(stations, TARGET, packet_id=20, base_t_ns=base + 100_000_000)
        time.sleep(0.6)
        late = fusion.wait_for_event(
            lambda e: e.get("event") == "GEOLOCATED" and e.get("packet_id") == 20,
            timeout_s=4.0,
        )
        _check(late is not None, "expected GEOLOCATED for target after convergence")
        _check(late["timestamp_class"] == "sync",
               f"post-convergence class={late['timestamp_class']!r}, want sync. "
               f"stdout: {fusion.stdout_lines[-15:]} "
               f"stderr: {fusion.stderr_lines[-10:]}")
        _check(late.get("clock_sync_pair_count", 0) >= 1,
               f"clock_sync_pair_count={late.get('clock_sync_pair_count')}, want >=1")
        _check(late.get("clock_sync_anchor_count", 0) >= 1,
               f"clock_sync_anchor_count={late.get('clock_sync_anchor_count')}, want >=1")
        # POSITION ACCURACY: the whole point of clock-sync is producing a
        # better geolocation, not just a prettier label. Verify the
        # post-sync position is within tolerance of the injected TARGET
        # coordinates, AND that the pre-sync solve was worse (or at
        # least no better). Per-station offsets injected at the top of
        # this test are 0/50us/-30us; without clock-sync those map to
        # tens of km of position error; with clock-sync they should
        # collapse to sub-100 m.
        err_late = haversine_m(late["lat"], late["lon"], TARGET["lat"], TARGET["lon"])
        _check(err_late < 250.0,
               f"post-sync position error {err_late:.1f} m too high; "
               f"injected offsets should have been recovered. solve={late}")
        err_early = haversine_m(early["lat"], early["lon"], TARGET["lat"], TARGET["lon"])
        _check(err_late <= err_early,
               f"post-sync error {err_late:.1f}m should be <= pre-sync {err_early:.1f}m; "
               f"clock-sync provided no benefit")
        # No GEOLOCATED for the anchor itself.
        for ev in fusion.of_type("GEOLOCATED"):
            _check(ev.get("from") != ANCHOR["from_id"],
                   f"anchor traffic produced GEOLOCATED: {ev}")
    finally:
        fusion.shutdown()


def case_spoofed_position_rejected():
    """Assertion 6: non-anchor POSITION_APP-style traffic does not update graph."""
    ctx = zmq.Context.instance()
    stations = make_stations(ctx)
    anchor_cli = f"{ANCHOR['from_id']}:lat={ANCHOR['lat']}:lon={ANCHOR['lon']}"
    fusion = FusionProcess([s.endpoint for s in stations], anchor_cli=[anchor_cli], clock_sync_min_n=4)
    try:
        # Inject 8 packets from a spoofer node that is NOT in the anchor registry.
        spoofer = {"from_id": "!badf00d0", "lat": ANCHOR["lat"], "lon": ANCHOR["lon"]}
        base = 1_700_000_002_000_000_000
        for i in range(8):
            emit_packet_from(stations, spoofer, packet_id=200 + i, base_t_ns=base + i * 5_000_000)
            time.sleep(0.05)
        time.sleep(0.6)
        # Now emit a target. It should NOT be timestamp_class=sync because
        # no anchor (only the spoofer) was heard.
        emit_packet_from(stations, TARGET, packet_id=300, base_t_ns=base + 100_000_000)
        time.sleep(0.6)
        ev = fusion.wait_for_event(
            lambda e: e.get("event") == "GEOLOCATED" and e.get("packet_id") == 300,
            timeout_s=3.0,
        )
        _check(ev is not None, "expected GEOLOCATED for target")
        _check(ev["timestamp_class"] != "sync",
               f"spoofer traffic should NOT have produced sync class: {ev}")
        _check(ev.get("clock_sync_pair_count", 0) == 0,
               f"spoofer should not have converged pairs: {ev}")
    finally:
        fusion.shutdown()


def case_dashboard_contract():
    """Assertion 9: GEOLOCATED + TX JSON carry every field the future
    timeline dashboard needs to render evidence."""
    ctx = zmq.Context.instance()
    stations = make_stations(ctx)
    stations[1].clock_offset_ns = 50_000
    stations[2].clock_offset_ns = -30_000
    anchor_cli = f"{ANCHOR['from_id']}:lat={ANCHOR['lat']}:lon={ANCHOR['lon']}"
    fusion = FusionProcess([s.endpoint for s in stations], anchor_cli=[anchor_cli], clock_sync_min_n=4)
    try:
        base = 1_700_000_003_000_000_000
        for i in range(8):
            emit_packet_from(stations, ANCHOR, packet_id=400 + i, base_t_ns=base + i * 5_000_000)
            time.sleep(0.05)
        time.sleep(0.6)
        emit_packet_from(stations, TARGET, packet_id=500, base_t_ns=base + 100_000_000)
        time.sleep(0.6)
        geo = fusion.wait_for_event(
            lambda e: e.get("event") == "GEOLOCATED" and e.get("packet_id") == 500,
            timeout_s=4.0,
        )
        _check(geo is not None, "expected GEOLOCATED")
        # Fields the timeline needs:
        wanted = ["from", "packet_id", "lat", "lon", "uncertainty_m",
                  "station_count", "timestamp_class",
                  "clock_sync_pair_count", "clock_sync_residual_ns",
                  "clock_sync_anchor_count", "clock_sync_reference"]
        for k in wanted:
            _check(k in geo, f"GEOLOCATED missing dashboard-required field: {k!r}; have {sorted(geo)}")
        # TX events also carry the per-station list with name/snr/coords.
        tx = next((e for e in fusion.of_type("TX") if e.get("packet_id") == 500), None)
        _check(tx is not None, "expected TX event for target")
        _check("stations" in tx and isinstance(tx["stations"], list),
               f"TX event missing per-station list: {tx}")
        _check(len(tx["stations"]) == len(stations),
               f"TX stations={len(tx['stations'])}, want {len(stations)}")
        for st_e in tx["stations"]:
            for k in ("name", "lat", "lon"):
                _check(k in st_e, f"TX station missing {k!r}: {st_e}")
    finally:
        fusion.shutdown()


# ---------- runner ----------

def case_stale_after_max_age():
    """Assertion 7: stop anchor traffic; after max-age the converged
    pairs expire to `stale`, target solves fall back to software_lock."""
    ctx = zmq.Context.instance()
    stations = make_stations(ctx)
    stations[1].clock_offset_ns = 50_000
    stations[2].clock_offset_ns = -30_000
    anchor_cli = f"{ANCHOR['from_id']}:lat={ANCHOR['lat']}:lon={ANCHOR['lon']}"
    # Use a very short max-age so the test runs fast.
    fusion = FusionProcess(
        [s.endpoint for s in stations],
        anchor_cli=[anchor_cli],
        clock_sync_min_n=4,
        clock_sync_max_age_s=1.0,
    )
    try:
        # Converge.
        base = 1_700_000_004_000_000_000
        for i in range(8):
            emit_packet_from(stations, ANCHOR, packet_id=600 + i, base_t_ns=base + i * 5_000_000)
            time.sleep(0.05)
        time.sleep(0.6)
        # Verify convergence took.
        early = fusion.wait_for_event(
            lambda e: e.get("event") == "GEOLOCATED" and e.get("packet_id") == 700,
            timeout_s=0.1,
        )  # no such packet, just drain
        emit_packet_from(stations, TARGET, packet_id=700, base_t_ns=base + 100_000_000)
        time.sleep(0.6)
        ev = fusion.wait_for_event(
            lambda e: e.get("event") == "GEOLOCATED" and e.get("packet_id") == 700,
            timeout_s=3.0,
        )
        _check(ev is not None and ev["timestamp_class"] == "sync",
               f"after convergence expected sync, got {ev}")
        # Wait > max-age with NO anchor traffic.
        time.sleep(1.5)
        # New target. By now pair samples are all older than max-age =>
        # status moves to stale on next FeedCluster recompute. The
        # CorrectAndClassify path requires Status == Converged to issue
        # Sync class, so this target should fall back to software_lock.
        emit_packet_from(stations, TARGET, packet_id=701, base_t_ns=base + 3_000_000_000)
        time.sleep(0.6)
        ev = fusion.wait_for_event(
            lambda e: e.get("event") == "GEOLOCATED" and e.get("packet_id") == 701,
            timeout_s=3.0,
        )
        _check(ev is not None, "expected GEOLOCATED for post-stale target")
        _check(ev["timestamp_class"] != "sync",
               f"after max-age expected software_lock/frame, got {ev}")
    finally:
        fusion.shutdown()


def case_mixed_class_degraded():
    """Assertion 8: when one station hasn't converged but the others
    have, the solve mixes classes and is flagged degraded."""
    ctx = zmq.Context.instance()
    stations = make_stations(ctx)
    stations[1].clock_offset_ns = 50_000
    anchor_cli = f"{ANCHOR['from_id']}:lat={ANCHOR['lat']}:lon={ANCHOR['lon']}"
    fusion = FusionProcess([s.endpoint for s in stations], anchor_cli=[anchor_cli], clock_sync_min_n=4)
    try:
        # Anchor heard by ONLY alpha + bravo (delta misses it -- simulate
        # by skipping delta's emit). After convergence, alpha-bravo pair
        # is converged but alpha-delta and bravo-delta are not.
        base = 1_700_000_005_000_000_000
        for i in range(8):
            # Skip delta on purpose for the anchor packets.
            for st in stations[:2]:
                dist_m = haversine_m(ANCHOR["lat"], ANCHOR["lon"], st.lat, st.lon)
                prop_ns = int(dist_m / SPEED_OF_LIGHT * 1e9)
                lock_t_ns = base + i * 5_000_000 + prop_ns
                st.emit({
                    "from": ANCHOR["from_id"], "packet_id": 800 + i,
                    "preamble_lock_t_ns": lock_t_ns,
                    "station_t_ns": lock_t_ns + 150_000_000,
                    "preset": "MediumFast", "sf": 9, "cr": 5, "bw_hz": 250_000,
                    "rssi_db": -90.0, "snr_db": 20.0,
                })
            time.sleep(0.05)
        time.sleep(0.6)
        # Target heard by ALL 3 stations.
        emit_packet_from(stations, TARGET, packet_id=900, base_t_ns=base + 100_000_000)
        time.sleep(0.6)
        ev = fusion.wait_for_event(
            lambda e: e.get("event") == "GEOLOCATED" and e.get("packet_id") == 900,
            timeout_s=4.0,
        )
        _check(ev is not None, "expected GEOLOCATED for mixed-class target")
        # delta's contribution falls into software_lock (no converged
        # pair to alpha), alpha+bravo get sync. WorstTimestampCls =
        # software_lock; Degraded = true.
        _check(ev.get("timestamp_class_degraded") is True or ev["timestamp_class"] != "sync",
               f"mixed-class target should be degraded or non-sync: {ev}")
        _check(ev.get("clock_sync_pair_count", 0) >= 1,
               f"alpha-bravo pair should have converged: {ev}")
    finally:
        fusion.shutdown()


CASES = {
    "no_anchor_no_sync":                 case_no_anchor_no_sync,
    "anchor_declared_not_observed":      case_anchor_declared_not_observed,
    "anchor_observed_convergence":       case_anchor_observed_convergence_and_target,
    "spoofed_position_rejected":         case_spoofed_position_rejected,
    "stale_after_max_age":                case_stale_after_max_age,
    "mixed_class_degraded":               case_mixed_class_degraded,
    "dashboard_contract":                case_dashboard_contract,
}


def main(argv: list[str]) -> int:
    if not FUSION.exists():
        print(f"ERROR: fusion binary not built at {FUSION}", file=sys.stderr)
        print("       cd fusion && go build", file=sys.stderr)
        return 2
    names = argv[1:] or list(CASES)
    failed = 0
    for name in names:
        fn = CASES.get(name)
        if fn is None:
            print(f"ERROR: unknown case {name!r}; have {sorted(CASES)}", file=sys.stderr)
            return 2
        print(f"=== {name} ===")
        t0 = time.time()
        try:
            fn()
            print(f"  PASS  ({time.time() - t0:.1f}s)")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL: {e}")
    print(f"\n{len(names) - failed}/{len(names)} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
