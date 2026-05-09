# meshtastic-fusion

Multi-station aggregator for [meshtastic-sniffer](../README.md). Subscribes to N sniffer ZMQ feeds, presents one dashboard over all of them, and fans command operations (add key, promote off-grid, etc.) to every registered sensor in one click.

A separate Go binary so it can be deployed on a different host than the SDR-attached sniffers. The sniffer side stays C; fusion is HTTP/SSE/state-shuffling work that's a better fit for Go's stdlib.

## What it does

- **Subscribes** to one or more sniffers' ZMQ PUB sockets (`--zmq=tcp://*:7008` on the sniffer side).
- **Multilateration (TDOA)**: when 3+ sensors with known positions and `station_t_ns` timestamps hear the same `(from, packet_id)` within the dedup window, the fusion runs a hyperbolic-TDOA solver (Levenberg-Marquardt, multi-start to break the 3-station hyperbolic ambiguity) and emits a `GEOLOCATED` event with the estimated emitter lat/lon and 1-sigma uncertainty in meters. The Live tab map renders these as magenta diamond markers with a confidence-radius circle. Position accuracy depends entirely on each sensor's clock-discipline class: ~5-30 m with GPSDO+1PPS Tier-1 stations, ~300 m with chrony+PPS Tier-2 stations, useless with NTP-only Tier-3 stations (the solver weights each observation by `1/station_t_acc_ns` so well-disciplined stations dominate).
- **Persistent sensor registry** at `~/.config/meshtastic-fusion/sensors.json` (or `--sensors-file=PATH`); add/remove via the dashboard's Sensors tab or `POST /api/sensors`, `DELETE /api/sensors/<name>`.
- **Bearer-token auth** via `--api-token=SECRET`. When set, every `/api/*` and `/events` request requires `Authorization: Bearer <T>` (or `?token=<T>` on the EventSource URL, since EventSource can't set custom headers). The dashboard JS pulls the token from a one-shot `?token=` query param on first load and caches it in sessionStorage. When `--api-token` is empty (default), no auth is enforced; treat that mode as VPN-gated only.
- **Persistent SSE replay ring** at `--state-db=PATH` (bbolt single-file). The 1024-event in-memory ring is mirrored to disk and rehydrated on startup, so a browser refresh — or a fusion restart — reconstructs recent dashboard state without waiting for new traffic.
- **Live dashboard** at `--listen=:9000` with five tabs:
  - **Live**: Leaflet map with per-station markers (distinct color per sensor) and per-node markers, plus side tables showing stations and recently-seen nodes with "heard by" attribution.
  - **Activity**: per-preset cards aggregated across all sensors, with each card showing per-sensor breakdown (frame counts, decrypt%).
  - **Topology**: force-directed graph; each station is a pinned colored node, each transmitting node has dashed pseudo-edges to every station that's heard it (SNR-colored).
  - **Sensors**: registry table with live health (green/yellow/red), frames seen, decrypt%, msps, last event, C2-transport badge with hover-tooltip showing per-session DEALER telemetry (heartbeat count, last-seen age, command success/timeout counts, p50/p95 latency).
  - **Config**: command fan-out (Add key, Channel-share URL, Add extra freq, CoT multicast) — each form POSTs to every sensor's `/api/*` and reports per-sensor status.
- **C2 fan-out** via HTTP `POST /api/fanout/<endpoint>` — fans to every registered sensor's matching `/api/<endpoint>` in parallel, with optional bearer token from the sensor's registry entry. Prefers DEALER (ZMQ) for any sensor with an active inbound DEALER session; falls back to HTTP otherwise.
- **DEALER telemetry** at `GET /api/dealer-stats` — per-identity heartbeat count, last-seen age, command counts (sent / replied / timed-out), and a sliding histogram of recent command latencies with p50/p95.
- **STATS heartbeats over ZMQ** — sniffer-side `[stats]` heartbeats are now published over the same ZMQ PUB feed alongside frame events, so fusion's Sensors tab shows live msps + cumulative frames + decrypt% per sensor without any extra channel.
- **TX consolidation events** when the same packet is heard by multiple sensors within a short window (`--window=3s` default), emitted as `{"event":"TX", ...}` to SSE subscribers.

## Quick start

Build once:

```bash
cd fusion
go build -o meshtastic-fusion ./...
```

Run a single sniffer + fusion on the same machine:

```bash
# Terminal 1: sniffer with ZMQ telemetry exposed
./build/meshtastic-sniffer --hackrf --rate=20000000 --center=915000000 \
    --presets=all --region=US --keys=default \
    --web=8888 --zmq=tcp://*:7008 --station-id=hackrf-rx

# Terminal 2: fusion (with auth + persistent state)
./fusion/meshtastic-fusion \
    --listen=:9000 \
    --api-token=$(openssl rand -hex 16) \
    --state-db=$HOME/.config/meshtastic-fusion/state.db \
    --sensors-file=$HOME/.config/meshtastic-fusion/sensors.json
```

Then browse to `http://localhost:9000/?token=<the_random_hex>`, Sensors tab, **Add**:

- name: `hackrf-rx`
- zmq: `tcp://127.0.0.1:7008`
- api: `http://127.0.0.1:8888`

The token query param is captured into sessionStorage on first load and stripped from the URL bar so it doesn't get bookmarked. Refreshing the page within the same tab keeps the session; opening a new private tab requires re-authenticating.

Two-station deployment? Same pattern, different ports / different machines:

```bash
# rooftop sensor
./build/meshtastic-sniffer ... --zmq=tcp://*:7008 --station-id=rooftop --gpsd

# basement sensor
./build/meshtastic-sniffer ... --zmq=tcp://*:7008 --station-id=basement --gpsd

# fusion (could be on a third machine)
./fusion/meshtastic-fusion --listen=:9000 \
    --api-token=$(openssl rand -hex 16) \
    --state-db=$HOME/.config/meshtastic-fusion/state.db \
    --sensors-file=$HOME/.config/meshtastic-fusion/sensors.json
```

Add both sensors via the dashboard. Multi-station benefits unlock once 2+ are connected: which sensor heard which packet at what SNR, "heard by N/M" badges, cross-sensor `(from, packet_id)` consolidation in the TX feed, and TDOA emitter geolocation once 3+ time-disciplined stations report `station_t_ns` for the same packet.

## Honest limitations

- **CurveZMQ — sniffer-side only.** The sniffer accepts `--zmq-curve-keygen=PATH` and `--zmq-curve-secret=PATH` to encrypt its PUB socket. Fusion's Go subscriber doesn't authenticate to a CURVE-protected PUB because `go-zeromq/zmq4` v0.17 declares the security type but doesn't implement the handshake. The trade-off is intentional: switching to a libzmq-cgo binding (e.g. `pebbe/zmq4`) would buy CURVE at the cost of pure-Go cross-compilation. The realistic deployment for a multi-station rig is over a private overlay (WireGuard / Tailscale / VPN) anyway, which provides equivalent wire encryption end-to-end. Until upstream `go-zeromq/zmq4` lands CURVE, gate the link via VPN or a libzmq proxy.
- **No long-term archive on the fusion side.** Each sniffer's `--archive=DIR` writes daily-rotated gzipped JSONL on the sensor host; fusion does not currently aggregate those across sensors. The bbolt state ring is bounded at 1024 events for SSE replay, not historical analysis. A multi-station archive sink is a follow-on item.
- **Ports / fields are inherited from the sniffer.** If the sniffer's event JSON shape changes (new fields), fusion's dashboard JS may need parallel updates. Tested via shared schema fixtures, not a wire-level contract.

## API endpoints

All require the bearer token when `--api-token` is set.

| Method | Path | Purpose |
|---|---|---|
| GET    | `/`                       | Embedded dashboard HTML (always open) |
| GET    | `/events`                 | SSE firehose: every event from every subscribed sniffer + TX/GEOLOCATED consolidations |
| GET    | `/api/sensors`            | List registered sensors (with live `dealer:bool` for current C2 transport) |
| POST   | `/api/sensors`            | Add or update a sensor `{name, zmq, api?, api_token?, lat?, lon?, alt_m?}` |
| DELETE | `/api/sensors/<name>`     | Remove a sensor |
| POST   | `/api/fanout/keys`        | Fan an `Add key` to every sensor (DEALER preferred; HTTP fallback) |
| POST   | `/api/fanout/share-url`   | Fan a `meshtastic.org/e/` channel-share URL |
| POST   | `/api/fanout/extra-freq`  | Fan an extra-frequency decoder slot |
| POST   | `/api/fanout/cot-multicast` | Fan a CoT multicast destination |
| GET    | `/api/dealer-stats`       | Per-identity DEALER session telemetry (heartbeats, latency p50/p95, command counts) |

## Tests

```bash
cd fusion
go test ./...
```

Unit coverage spans auth (`web_test.go`), bbolt persistence (`store_test.go`), the sensor registry (`sensors_test.go`), HTTP fan-out + DEALER stats math (`c2_test.go`), the HTTP API surface (`api_test.go`), and the TDOA solver (`mlat_test.go`).

## License

GPL-3.0-or-later. Same license + author as the parent project. See [../LICENSE](../LICENSE).
