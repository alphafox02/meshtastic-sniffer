# meshtastic-sniffer

A standalone wideband passive Meshtastic LoRa receiver written in C. Captures one wide IQ slice from a single SDR and decodes **every Meshtastic channel and preset that fits in the slice simultaneously** — no per-channel hopping, no missed packets. With keys supplied, decrypts text messages, GPS positions, NodeInfo, telemetry, routing, traceroute, ATAK PLI, and more — all surfaced from one capture.

Supports HackRF, BladeRF, USRP (UHD), SDRplay (native API v3), Airspy R2/Mini, RTL-SDR, and any SoapySDR device for live capture, plus VITA 49 (VRT) UDP input and IQ file playback. Built-in web dashboard (`--web`) provides a real-time Leaflet.js map, per-preset Activity tab, force-directed Topology graph, and runtime Config tab for adding keys without restarting.

Companion tools (built alongside the sniffer):

- **[meshtastic-recover](recover/)** — offline PSK recovery from captured pcaps. Aircrack-ng-style: feed a pcap and a wordlist, get back any keys that successfully decrypt. CPU OpenMP-parallel, hashcat custom-mode plugin for GPU.
- **[meshtastic-fusion](fusion/)** — multi-station aggregator (Go). Subscribes to N sniffer ZMQ feeds, presents one dashboard, runs hyperbolic-TDOA multilateration when 3+ time-disciplined stations hear the same packet.
- **[meshtastic-wardrive](wardrive/)** — mobile single-node wardriving (Go). Strap an SDR + GPS to a vehicle, build a Kismet-style local SQLite of every node observed, export to KML/KMZ/CSV/JSON.

Sister project to [iridium-sniffer](https://github.com/alphafox02/iridium-sniffer) and [inmarsat-sniffer](https://github.com/alphafox02/inmarsat-sniffer). Same SDR backend matrix, same threading style, same output ecosystem.

## Features

- Polyphase filterbank channelizer (AVX2/SSE4.2/NEON SIMD), one wide IQ stream into N parallel per-channel basebands at `Fs/M` each
- Async DSP pipeline: SDR recv decoupled from channelizer by a sample-pump queue, per-channel LoRa demod dispatched to a sharded worker pool; short B205mini runs can hit 26 Msps with all 1024 US preset channels, while long soaks expose the remaining DSP headroom honestly
- All 26 Meshtastic regions selectable per run via `--region=`: US (902–928), EU_868, EU_433, CN, JP, ANZ, KR, TW, RU, IN, NZ_865, TH, UA_433, UA_868, MY_433, MY_919, SG_923, KZ_433, KZ_863, NP_865, BR_902, PH_433/868/915, LORA_24. **One region per binary invocation** — Meshtastic regions span 433 MHz to 2.4 GHz, well beyond any commodity SDR's instantaneous bandwidth, so multi-region monitoring is run as multiple sniffer instances on different SDRs, aggregated by `meshtastic-fusion`.
- All 9 standard presets: ShortTurbo, ShortFast, ShortSlow, MediumFast, MediumSlow, LongFast, LongMod, LongSlow, LongTurbo
- Multi-key AES-128 / AES-256-CTR with 1-byte channel-hash routing — adding more keys does not slow per-packet decode (steady state: 1 AES op per packet)
- Per-port protobuf decode for `TEXT_MESSAGE_APP`, `POSITION_APP`, `NODEINFO_APP`, `TELEMETRY_APP` (DeviceMetrics + EnvironmentMetrics + PowerMetrics), `ROUTING_APP`, `TRACEROUTE_APP`, `WAYPOINT_APP`, `ADMIN_APP`, `NEIGHBORINFO_APP`, `KEY_VERIFICATION_APP`, `MAP_REPORT_APP`, `ATAK_PLUGIN`, `REMOTE_HARDWARE_APP`, `DETECTION_SENSOR_APP`, `STORE_FORWARD_APP`, `PAXCOUNTER_APP`. Other ports surface as raw bytes.
- ATAK port 72 decoder for `TAKPacket`: callsign, team, role, battery, PLI (lat/lon/alt/speed/course), GeoChat. PLIs republished as CoT XML over multicast.
- Off-grid LoRa scanner: occupied-bandwidth estimator + 3-confirm threshold flags LoRa-shaped energy outside the configured channel grid
- Two-tier dedup: payload-fingerprint plus slot+time-adjacency for heavy-corruption replicas under close-range or strong-interference conditions
- Per-frame RSSI/SNR + on-failure CRC + drift-only CFO telemetry in the JSON event and dashboard
- Built-in web dashboard (Live map / Activity / Topology / Config), runtime key + extra-freq additions without restart
- JSON, UDP, MQTT, ZMQ PUB, CoT XML multicast, daily-rotated gzipped JSONL archive, libpcap streaming export sinks
- PSK dictionary attack against undecrypted frames (`--psk-wordlist=PATH`), geofence ENTRY/EXIT alerts on positioned nodes (`--geofence=PATH`), CurveZMQ on the PUB socket (`--zmq-curve-secret=PATH`)
- Replay-attack flagging on duplicate `(from, packet_id)` tuples beyond the normal mesh retransmit window
- Multi-station deployment: emit ZMQ telemetry to a `meshtastic-fusion` aggregator, optionally self-register via `--announce-to=URL`, optional outbound DEALER socket (`--c2-dealer=tcp://fusion:7009`) for NAT-friendly C2
- `--schema` dumps the JSON event schema (JSON Schema 2020-12) so SIEM consumers can validate without guessing
- AddressSanitizer- and ThreadSanitizer-clean build / smoke-test pipeline

## What it decodes

- **Text messages, positions, NodeInfo, telemetry** on any channel whose PSK is loaded
- **ATAK PLI** (lat/lon/alt/speed/course/team/role/battery) — republished as CoT XML over LAN multicast for ATAK-CIV / WinTAK / iTAK
- **Topology hints** from NEIGHBORINFO and relay-hop bytes
- **Off-grid LoRa**: any LoRa-shaped energy outside the configured Meshtastic grid (custom community channels, drone telemetry, etc.) — flagged with estimated SF/BW

All decoded simultaneously from a single wideband capture, with optional per-frame mlat timing for fusion-side hyperbolic-TDOA geolocation.

## Installation

### DragonOS Noble

DragonOS Noble ships with HackRF, BladeRF, USRP (UHD), RTL-SDR, Airspy, SDRplay, SoapySDR, OpenSSL, FFTW3, libmosquitto, and libzmq pre-installed. **Do not `apt install` the SDR libraries on top — re-installing them can break the existing DragonOS-tuned versions.** Just clone and build:

```bash
git clone https://github.com/alphafox02/meshtastic-sniffer.git
cd meshtastic-sniffer
mkdir build && cd build
cmake ..
make -j$(nproc)
```

CMake auto-detects every available SDR backend and output sink. All should show "enabled" — if anything reports "disabled" on DragonOS, file an issue.

For the Go-based companions (`meshtastic-fusion` and `meshtastic-wardrive`), DragonOS Noble already has a modern Go toolchain — confirm with `go version` (≥ 1.25). Then:

```bash
cd fusion   && go build -o meshtastic-fusion   ./...
cd wardrive && go build -o meshtastic-wardrive ./...
```

### Ubuntu / Debian

```bash
git clone https://github.com/alphafox02/meshtastic-sniffer.git
cd meshtastic-sniffer

# Core dependencies (required)
sudo apt install build-essential cmake pkg-config libfftw3-dev libssl-dev

# SDR libraries (install only what you have)
sudo apt install libhackrf-dev       # HackRF One
sudo apt install libbladerf-dev      # BladeRF
sudo apt install libuhd-dev          # USRP (B2x0, N2x0, etc.)
sudo apt install librtlsdr-dev       # RTL-SDR (native)
sudo apt install libairspy-dev       # Airspy R2 / Mini
sudo apt install libsoapysdr-dev     # SoapySDR (LimeSDR, PlutoSDR, etc.)
# SDRplay native API: install from https://www.sdrplay.com/api/

# Optional output sinks
sudo apt install libmosquitto-dev    # --mqtt
sudo apt install libzmq3-dev         # --zmq (and meshtastic-fusion)
sudo apt install libsodium-dev       # CurveZMQ encryption on --zmq

# Optional: GPS for multilateration / wardrive
sudo apt install gpsd gpsd-clients

mkdir build && cd build
cmake ..
make -j$(nproc)
```

CMake output shows what was detected:

```
-- HackRF: enabled
-- BladeRF: enabled
-- USRP (UHD): enabled
-- RTL-SDR: enabled
-- SoapySDR: enabled
-- MQTT: enabled
-- ZMQ: enabled
```

For the Go companions, install Go 1.25+ from <https://go.dev/dl/>, then `cd fusion && go build ./...` and `cd wardrive && go build ./...`.

## First-time use (60 seconds)

You have a Meshtastic node and an SDR. You want to see what your node and its neighbours are saying.

1. **Get your channel-share URL.** In the Meshtastic phone app, open the channel, tap "Share Channel," and copy the URL — it looks like `https://meshtastic.org/e/#CgM...`. That URL carries the channel name and the AES key.

2. **Plug in the SDR.** Run `./meshtastic-sniffer --list` to confirm it's detected.

3. **Run it.** The region defaults to `US` (override with `--region=EU_868` etc.):

   ```bash
   ./meshtastic-sniffer --hackrf --share-url='https://meshtastic.org/e/#CgM...' --web=8888
   ```

   Open `http://localhost:8888` to see the dashboard.

4. **If nothing shows up after a minute**, check stderr — the binary prints loud warnings when no samples are flowing or no LoRa frames have decoded. Common causes: gain too low (try `--gain=40`), wrong region, no node in range.

5. **Adding more channels later:** open the dashboard, click **Config** tab, paste another `meshtastic.org/e/` URL, hit Add. No restart needed.

## Quickstart

```bash
# Casual: default region (US), default LongFast preset, default PSK ("simple1"):
./meshtastic-sniffer --hackrf --keys=default --web=8888

# Paste your channel-share URL once, skip the dashboard:
./meshtastic-sniffer --hackrf --share-url='https://meshtastic.org/e/#CgM...'

# Power: stare at every preset on US 902-928, dump per-channel stats every 5s,
# tee raw IQ to disk, multi-station-tagged feed to a collector:
./meshtastic-sniffer --bladerf --region=US --presets=all \
                    --keys-file=$HOME/.config/meshtastic-sniffer/keys \
                    --stats-json=/run/meshsniff/stats.json \
                    --iq-record=/data/capture-$(date +%s).cs8 \
                    --feed=collector:5588 --station-id=basement-rx --web=8888

# Network IQ input: any sender emitting VITA-49 (sample rate + center freq
# come from the VITA-49 IF-context packets automatically):
./meshtastic-sniffer --vita49=4991 --keys=default --web=8888

# Replay an IQ capture (sample rate + freq + format pulled from .sigmf-meta):
./meshtastic-sniffer --file=capture.cf32 --keys=default

# Multi-output: stdout JSON + UDP + MQTT + ZMQ + CoT multicast + web
./meshtastic-sniffer --hackrf --keys=LongFast=default,Ops=hex:00112233...ff \
                    --feed=collector:5588 --mqtt=mqtt.local \
                    --zmq=tcp://*:7008 --cot-multicast=239.2.3.1:6969 \
                    --web=8888 --station-id=basement-rx

# Off-grid scan only (no decode, discover non-standard LoRa freqs):
./meshtastic-sniffer --hackrf --scan --alert-off-grid

# Long-running deployment: daily archive, geofence alerts, PSK wordlist,
# replay-attack flagging, libpcap streaming export:
./meshtastic-sniffer --hackrf --keys-file=$HOME/.config/meshtastic-sniffer/keys \
                    --archive=/var/log/meshtastic \
                    --geofence=$HOME/.config/meshtastic-sniffer/zones.ini \
                    --psk-wordlist=/usr/share/dict/words \
                    --pcap=/data/meshtastic.pcap --web=8888

# Multi-station: feed a meshtastic-fusion aggregator on the same VPN.
./meshtastic-sniffer --hackrf --keys=default --station-id=rooftop \
                    --gpsd=localhost:2947 --web=8888 \
                    --zmq=tcp://*:7008 \
                    --announce-to=http://fusion.local:9000/api/sensors \
                    --c2-dealer=tcp://fusion.local:7009

# List every SDR you have plugged in:
./meshtastic-sniffer --list

# Run the self-tests (channelizer routing + AES end-to-end + JSON output):
./meshtastic-sniffer --selftest
```

## Hardware capacity

The number of channels the sniffer demodulates simultaneously is set by the SDR's analog bandwidth and your `--rate`. **Any rate works** — the channelizer auto-fits whichever channels of the configured grid land inside `[center − rate/2, center + rate/2]`. The US ISM band is 902–928 MHz, so **~26 MHz of SDR bandwidth is the threshold to capture every US-band 250 kHz slot from one stare**; below that you cover a contiguous subset that the binary picks for you. Other regions are narrower (EU_868 is ~5 MHz, EU_433 is ~1.7 MHz), so a 20 MHz HackRF is full-coverage in most non-US regions.

| SDR | Bandwidth | Coverage at default rate | Notes |
|---|---|---|---|
| HackRF One | 20 MHz | ~73-80 US LongFast slots + every other preset's grid that fits | Most common config. Full coverage in EU_868 / EU_433 / most non-US regions. |
| BladeRF 2.0 | up to 56 MHz (AD9361) | All 104 US LongFast slots at ~26 Msps | Full US ISM coverage; headroom for adjacent-band scanning. |
| USRP B205mini / B210 | up to 56 MHz (AD9361) | **All 9 presets, 1024 channels, full US 902-928 MHz at 26 Msps** | UHD-driven; pass `--usrp-otw=sc8` for sustained 26 Msps (see *USRP tuning notes* below). |
| SDRplay (RSPdx, RSP1A) | 10 MHz | One BW group + adjacent presets | Native API v3. |
| Airspy R2 / Mini | 10 MHz | One BW group + adjacent presets | |
| RTL-SDR (R820T) | 2.0 MHz | One BW group, ~8 LongFast slots | Cheap entry point. Default rate is 2.0 Msps (multiple of 250 kHz BW); higher rates can desense the R820T tuner. |
| Custom via SoapySDR | varies | — | LimeSDR, PlutoSDR, etc. |
| VITA-49 / VRT (network) | varies | — | Remote IQ over UDP from any sender that emits VITA-49 (`[BIND:]PORT`). Same wire format as iridium-sniffer / inmarsat-sniffer. |
| IQ file replay | — | — | Offline; auto-loads `.sigmf-meta` sibling for rate/freq/format. |

`--list` enumerates all attached SDRs across every compiled-in backend. Without `--center`, the binary picks a sensible center from `--region` + configured preset midpoints, logs the resolved coverage window, and warns if a user-supplied `--center` falls outside the configured region.

### HackRF tuning notes

The single `--gain=DB` knob maps across HackRF's three independent stages, with **LNA filled first** (where it actually buys noise figure), then VGA, then more LNA, then the 14 dB front-end amp at the top. Per-knob control via `--hackrf-lna=N` (0..40 step 8), `--hackrf-vga=N` (0..62 step 2), and `--hackrf-amp` / `--hackrf-amp-off`.

**Defaults (with no `--gain` or per-knob flags):** LNA=24, VGA=20, AMP off — the canonical "good HackRF RX" config that hears distant nodes at 5–15 dB SNR.

**Close-range desense.** A Meshtastic node sitting within 1–2 m of your HackRF antenna can produce enough RF to overload the analog mixer regardless of LNA gain. The ADC won't clip (signal looks fine), but mixer intermodulation products inside the band corrupt the demod's symbol detection. Symptoms: high SNR (25–35 dB) but every frame from the close node has `payload_crc_ok: false`, and the topology fills with bit-flipped phantom node IDs (`!471c1b98` instead of the real `!433c0b98`, etc.). Fixes:

- Move the HackRF physically further from the node (5+ ft, different room)
- Inline a 6–20 dB SMA pad between the antenna and HackRF
- Reduce the test node's TX power (`meshtastic --set lora.tx_power 5`)
- Knock LNA back: `--hackrf-lna=8` for close-range bench testing

Distant signals decode cleanly even with a close node hammering the front end. `payload_crc_ok` is the diagnostic.

### USRP tuning notes (B205mini / B210)

Default UHD wire format is `sc16` (4 bytes/sample). At 26 Msps that's 104 MB/s over USB plus the host-side sc16→fc32 conversion UHD performs in the recv path. On a 16-core host that load occasionally pushes UHD's recv FIFO past its overflow threshold (`OOO` in stderr) — the channelizer can keep up, but `uhd_rx_streamer_recv()` falls behind for short bursts.

**Use `--usrp-otw=sc8` for sustained 26 Msps.** sc8 halves both USB bandwidth (52 MB/s) and UHD's internal conversion work. The 4 LSBs of dynamic range are not visible to LoRa decoding — chirp demodulation is phase-based and routinely tolerates >20 dB of noise margin, so dropping the bottom 24 dB of headroom changes nothing in practice. HackRF runs 8-bit at the ADC by default; sc8 brings the B-series to the same precision floor.

```bash
./meshtastic-sniffer --usrp --rate=26000000 --center=915000000 \
                    --region=US --presets=all --keys=default \
                    --usrp-otw=sc8 --gain=40 --web=8888
```

Short validation run: **26.02-26.03 Msps with `--presets=all`, zero `OOO`, all 1024 channels live.** A later 7.8-hour soak stayed stable with clean drains and no leak, but averaged **22.72 Msps** with a steady trickle of UHD overflows; the remaining long-run bottleneck is downstream DSP throughput, not worker-pool correctness.

If you still see occasional bursty `OOO` after enabling sc8, the sample-pump queue depth knob is `MESHTASTIC_SAMPLE_QUEUE=N` (default 256). Bumping higher gives UHD more recv slack at the cost of slightly higher peak memory. If `queue_waits` stays high over a long run, the issue is sustained DSP throughput rather than queue depth.

## Outputs

- **JSON feed** to stdout (always when running) and to UDP endpoints (`--feed=HOST:PORT`, repeatable)
- **MQTT** publish (`--mqtt=HOST[:PORT]`, topic `meshtastic/<station-id>` by default)
- **ZMQ PUB** for multi-consumer (`--zmq=tcp://*:7008`); optional CurveZMQ with `--zmq-curve-secret=PATH` (keypair via `--zmq-curve-keygen=PATH`)
- **CoT XML multicast** (`--cot-multicast=239.2.3.1:6969`) — every positioned node (regular POSITION packets *and* ATAK PLIs) republished as Cursor-on-Target XML. Any LAN ATAK-CIV / WinTAK / iTAK picks them up automatically — no TAK Server required.
- **PCAP streaming export** (`--pcap=PATH` rotating file, `--pcap-fifo=PATH` named pipe for live Wireshark). Each LoRa frame wrapped in DLT_USER0.
- **Daily-rotated gzipped JSONL archive** (`--archive=DIR`) — every emitted event appended to `DIR/meshtastic-YYYYMMDD.jsonl.gz`, rotated at UTC midnight. SIEM-friendly.
- **Built-in web dashboard** (`--web=8888`) — four tabs (Live / Activity / Topology / Config)

## Web dashboard

`--web=8888` opens four tabs:

- **Live** — Leaflet map with node markers + trail polylines (last 8 fixes per node). Nodes table with search box, sortable columns, CSV export. Click any row to slide in a per-node drawer: name + id, metrics, last-60 SNR sparkline, recent text messages, recent positions, channels-seen-on. Channels table (by hash). Messages and Discoveries panels.
- **Activity** — per-preset cards. Each card shows fpm (60-second rolling), cumulative frames, decrypted/total channel ratio, sparkline, and the channel sub-list (channel name when decrypted, `(encrypted)` otherwise). Idle presets render greyed.
- **Topology** — force-directed graph. Nodes sized by frame count, edges colored by SNR. Real edges from `NEIGHBORINFO_APP` packets and resolved relay-hop hints. A synthetic "RX" station has dashed pseudo-edges to every node this sniffer hears, so even sparse meshes give a useful picture.
- **Config** — runtime forms for adding keys, importing `meshtastic.org/e/` channel-share URLs, adding extra-frequency decoder slots, changing CoT multicast destination — all without restarting.

Equivalent endpoints at `POST /api/keys`, `POST /api/share-url`, `POST /api/extra-freq`, `POST /api/cot-multicast`. Optional bearer-token auth via `--api-token=SECRET` (clients send `Authorization: Bearer SECRET`).

## JSON event format

`./meshtastic-sniffer --schema` dumps the canonical JSON Schema 2020-12 for every event the binary emits.

**Per-frame fields:** `from`, `to`, `packet_id`, `channel_hash` (1-byte routing hash from the radio header), optional `slot_id` (which polyphase channelizer slot caught the frame), `hop_limit`/`hop_start`, `rssi_db`/`snr_db`.

**Quality telemetry — silent when healthy, present when actionable:**
- `payload_crc_ok: false` — CRC was present and failed (frame bytes are corrupt; absence means no explicit CRC failure was reported: CRC passed, or no CRC was present on the wire)
- `cfo_hz` — only when |drift| > 100 Hz (radio is well-tuned otherwise)

**Multilateration timing:** `station_t_ns` (host-realtime ns at first-replica receive) + `station_t_acc_ns` (operator-self-reported clock-discipline class). Set `--station-t-acc-ns=N` per station: 100 for GPSDO+1PPS, 1000 for chrony+PPS, 1000000 (default) for NTP-class. The fusion-side mlat solver weights observations by this value.

**Decoded-port fields** (text, lat/lon, telemetry, etc.) appear only when the channel key is known *and* the payload parses *and* the LoRa CRC passed. CRC-failed frames are gated explicitly: even when AES-CTR happens to produce parseable-looking bytes from corrupt ciphertext, those bytes are suppressed and the frame is reported as `decrypted: false`.

**Top-level `event` discriminator** distinguishes from regular packet events:
- `STATS` — periodic msps + cumulative frames + decryption rate
- `OFF_GRID_LORA` — scanner detected LoRa-shaped energy outside the configured grid
- `REPLAY_SUSPECTED` — duplicate `(from, packet_id)` outside the normal mesh retransmit window
- `GEOFENCE_ENTRY` / `GEOFENCE_EXIT` — positioned node crossed a polygon boundary
- `PSK_DISCOVERED` — `--psk-wordlist` attack found a key
- `GEOLOCATED` — fusion-side mlat solver produced an emitter position estimate
- `HEARTBEAT` — DEALER C2 session keepalive (when `--c2-dealer` is configured)

## Stats heartbeat

Every 5 seconds the binary prints a one-line summary to stderr:

```
[stats] 18.45 Msps in, 12 LoRa frames, 9 decrypted
```

`off-grid hits` is appended only when the scanner is enabled (`--scan*` or `--alert-off-grid`).

### Pipeline diagnostics

Set `MESHTASTIC_PFB_STATS=1` to dump async-pipeline counters to stderr at shutdown:

```
sample-pump:    submitted=147624 processed=147624 queue_waits=14841
pfb sink pool:  submitted=5113024 completed=5113024 queue_bp=0 freebuf_waits=0
```

What to look for:

- **`submitted == processed`** (sample-pump) and **`submitted == completed`** (sink pool): clean drain, every sample reached the demod
- **`queue_waits`** (sample-pump): producer blocked on a full queue. Non-zero is fine; means the recv side burst faster than DSP for a moment and the queue absorbed it. Sustained high values suggest you need a larger `MESHTASTIC_SAMPLE_QUEUE=N` (default 256)
- **`queue_bp`** (sink pool): per-worker queue ran full. Should be zero in normal operation
- **`freebuf_waits`** (sink pool): channelizer waited for a LoRa worker to free a buffer. Non-zero means a worker fell behind sample rate — usually a slow CPU or too many channels for the host

Worker count defaults to `min(nproc-1, 16)`; override with `MESHTASTIC_SINK_WORKERS=N`.

## Offline PSK recovery

[meshtastic-recover](recover/) reads captured pcaps (`--pcap=PATH`) and a wordlist, runs the same channel-hash prefilter + AES-CTR + protobuf-shape verifier the live decoder uses, and prints any keys that successfully decrypt. OpenMP-parallel across all CPU cores. Output is `--keys-file=` compatible — feed the recovered keys back to the sniffer.

```bash
# Try every firmware default key (simple1..simple255):
./meshtastic-recover --pcap=session.pcap --simple-keys --output=recovered.keys

# Add a passphrase wordlist:
./meshtastic-recover --pcap=session.pcap --simple-keys --wordlist=/usr/share/dict/words

# Re-decode the same capture with the recovered keys:
./meshtastic-sniffer --file=session.pcap --keys-file=recovered.keys
```

GPU acceleration via a [hashcat](https://hashcat.net) custom-mode plugin (working end-to-end on real-radio captures, pending upstream PR cleanup). Export hashcat-format hashes with `--hashcat-export=PATH`; see [recover/README.md](recover/README.md) for format spec.

Realistic attack surface: factory-default channels recover instantly; weak-passphrase channels recover from a rockyou-class wordlist in seconds; channels using a strong randomly-generated 16/32-byte PSK are not feasible to recover.

## Multi-station / mobile

- **[meshtastic-fusion](fusion/)** — central aggregator for N rooftop / fixed sensors. Bearer-auth dashboard, bbolt-backed persistent state, hyperbolic-TDOA emitter geolocation when 3+ time-disciplined stations hear the same packet (~5–30 m with GPSDO+1PPS, ~300 m with chrony+PPS). C2 fan-out over HTTP or ZMQ DEALER.
- **[meshtastic-wardrive](wardrive/)** — single-node mobile capture. Spawns the sniffer as a subprocess, ingests gpsd, writes every observation to SQLite, exports per-node KML/KMZ + WigleWifi-style CSV + JSON sidecar with RSSI²-weighted centroid estimates and 1-σ confidence rings.

Both Go binaries; see their READMEs.

## Honest limitations

- No direction finding from a single SDR — amplitude alone can't localize an emitter. Multilateration via 3+ stations works but requires GPSDO-locked SDRs for sub-100 m accuracy (Tier 1); chrony+PPS hosts give ~300 m (Tier 2).
- 16 known port numbers are decoded into structured fields; others surface as raw bytes in the JSON event.
- AdminMessage signature verification (ed25519) is not implemented yet — admin packets are decoded but not validated.
- CurveZMQ is sniffer-side only; the Go-based `meshtastic-fusion` aggregator can't yet authenticate to a CURVE-protected PUB (limitation of `go-zeromq/zmq4` v0.17). Use a libzmq-based proxy or VPN-gate the link.
- Close-range front-end overload: a Meshtastic node within 1–2 m of the HackRF antenna corrupts demod via mixer intermodulation regardless of LNA gain. Surfaced via `payload_crc_ok: false`; mitigated by physical separation, an inline RF attenuator, or lowering the test node's TX power. See the *HackRF tuning notes* section above.

## Self-test and smoke test

`./meshtastic-sniffer --selftest` runs two checks:

1. **Channelizer**: synthesizes a 0.1 s tone at 902.625 MHz inside a 20 MHz capture centered on 910 MHz, configures four 250 kHz channels at the US LongFast slot 0..3 grid, verifies the tone lands in slot 2 with the expected power profile.
2. **AES + multi-key + protobuf**: builds a synthetic Meshtastic packet (`TEXT_MESSAGE_APP`, payload `"Hello"`, encrypted with the default key), runs it through the decode path, and verifies the callback fires with the right port + payload + channel name.

`bash tests/test_smoke.sh` adds SigMF auto-config, `--list`, web `/api/*` round-trip, STATS SSE heartbeat. Both tests run clean under AddressSanitizer + UndefinedBehaviorSanitizer; ThreadSanitizer reports no data races on the keyset rwlock under concurrent `/api/keys` POST load.

## Generating test IQ from gr-lora_sdr

If you have `gnuradio` and `gr-lora_sdr` installed (`python3 -c "from gnuradio import lora_sdr"` should succeed), you can generate a known-good Meshtastic-shaped IQ file without any radio hardware:

```bash
python3 tools/gen_meshtastic_iq.py --out=/tmp/meshtastic_test.cf32 \
                                    --text="Hello" --sf=11 --bw=250000 --cr=5
./meshtastic-sniffer --file=/tmp/meshtastic_test.cf32 --rate=250000 \
                    --center=903000000 \
                    --extra-freq=903000000:bw=250000:sf=11:cr=5 \
                    --keys=default
```

The generator builds a real Meshtastic frame (16-byte radio header + AES-128-CTR encrypted Data envelope with channel-hash for the default key) and runs it through gr-lora_sdr's modulator. Useful as a pipeline smoke test and for iterating on LoRa demod's sync/header/payload decoding.

`MESHTASTIC_LORA_TRACE=1` enables a per-symbol state-machine trace on stderr.

## License

GPL-3.0-or-later. See `LICENSE`. Copyright (c) 2026 CEMAXECUTER LLC.

This project is independent of and not affiliated with Meshtastic. "Meshtastic" is a trademark of [Meshtastic LLC](https://meshtastic.org). Protocol constants used here (default PSK, channel hash, AES-CTR nonce layout, region/preset tables) are interoperability facts derived from the upstream firmware at <https://github.com/meshtastic/firmware> (also GPL-3.0-or-later); no proprietary code is included.

### Upstream attribution

- **gr-lora_sdr** by Joachim Tapparel @ EPFL TCL Lab (<https://github.com/tapparelj/gr-lora_sdr>, GPL-3.0-or-later) — significant portions of `lora.c`'s bit-level decode path (hard-decode Hamming, deinterleave, gray, dewhiten, preamble-mode-vote) are ported from gr-lora_sdr and verified bit-exact against its stage outputs. Per-stage citations appear inline at the relevant call sites in `lora.c`.
- **Meshtastic firmware** (<https://github.com/meshtastic/firmware>, GPL-3.0-or-later) — the wire format, default PSK, simpleN PSK derivation, channel-hash function, AES-CTR nonce layout, region/preset tables, and port number assignments are derived from the upstream firmware. Implementation here is original; only the on-the-air constants come from upstream.
- **Felipe Kersting** — `blocking_queue.h` and `fair_lock.h` are vendored MIT-licensed primitives (Copyright (c) 2020). License preserved in each file.
