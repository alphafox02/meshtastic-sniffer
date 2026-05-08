# meshtastic-sniffer

Wideband passive Meshtastic LoRa receiver written in C. Captures one wide IQ slice from a single SDR and decodes **every Meshtastic channel and preset that fits in the slice simultaneously** -- no per-channel hopping, no missed packets. With keys supplied, decrypts in parallel: text messages, GPS positions, node info, telemetry, routing, traceroute, ATAK plugin packets, and more -- all surfaced from one capture.

Sister project to [iridium-sniffer](https://github.com/alphafox02/iridium-sniffer) and [inmarsat-sniffer](https://github.com/alphafox02/inmarsat-sniffer). Same SDR backend matrix, same threading style, same output ecosystem.

## Features

- Polyphase filterbank channelizer (AVX2/SSE4.2/NEON SIMD), one wide IQ stream into N parallel per-channel basebands at `Fs/M` each
- All 26 Meshtastic regions selectable per run via `--region=`: US (902-928), EU_868, EU_433, CN, JP, ANZ, KR, TW, RU, IN, NZ_865, TH, UA_433, UA_868, MY_433, MY_919, SG_923, KZ_433, KZ_863, NP_865, BR_902, PH_433/868/915, LORA_24. **One region per binary invocation** — Meshtastic regions span 433 MHz to 2.4 GHz, well beyond any commodity SDR's instantaneous bandwidth, so multi-region monitoring is run as multiple sniffer instances on different SDRs aggregated by [meshtastic-fusion](fusion/).
- All 9 standard presets: ShortTurbo, ShortFast, ShortSlow, MediumFast, MediumSlow, LongFast, LongMod, LongSlow, LongTurbo
- Multi-key AES-128 / AES-256-CTR with 1-byte channel-hash routing -- adding more keys does NOT slow per-packet decode (steady state: 1 AES op per packet)
- Per-port protobuf decode for `TEXT_MESSAGE_APP`, `POSITION_APP`, `NODEINFO_APP`, `TELEMETRY_APP` (DeviceMetrics + EnvironmentMetrics + PowerMetrics), `ROUTING_APP`, `TRACEROUTE_APP`, `WAYPOINT_APP`, `ADMIN_APP`, `NEIGHBORINFO_APP`, `KEY_VERIFICATION_APP`, `MAP_REPORT_APP`, `ATAK_PLUGIN`, `REMOTE_HARDWARE_APP`, `DETECTION_SENSOR_APP`, `STORE_FORWARD_APP`, `PAXCOUNTER_APP`. Other ports surface as raw bytes in JSON.
- ATAK port 72 decoder for `TAKPacket`: callsign, team, role, battery, PLI (lat/lon/alt/speed/course), GeoChat. PLIs republished as CoT XML over multicast (see Outputs).
- Off-grid LoRa scanner: occupied-bandwidth estimator + 3-confirm threshold flags LoRa-shaped energy outside the configured channel grid
- Per-frame RSSI/SNR + on-failure CRC + drift-only CFO telemetry carried through into the JSON event and the dashboard
- Built-in web dashboard (Live map / Activity / Topology / Config), runtime key + extra-freq additions without restart
- JSON, UDP, MQTT, ZMQ PUB, CoT XML multicast, daily-rotated gzipped JSONL archive, libpcap streaming export output sinks
- PSK dictionary attack against undecrypted frames (`--psk-wordlist=PATH`), geofence ENTRY/EXIT alerts on positioned nodes (`--geofence=PATH`), CurveZMQ on the PUB socket (`--zmq-curve-secret=PATH`)
- Replay-attack flagging on duplicate `(from, packet_id)` tuples beyond the normal mesh retransmit window
- Multi-station deployment: emit ZMQ telemetry to a [meshtastic-fusion](fusion/) aggregator, optionally self-register via `--announce-to=URL`, optional outbound DEALER socket (`--c2-dealer=tcp://fusion:7009`) for NAT-friendly C2
- `--schema` dumps the JSON event schema (JSON Schema 2020-12) so SIEM consumers can validate without guessing
- AddressSanitizer- and ThreadSanitizer-clean build / smoke-test pipeline

## Use cases

The same passive observer fits three operational shapes:

- **Operator / surveyor** -- ham, EmComm coordinator, community organizer. "What Meshtastic networks operate in my area? How busy is each preset? Are nodes reaching each other?" Live map + Activity + Topology tabs. Default keys supplied.
- **Pen tester / red team** -- authorized engagement on a target's mesh. "Do they use default channel keys? Are admin commands flying around unsigned? What's their actual range envelope?" JSON feed for tooling, libpcap streaming export (`--pcap=PATH` / `--pcap-fifo=PATH` for live Wireshark), PSK dictionary attack against unknown channels (`--psk-wordlist=PATH`).
- **Defensive monitoring** -- site security wanting to know what's leaving the perimeter via LoRa. Off-grid scanner + daily-rotated gzipped JSONL archive (`--archive=DIR`) + geofence ENTRY/EXIT alerts (`--geofence=PATH`).

The core is honest passive observation; the use case is mostly which outputs you wire up and which dashboard tabs you stare at.

## Hardware capacity

The number of channels you stare at simultaneously is set by the SDR's analog bandwidth and your `--rate`. **Any rate works** -- the channelizer auto-fits whichever channels of the configured grid land inside `[center - rate/2, center + rate/2]`. The US ISM band is 902--928 MHz, so **~26 MHz of SDR bandwidth is the threshold to capture every US-band 250 kHz slot from one stare**; below that you cover a contiguous subset that the binary picks for you. Other regions are narrower (EU_868 is ~5 MHz, EU_433 is ~1.7 MHz), so a 20 MHz HackRF is full-coverage in most non-US regions.

| SDR | Bandwidth | Coverage at default rate | Notes |
|-----|-----------|--------------------------|-------|
| HackRF One | 20 MHz | 409 channels at `--presets=all` US (41 LongFast slots + every other preset's slot grid that fits) | Most common config; partial cover of LongFast but every preset is decoded in parallel. Full coverage in EU_868 / EU_433 / most non-US regions |
| BladeRF 2.0 | up to 56 MHz (AD9361) | All 104 US LongFast slots at ~26 Msps | Full US ISM coverage; headroom for adjacent-band scanning |
| USRP B210 | up to 56 MHz (AD9361) | All 104 US LongFast slots at ~26 Msps | UHD-driven; same headroom |
| SDRplay (RSPdx, RSP1A) | 10 MHz | One BW group + adjacent presets | Native API |
| Airspy R2 / Mini | 10 MHz | One BW group + adjacent presets | |
| RTL-SDR (R820T) | 2.4 MHz | One BW group, ~9 LongFast slots | Cheap entry point |
| Custom via SoapySDR | varies | -- | Generic |
| VITA-49 / VRT (network) | varies | -- | Remote IQ over UDP from any sender that emits VITA-49 (`[BIND:]PORT`, big-endian VRT signal-data, optional VRL wrapper). Same wire format as iridium-sniffer / inmarsat-sniffer; if a sender works for those, it works for this. |
| IQ file replay | -- | -- | Offline; auto-loads `.sigmf-meta` sibling for rate/freq/format |

`--list` enumerates all attached SDRs across every compiled-in backend.

`./meshtastic-sniffer --rate=20000000 --region=US --presets=all` -- without `--center`, the binary picks a sensible center from region + preset midpoints, logs the resolved coverage window, and warns if a user-supplied `--center` falls outside the configured region.

### HackRF tuning notes

The single `--gain=DB` knob maps across HackRF's three independent stages, but real-world deployments often benefit from per-knob control. Use `--hackrf-lna=N` (0..40 step 8), `--hackrf-vga=N` (0..62 step 2), and `--hackrf-amp` / `--hackrf-amp-off` to set them explicitly.

**Watch out for close-range desense.** A Meshtastic node sitting 1-2 meters from your HackRF antenna can produce enough RF to overload the analog mixer regardless of LNA gain — the ADC won't clip (signal looks fine), but mixer intermodulation products inside the band corrupt the demod's symbol detection. Symptoms: high SNR (25-30 dB) but every frame from the close node has `payload_crc_ok: false`, and the topology fills with bit-flipped phantom node IDs (`!471c1b98` instead of the real `!433c0b98`, etc.). Two practical fixes:

- Move the HackRF physically further from the node (5+ ft / different room).
- Inline a 6-10 dB SMA pad between the antenna and HackRF.

Distant signals are unaffected by this and decode cleanly even with the close node hammering the front end. The `payload_crc_ok` field is the diagnostic; if you only see CRC failures from one specific node and clean frames from others, it's RF physics not a software bug.

## Outputs

- **JSON feed** to stdout (always when running) and to UDP endpoints (`--feed=HOST:PORT`, repeatable)
- **MQTT** publish (`--mqtt=HOST[:PORT]`, topic `meshtastic/<station-id>` by default, override with `--mqtt-topic`)
- **ZMQ PUB** for multi-consumer (`--zmq=tcp://*:7008`); optional CurveZMQ encryption with `--zmq-curve-secret=PATH` (generate keypair via `--zmq-curve-keygen=PATH`)
- **CoT XML multicast** (`--cot-multicast=239.2.3.1:6969`) -- republishes every positioned node (regular Meshtastic POSITION packets *and* ATAK PLIs) as Cursor-on-Target XML to a multicast group. Any LAN ATAK-CIV / WinTAK / iTAK picks them up automatically -- no TAK Server required. CoT UIDs are prefixed with `--station-id` when set so multi-station deployments don't collide.
- **PCAP** streaming export (`--pcap=PATH` for a rotating file, `--pcap-fifo=PATH` for a named pipe Wireshark can attach to live). Each LoRa frame is wrapped in DLT_USER0 with a libpcap header.
- **Daily-rotated gzipped JSONL archive** (`--archive=DIR`) -- every emitted event appended to `DIR/meshtastic-YYYYMMDD.jsonl.gz`, rotated at UTC midnight. SIEM-friendly.
- **Built-in web dashboard** (`--web=8888`) -- four tabs (see below)

## Web dashboard

`--web=8888` opens four tabs:

- **Live** -- Leaflet map with node markers + trail polylines (last 8 fixes per node). Nodes table with search box, sortable columns (ID / Name / SNR / Frames / Last seen), CSV export. Click any row to slide in a per-node drawer: name + id, metrics, last-60 SNR sparkline, recent text messages, recent positions, channels-seen-on. Channels table (by hash). Messages and Discoveries panels.
- **Activity** -- per-preset cards, one per Meshtastic preset (ShortTurbo, ShortFast, ShortSlow, MediumFast, MediumSlow, LongFast, LongMod, LongSlow, LongTurbo). Each card shows fpm (60-second rolling), cumulative frames, decrypted/total channel ratio, sparkline, and the channel sub-list (channel name when decrypted, `(encrypted)` otherwise). Idle presets render greyed.
- **Topology** -- force-directed graph. Nodes sized by frame count, edges colored by SNR. Real edges from `NEIGHBORINFO_APP` packets and resolved relay-hop hints. A synthetic "RX" station at canvas center has a faint dashed pseudo-edge to every node this sniffer hears, so even a sparse mesh with no NEIGHBORINFO traffic gives a useful picture (what *you* are receiving). Hover to highlight; click any real node to open the drawer.
- **Config** -- runtime forms for adding keys, importing `meshtastic.org/e/` channel-share URLs, adding extra-frequency decoder slots, changing CoT multicast destination -- all without restarting the binary.

Equivalent endpoints exposed at `POST /api/keys`, `POST /api/share-url`, `POST /api/extra-freq`, `POST /api/cot-multicast` for scripting. Optional bearer-token auth via `--api-token=SECRET` (clients send `Authorization: Bearer SECRET`).

## JSON event format

`./meshtastic-sniffer --schema` dumps the canonical JSON Schema 2020-12 for every event the binary emits.

**Per-frame fields:** `from`, `to`, `packet_id`, `channel_hash` (1-byte routing hash from the radio header), optional `slot_id` (which polyphase channelizer slot caught the frame), `hop_limit`/`hop_start`, `rssi_db`/`snr_db`.

**Quality telemetry — silent when healthy, present when actionable:**
- `payload_crc_ok: false` — CRC was present and failed (frame bytes are corrupt; absence implies CRC passed)
- `cfo_hz` — only when |drift| > 100 Hz (radio is well-tuned otherwise)

**Multilateration timing:** `station_t_ns` (host-realtime ns at first-replica receive) + `station_t_acc_ns` (operator-self-reported clock-discipline class). Set `--station-t-acc-ns=N` per station: 100 for GPSDO+1PPS, 1000 for chrony+PPS, 1000000 (default) for NTP-class. The fusion-side mlat solver weights observations by this value.

**Decoded-port fields** (text, lat/lon, telemetry, etc.) appear only when the channel key is known *and* the payload parses *and* the LoRa CRC passed. CRC-failed frames are gated explicitly: even when AES-CTR happens to produce parseable-looking bytes from corrupt ciphertext, those bytes are suppressed and the frame is reported as `decrypted: false`. This prevents fictitious POSITION / TEXT_MESSAGE decodes from showing up on the dashboard or in the JSON feed.

**Top-level `event` discriminator** distinguishes from regular packet events:
- `STATS` — periodic msps + cumulative frames + decryption rate
- `OFF_GRID_LORA` — scanner detected LoRa-shaped energy outside the configured grid
- `REPLAY_SUSPECTED` — duplicate `(from, packet_id)` outside the normal mesh retransmit window
- `GEOFENCE_ENTRY` / `GEOFENCE_EXIT` — positioned node crossed a polygon boundary
- `PSK_DISCOVERED` — `--psk-wordlist` attack found a key
- `GEOLOCATED` — fusion-side mlat solver produced an emitter position estimate
- `HEARTBEAT` — DEALER C2 session keepalive (when `--c2-dealer` is configured)

The JSON wire format changed in May 2026: the per-event `channel` field was renamed to `channel_hash` to reduce confusion with both decoder slot index and human-readable channel name. Downstream consumers reading the old field name need a one-line rename.

## Stats heartbeat

Every 5 seconds the binary prints a one-line summary to stderr so you can tell at a glance whether samples are flowing and frames are being decoded:

```
[stats] 18.45 Msps in, 12 LoRa frames, 9 decrypted
```

`off-grid hits` is appended only when the scanner is enabled (`--scan*` or `--alert-off-grid`).

## Build

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

Dependencies: cmake >= 3.9, FFTW3 (float), pthreads, OpenSSL (AES-CTR), and at least one SDR library for live capture. CMake auto-detects every backend you have installed.

```bash
sudo apt install build-essential cmake pkg-config libfftw3-dev libssl-dev
sudo apt install librtlsdr-dev libhackrf-dev libbladerf-dev libuhd-dev \
                 libsoapysdr-dev libairspy-dev
# SDRplay native API: install from sdrplay.com/api
# Optional output sinks
sudo apt install libmosquitto-dev libzmq3-dev
```

## First-time use (30 seconds)

You have a Meshtastic node and an SDR. You want to see what your node and its neighbours are saying.

1. **Get your channel key.** In the Meshtastic phone app, open the channel, tap "Share Channel," and copy the URL -- it looks like `https://meshtastic.org/e/#CgM...`. That URL contains the channel name and the AES key in a small protobuf payload.

2. **Plug in the SDR.** Run `./meshtastic-sniffer --list` to confirm it's detected.

3. **Run with a sensible default + paste your channel URL:**

   ```bash
   ./meshtastic-sniffer --hackrf --share-url='https://meshtastic.org/e/#CgM...' --web=8888
   ```

   The binary picks a sample rate and center frequency from the SDR + region (`US` by default -- override with `--region=EU_868` etc.). It opens the dashboard at `http://localhost:8888`.

4. **If nothing shows up after a minute**, check stderr -- the binary prints loud warnings when no samples are flowing or no LoRa frames have decoded. Common causes: gain too low (`--gain=40`), wrong region, no node in range. The HackRF default is LNA=0 / VGA=30 -- right for close traffic but turn `--gain` up for distant captures.

5. **Adding more channels later:** open the dashboard, click **Config** tab, paste another `meshtastic.org/e/` URL, hit Add. Done -- no restart needed.

## Quickstart

```bash
# Casual: defaults pick up rate/center for your SDR + region.
./meshtastic-sniffer --hackrf --keys=default --web=8888

# Or paste your channel-share URL once and skip the dashboard:
./meshtastic-sniffer --hackrf --share-url='https://meshtastic.org/e/#CgM...' --web=8888

# Power: stare at every preset on US 902-928, dump per-channel stats every 5s,
# tee raw IQ to disk for later replay, multi-station-tagged feed to a collector:
./meshtastic-sniffer --bladerf --presets=all \
                    --keys-file=$HOME/.config/meshtastic-sniffer/keys \
                    --stats-json=/run/meshsniff/stats.json \
                    --iq-record=/data/capture-$(date +%s).cs8 \
                    --feed=collector:5588 --station-id=basement-rx --web=8888

# Receive over a network feed (any sender that emits VITA-49 VRT):
./meshtastic-sniffer --vita49=4991 --keys=default --web=8888
# (sample rate + center freq come from the VITA-49 IF-context packets
#  automatically when the sender emits them; otherwise pin via --rate/--center)

# US LongFast on a HackRF with explicit overrides:
./meshtastic-sniffer --hackrf --region=US --presets=LongFast \
                    --rate=20000000 --center=910000000 \
                    --keys=default --web=8888

# Replay an IQ capture (sample rate / freq / format pulled from .sigmf-meta):
./meshtastic-sniffer --file=capture.cf32 --keys=default

# Multi-output: stdout JSON + UDP feed + MQTT + ZMQ + CoT multicast + web
./meshtastic-sniffer --hackrf --keys=LongFast=default,Ops=hex:00112233...ff \
                    --feed=collector:5588 --mqtt=mqtt.local \
                    --zmq=tcp://*:7008 --cot-multicast=239.2.3.1:6969 \
                    --web=8888 --station-id=basement-rx

# Off-grid scan only (no decode, just discover non-standard LoRa freqs):
./meshtastic-sniffer --hackrf --scan --alert-off-grid

# Long-running deployment: gzipped daily archive, geofence alerts, PSK dictionary
# attack against unknown channels, replay-attack flagging on duplicate (from, pid):
./meshtastic-sniffer --hackrf --keys-file=$HOME/.config/meshtastic-sniffer/keys \
                    --archive=/var/log/meshtastic \
                    --geofence=$HOME/.config/meshtastic-sniffer/zones.ini \
                    --psk-wordlist=/usr/share/dict/words \
                    --pcap=/data/meshtastic.pcap --web=8888

# Multi-station: register with a meshtastic-fusion aggregator on the same VPN,
# expose a NAT-friendly DEALER C2 socket back to it.
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

The generator builds a real Meshtastic frame (16-byte radio header + AES-128-CTR encrypted Data envelope with channel-hash for the default key) and runs it through gr-lora_sdr's modulator. Useful both as a smoke test of the whole pipeline and for iterating on the LoRa demod's sync/header/payload decoding.

`MESHTASTIC_LORA_TRACE=1` enables a per-symbol state-machine trace on stderr, useful for debugging decode against a known-good reference.

## Self-test and smoke test

`./meshtastic-sniffer --selftest` runs two checks:

1. **Channelizer**: synthesizes a 0.1 sec tone at 902.625 MHz inside a 20 MHz capture centered on 910 MHz; configures four 250 kHz channels at the US LongFast slot 0..3 grid; verifies the tone lands in slot 2 with the expected power profile.
2. **AES + multi-key + protobuf**: builds a synthetic Meshtastic packet (`TEXT_MESSAGE_APP`, payload `"Hello"`, encrypted with the default key), runs it through the decode path, and verifies the callback fires with the right port + payload + channel name.

`bash tests/test_smoke.sh` adds SigMF auto-config, `--list`, web `/api/*` round-trip, STATS SSE heartbeat, and stats heartbeat. Both tests run clean under AddressSanitizer + UndefinedBehaviorSanitizer; ThreadSanitizer reports no data races on the keyset rwlock under concurrent `/api/keys` POST load.

## Honest limitations

Things this tool does not do today:

- No direction finding from a single SDR -- amplitude alone can't localize an emitter. Multilateration via 3+ stations works but requires GPSDO-locked SDRs for sub-100m accuracy (Tier-1); chrony+PPS hosts give ~300 m (Tier-2).
- 16 of the known port numbers are decoded into structured fields; others surface as raw bytes in the JSON event
- AdminMessage signature verification (ed25519) is not implemented yet -- admin packets are decoded but not validated
- CurveZMQ is sniffer-side only; the Go-based [meshtastic-fusion](fusion/) aggregator can't yet authenticate to a CURVE-protected PUB (limitation of `go-zeromq/zmq4` v0.17). Use a libzmq-based proxy or VPN-gate the link.
- Close-range front-end overload: a Meshtastic node within 1-2 m of the HackRF antenna corrupts demod via mixer intermodulation regardless of LNA gain. Surfaced via `payload_crc_ok: false`; mitigated by physical separation or an inline RF attenuator. See the *HackRF tuning notes* section above.

## Offline PSK recovery

A companion CLI tool [meshtastic-recover](recover/) reads captured pcaps (`--pcap=PATH`) and a wordlist, runs the same channel-hash prefilter + AES-CTR + protobuf-shape verifier the live decoder uses, and prints any keys that successfully decrypt one or more captured frames. OpenMP-parallel across all CPU cores. Output is in `--keys-file=` compatible format ready to feed back to the sniffer.

```bash
# Try the firmware default keys (simple1..simple255) against a capture
./meshtastic-recover --pcap=session.pcap --simple-keys --output=recovered.keys

# Add a passphrase wordlist (keeps default-key trials, adds dictionary attack)
./meshtastic-recover --pcap=session.pcap --simple-keys --wordlist=/usr/share/dict/words

# Re-decode the same capture using whatever keys were recovered
./meshtastic-sniffer --file=session.pcap --keys-file=recovered.keys
```

GPU acceleration via a [hashcat](https://hashcat.net) custom-mode plugin (status: working end-to-end on real-radio captures, pending upstream PR cleanup). The recover binary produces hashcat-compatible hash files via `--hashcat-export=PATH` and `--channel-name=NAME`. See [recover/README.md](recover/README.md) for the format spec and verifier algorithm.

Realistic attack surface: factory-default channels recover instantly; weak-passphrase channels recover from a rockyou-class wordlist in seconds; channels using a strong randomly-generated 16/32-byte PSK are not feasible to recover.

## License

GPL-3.0-or-later. See `LICENSE`. Copyright (c) 2026 CEMAXECUTER LLC.

This project is independent of and not affiliated with Meshtastic. "Meshtastic" is a trademark of [Meshtastic LLC](https://meshtastic.org). Protocol constants used here (default PSK, channel hash, AES-CTR nonce layout, region/preset tables) are interoperability facts derived from the upstream firmware at <https://github.com/meshtastic/firmware> (also GPL-3.0-or-later); no proprietary code is included.

### Upstream attribution

- **gr-lora_sdr** by Joachim Tapparel @ EPFL TCL Lab (<https://github.com/tapparelj/gr-lora_sdr>, GPL-3.0-or-later) -- significant portions of `lora.c`'s bit-level decode path (hard-decode Hamming, deinterleave, gray, dewhiten, preamble-mode-vote) are ported from gr-lora_sdr and verified bit-exact against its stage outputs. Per-stage citations appear inline at the relevant call sites in `lora.c`.
- **Meshtastic firmware** (<https://github.com/meshtastic/firmware>, GPL-3.0-or-later) -- the wire format, default PSK, simpleN PSK derivation, channel-hash function, AES-CTR nonce layout, region/preset tables, and port number assignments are all derived from the upstream firmware. Implementation here is original; only the on-the-air constants come from upstream.
- **Felipe Kersting** -- `blocking_queue.h` and `fair_lock.h` are vendored MIT-licensed primitives (Copyright (c) 2020). License preserved in each file.
