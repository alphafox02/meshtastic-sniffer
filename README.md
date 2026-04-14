# meshtastic-sniffer

Wideband Meshtastic LoRa receiver written in C. Captures one wide IQ slice from a single SDR and decodes **every Meshtastic channel and preset in the band simultaneously** — no per-channel hopping, no missed packets. With keys supplied, decrypts in parallel: text messages, GPS positions, node info, telemetry, routing, traceroute, ATAK plugin packets, and more — all surfaced from one capture.

Sister project to [iridium-sniffer](https://github.com/alphafox02/iridium-sniffer) and [inmarsat-sniffer](https://github.com/alphafox02/inmarsat-sniffer). Same SDR backend matrix, same threading style, same output ecosystem.

## What it decodes

- **All Meshtastic regions**: US (902-928), EU_868, EU_433, CN, JP, ANZ, KR, TW, RU, IN, NZ_865, TH, UA_433, UA_868, MY_433, MY_919, SG_923, KZ_433, KZ_863, NP_865, BR_902, PH_433/868/915, LORA_24
- **All presets**: ShortTurbo, ShortFast, ShortSlow, MediumFast, MediumSlow, LongFast, LongModerate, LongSlow, LongTurbo
- **All channel slots per preset**, in parallel from one capture (US LongFast = 104 slots at 250 kHz BW)
- **Multi-key AES-128 / AES-256-CTR** with channel-hash routing — supply many keys, the right one is auto-selected per packet via 1-byte channel hash. Adding more keys does NOT slow per-packet decode (steady state: 1 AES op per packet).
- **Per-port protobuf decode** for: `TEXT_MESSAGE_APP`, `POSITION_APP`, `NODEINFO_APP`, `TELEMETRY_APP` (DeviceMetrics + EnvironmentMetrics + PowerMetrics), `ROUTING_APP`, `TRACEROUTE_APP`, `WAYPOINT_APP`, `ADMIN_APP` (variant surfaced), `NEIGHBORINFO_APP` (per-neighbour SNR), `KEY_VERIFICATION_APP` (metadata only — hashes never re-emitted), `MAP_REPORT_APP`, `ATAK_PLUGIN`. Other ports surface as raw bytes in JSON.
- **ATAK port 72 decoder** — `TAKPacket` protobuf: callsign, team, role, battery, PLI (lat/lon/alt/speed/course) and GeoChat (to/text). PLIs are also republished as CoT XML over multicast (see Outputs).
- **Off-grid scanner** — flags LoRa-shaped energy outside the configured channel grid (hams on 6m/10m, custom-freq nodes, misconfigured devices); one OFF_GRID_LORA event per discovery, 3-confirm threshold to suppress one-shot spikes.
- **Per-frame RSSI/SNR** carried through from the LoRa demod into the JSON event and the dashboard nodes table.

## Hardware capacity

The number of presets/channels you can stare at simultaneously is set by the SDR's bandwidth.

| SDR | Bandwidth | Presets in one stare | Notes |
|-----|-----------|----------------------|-------|
| HackRF One | 20 MHz | All US presets at 910 MHz center | Matches `meshtastic_sdr` GnuRadio reference |
| BladeRF 2.0 | 56 MHz | Whole 902-928 ISM with margin | |
| USRP B210 | 56 MHz | Whole ISM band | |
| SDRplay RSPdx | 10 MHz | Most presets per region | |
| Airspy R2 | 10 MHz | Most presets per region | |
| RTL-SDR (R820T) | 2.4 MHz | One BW group | e.g. all LongFast 250 kHz slots that fit |
| Custom via SoapySDR | varies | — | |
| VITA 49 (network) | varies | — | Remote/distributed |
| IQ file replay | — | — | Offline analysis; auto-loads `.sigmf-meta` sibling |

`--list` enumerates all attached SDRs across every compiled-in backend.

## Outputs

- **JSON feed** to stdout (always when running) and to UDP endpoints (`--feed=HOST:PORT`, repeatable)
- **MQTT** publish (`--mqtt=HOST[:PORT]`, topic `meshtastic/<station-id>` by default, override with `--mqtt-topic`)
- **ZMQ PUB** for multi-consumer (`--zmq=tcp://*:7008`)
- **CoT XML multicast** (`--cot-multicast=239.2.3.1:6969`) — republishes every positioned node (regular Meshtastic POSITION packets *and* ATAK PLIs) as Cursor-on-Target XML to a multicast group. Any LAN ATAK-CIV / WinTAK / iTAK picks them up automatically — no TAK Server required. ATAK PLI packets carry their own callsign/team/role/battery; regular POSITION packets are labelled with the node's `long_name` from the NODEINFO cache. CoT UIDs are prefixed with `--station-id` when set, so multi-station deployments don't collide (`MESH-<station>-<callsign>`).
- **Built-in web dashboard** (`--web=8888`) — three tabs:
  - **Live**: Leaflet map with node markers + trail polylines (last 8 fixes per node), nodes table with last SNR per node, **CSV export** button, separate panels for chat messages and discoveries/ATAK events.
  - **Spectrum** (when `--web-spectrum`): scrolling waterfall canvas with live wideband FFT (256 bins downsampled from the scanner's 4096-bin FFT, 1 Hz update over the SSE stream).
  - **Config**: runtime forms for adding keys, pasting `meshtastic.org/e/` channel-share URLs, adding extra-frequency decoder slots, and changing the CoT multicast destination — all without restarting the binary.

## Web Config tab — runtime configuration

The dashboard's Config tab exposes four runtime controls that take effect *without restarting* the binary:

- **Add keys** (one spec per line — `ChannelName=SPEC`, where SPEC is `default | simpleN | hex:HHHH... | base64:....`). New keys take effect on the very next packet via the precomputed channel-hash dispatch table.
- **Channel-share URL** — paste a `https://meshtastic.org/e/#...` link; the protobuf payload is decoded into channel name + PSK and added to the keyset.
- **Add extra frequency** (`HZ:bw=BW:sf=SF:cr=CR`) — promote an off-grid sighting (or any custom freq) to a real decoder slot. Mid-stream channelizer addition; the new decoder picks up samples on the next channelizer step.
- **CoT multicast** — change or disable the multicast destination on the fly.

Equivalent endpoints exposed at `POST /api/keys`, `POST /api/share-url`, `POST /api/extra-freq`, `POST /api/cot-multicast` for scripting.

## Stats heartbeat

Every 5 seconds the binary prints a one-line summary to stderr so you can tell at a glance whether samples are flowing and frames are being decoded:

```
[stats] 18.45 Msps in, 12 LoRa frames, 9 decrypted, 1 off-grid hits
```

## Status

The full pipeline (channelizer + multi-key AES + protobuf + 12 per-port decoders + JSON/MQTT/ZMQ/CoT/web) is wired and validated end-to-end with a synthetic frame round-trip self-test plus a 4-test smoke suite (`tests/test_smoke.sh`). The LoRa CSS frame sync + FFT dechirp DSP is implemented in full structure (preamble detect, dechirp + FFT, Gray, Hamming, dewhitening, CRC) but is awaiting validation against real over-the-air or gr-lora_sdr-generated IQ before being declared production-ready. See `ARCHITECTURE.md` for the full pipeline diagram and design notes.

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

You have a Meshtastic node and an SDR (HackRF / RTL-SDR / etc). You want to see what your node and its neighbours are saying.

1. **Get your channel key.** In the Meshtastic phone app, open the channel, tap "Share Channel," and copy the URL — it looks like `https://meshtastic.org/e/#CgM...`. That URL contains the channel name and the AES key in a small protobuf payload.

2. **Plug in the SDR.** Run `./meshtastic-sniffer --list` to confirm it's detected.

3. **Run with a sensible default + paste your channel URL:**

   ```bash
   ./meshtastic-sniffer --hackrf --share-url='https://meshtastic.org/e/#CgM...' --web=8888
   ```

   The binary picks a sample rate and center frequency from the SDR + region (`US` by default — override with `--region=EU_868` etc.). It opens the dashboard at `http://localhost:8888`.

4. **If nothing shows up after a minute**, check stderr — the binary prints loud warnings when no samples are flowing or no LoRa frames have decoded. Common causes: gain too low (`--gain=40`), wrong region, no node in range.

5. **Adding more channels later:** open the dashboard, click **Config** tab, paste another `meshtastic.org/e/` URL, hit Add. Done — no restart needed.

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

# Receive over a network feed (e.g. KrakenSDR / SDR4SPACE / phantomized SDR via VITA-49):
./meshtastic-sniffer --vita49=4991 --keys=default --web=8888
# (sample rate + center freq come from the VITA-49 context packets automatically)

# US LongFast on a HackRF with explicit overrides (the old way, still works):
./meshtastic-sniffer --hackrf --region=US --presets=LongFast \
                    --rate=20000000 --center=910000000 \
                    --keys=default --web=8888

# Replay an IQ capture (sample rate / freq / format pulled from .sigmf-meta):
./meshtastic-sniffer --file=capture.cf32 --keys=default

# Multi-output: stdout JSON + UDP feed + MQTT + ZMQ + CoT multicast + web
./meshtastic-sniffer --hackrf --keys=LongFast=default,Ops=hex:00112233...ff \
                    --feed=collector:5588 --mqtt=mqtt.local \
                    --zmq=tcp://*:7008 --cot-multicast=239.2.3.1:6969 \
                    --web=8888 --web-spectrum --station-id=basement-rx

# Off-grid scan only (no decode, just discover non-standard LoRa freqs):
./meshtastic-sniffer --hackrf --scan --alert-off-grid

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

## Self-test

`./meshtastic-sniffer --selftest` runs two checks:

1. **Channelizer**: synthesizes a 0.1 sec tone at 902.625 MHz inside a 20 MHz capture centered on 910 MHz; configures four 250 kHz channels at the US LongFast slot 0..3 grid; verifies the tone lands in slot 2 with the expected power profile.
2. **AES + multi-key + protobuf**: builds a synthetic Meshtastic packet (TEXT_MESSAGE_APP, payload `"Hello"`, encrypted with the default key), runs it through `mesh_packet_decode`, and verifies the callback fires with the right port + payload + channel name.

Both must print `PASS`.

## License

GPL-3.0-or-later. See `LICENSE`. Copyright (c) 2026 CEMAXECUTER LLC.

This project is independent of and not affiliated with Meshtastic. "Meshtastic" is a trademark of [Meshtastic LLC](https://meshtastic.org). The protocol constants used here are interoperability facts; no proprietary code is included.
