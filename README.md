# meshtastic-sniffer

A passive Meshtastic LoRa receiver written in C. Takes one wide IQ slice from a single SDR and runs two decode paths in parallel:

- **Wideband polyphase channelizer**, always on. Configures one LoRa decoder per Meshtastic channel slot that fits inside the SDR's bandwidth, and runs them concurrently. On a B205mini at 26 Msps this covers the full US 902-928 MHz band with every channel decoded at once.
- **Focused decoder pool**, on demand. A bounded set of workers (default 2, up to 4) that wake on wideband preamble detections, rewind raw IQ from a short ring buffer, and run a cleaner per-slot decode at the same time. Idle until needed; never slows the wideband path.

Both paths feed the same dedup, JSON, MQTT, ZMQ, CoT, pcap, and web dashboard outputs. With keys supplied, the binary decrypts text, GPS, NodeInfo, telemetry, routing, ATAK PLI, and the other standard ports. Bit-level decode stages cross-check against [gr-lora_sdr](https://github.com/tapparelj/gr-lora_sdr) fixtures (the Tapparel/EPFL reference). Frames that pass CRC are tagged `payload_crc_ok: true` and `fields_trusted: true` so the operator can tell sightings from RF diagnostics.

Backends: HackRF, BladeRF, USRP (UHD), SDRplay, Airspy, RTL-SDR, any SoapySDR device, VITA-49/VRT over UDP, and IQ file replay.

Sister project to [iridium-sniffer](https://github.com/alphafox02/iridium-sniffer) and [inmarsat-sniffer](https://github.com/alphafox02/inmarsat-sniffer).

---

## What's new: scan-then-focus deep decode

The wideband channelizer covers everything in the slice at the rate the SDR can sustain, but it's a throughput tradeoff: bin-leakage between adjacent channels limits how much SNR each per-slot decoder sees. The new `--deep-decode=auto` mode adds a bounded pool of *focused* workers that pull raw IQ from a short ring buffer, run a cleaner per-slot DDC, and feed the same LoRa decoder. They wake on preamble locks from the wideband scanner and idle out after a hold-down.

Default is `off`, so the wideband-only path is unchanged for existing users. Enable per run:

```bash
./meshtastic-sniffer --usrp --rate=20000000 --center=915000000 \
                    --region=US --presets=all --keys=default \
                    --deep-decode=auto --focus-workers=2 \
                    --trusted-only --web=8888
```

A startup banner reports what's covered:

```
[coverage] center=915.000MHz rate=20.000Msps region=US presets=all
[coverage] scan: 905.000-925.000MHz, 800 channel(s) configured
[coverage] deep-decode: auto, workers=2, ring=500ms, rewind=20ms, hold=5.0s, min-snr=6.0dB
[output]   confirmed events only (--trusted-only)
```

`--trusted-only` is recommended for the user-facing JSON feed: it suppresses CRC-failed and untrusted-fields events. Add `--show-untrusted` to bring them back for RF diagnostics.

<details>
<summary>Focused-pool tuning flags</summary>

| Flag | Default | What it does |
| --- | --- | --- |
| `--deep-decode=off\|auto` | `off` | Master switch. `auto` enables the ring buffer and worker pool. |
| `--focus-workers=N` | `2` | Pool size, 1..4. Each worker runs a per-slot DDC + LoRa decoder. |
| `--focus-hold-s=S` | `5` | Seconds of frame inactivity before a worker idles back. |
| `--focus-rewind-ms=N` | `20` | How far back in the ring to rewind from a preamble lock. |
| `--focus-ring-ms=N` | `500` | Raw-IQ ring buffer history depth. |
| `--focus-min-snr-db=N` | `6` | Drop preamble locks below this SNR. Wideband decode is unaffected. |
| `--focus-freqs=Hz,Hz,...` | (none) | Restrict the pool to specific frequencies. Default: any slot can promote. |

When a worker can't keep up with the live sample rate, it disarms itself and counts the event as `samples_skipped` rather than continuing with a corrupted sample stream. `dropped_busy` and `below_snr` counters at shutdown surface what the pool turned away.

</details>

---

## Companion tools

- [meshtastic-recover](recover/) — offline PSK recovery from captured pcaps. OpenMP-parallel; a hashcat custom-mode plugin handles GPU.
- [meshtastic-fusion](fusion/) — multi-station aggregator (Go). Subscribes to N sniffer ZMQ feeds, runs hyperbolic-TDOA when 3+ time-disciplined stations hear the same packet.
- [meshtastic-wardrive](wardrive/) — mobile single-node capture (Go). SDR + GPS + SQLite + KML/KMZ/CSV/JSON exports.

---

## Install

### DragonOS Noble

DragonOS Noble already ships with HackRF, BladeRF, UHD, RTL-SDR, Airspy, SDRplay, SoapySDR, OpenSSL, FFTW3, libmosquitto, and libzmq. Don't `apt install` the SDR libraries on top — that can replace the DragonOS-tuned versions.

```bash
git clone https://github.com/alphafox02/meshtastic-sniffer.git
cd meshtastic-sniffer
mkdir build && cd build
cmake .. && make -j$(nproc)
```

For the Go companions: `cd fusion && go build ./...` and `cd wardrive && go build ./...` (Go 1.25+).

### Ubuntu / Debian

```bash
sudo apt install build-essential cmake pkg-config libfftw3-dev libssl-dev

# SDR libraries (install only what you have)
sudo apt install libhackrf-dev libbladerf-dev libuhd-dev \
                 librtlsdr-dev libairspy-dev libsoapysdr-dev

# Optional sinks
sudo apt install libmosquitto-dev libzmq3-dev libsodium-dev

git clone https://github.com/alphafox02/meshtastic-sniffer.git
cd meshtastic-sniffer && mkdir build && cd build
cmake .. && make -j$(nproc)
```

CMake prints which backends it found. Run `./meshtastic-sniffer --list` to confirm your SDR shows up.

---

## Quickstart

```bash
# Default: wideband-only, US region, default LongFast key, dashboard at :8888
./meshtastic-sniffer --hackrf --keys=default --web=8888

# Paste a channel-share URL from the Meshtastic app to import a key:
./meshtastic-sniffer --hackrf --share-url='https://meshtastic.org/e/#CgM...'

# B205 covering full US 902-928 MHz at 26 Msps, deep decode on:
./meshtastic-sniffer --usrp --rate=26000000 --center=915000000 \
                    --usrp-otw=sc8 --gain=40 --region=US --presets=all \
                    --keys=default --deep-decode=auto --trusted-only --web=8888

# Replay an IQ file:
./meshtastic-sniffer --file=capture.cf32 --keys=default

# Network IQ in (VITA-49):
./meshtastic-sniffer --vita49=4991 --keys=default

# List attached SDRs:
./meshtastic-sniffer --list

# Self-tests:
./meshtastic-sniffer --selftest
```

The dashboard's **Config** tab adds keys and channel-share URLs at runtime, no restart needed.

---

## Hardware capacity

The number of channels demodulated at once is set by the SDR's analog bandwidth and `--rate`. Any rate works: the channelizer fits whichever standard channels land inside `[center − rate/2, center + rate/2]`. US ISM is 902–928 MHz, so roughly 26 MHz of SDR bandwidth covers every US 250 kHz slot from one stare; below that, you cover a contiguous subset.

| SDR | Bandwidth | Coverage at typical rate |
| --- | --- | --- |
| HackRF One | 20 MHz | ~73-80 US LongFast slots; full coverage in EU_868 / EU_433 / most non-US regions |
| BladeRF 2.0 | up to 56 MHz | All US LongFast slots at ~26 Msps |
| USRP B205mini / B210 | up to 56 MHz | Full US 902-928 MHz at 26 Msps with `--usrp-otw=sc8` |
| SDRplay (RSPdx, RSP1A) | 10 MHz | One BW group + adjacent presets |
| Airspy R2 / Mini | 10 MHz | One BW group + adjacent presets |
| RTL-SDR (R820T) | 2.0 MHz | One BW group, ~8 LongFast slots |
| SoapySDR (LimeSDR, PlutoSDR, ...) | varies | Per-device |
| VITA-49 / VRT (network) | varies | Sample rate + freq from the IF-context packets |
| IQ file | — | `.sigmf-meta` sibling auto-loads rate/freq/format |

`--list` enumerates everything attached.

<details>
<summary>HackRF tuning (close-range desense, per-stage gain)</summary>

`--gain=DB` maps across the three internal stages, LNA-first. Per-knob: `--hackrf-lna=N` (0..40 step 8), `--hackrf-vga=N` (0..62 step 2), `--hackrf-amp` / `--hackrf-amp-off`.

Defaults (no flags): LNA=24, VGA=20, AMP off. A Meshtastic node sitting within 1–2 m of the antenna can produce enough RF to overload the mixer regardless of LNA gain; the ADC won't clip but intermod corrupts demod. Symptoms: high SNR with many `payload_crc_ok: false` from the close node, plus bit-flipped phantom IDs in topology. Fixes: move the antenna further away, add an inline SMA pad, drop the node's TX power, or `--hackrf-lna=8`.

</details>

<details>
<summary>USRP tuning (sustained 26 Msps, sc8 wire format)</summary>

Default UHD wire format is `sc16` (4 bytes/sample). At 26 Msps that's 104 MB/s over USB plus host-side sc16→fc32 conversion. On 16-core hosts this occasionally pushes UHD's recv FIFO past overflow (`OOO`).

Use `--usrp-otw=sc8` for sustained 26 Msps: halves USB bandwidth and host conversion work, no measurable SNR loss for LoRa.

```bash
./meshtastic-sniffer --usrp --rate=26000000 --center=915000000 \
                    --region=US --presets=all --keys=default \
                    --usrp-otw=sc8 --gain=40 --web=8888
```

Reference: short B205mini validation hits 26.02 Msps with all 1024 channels live; long soaks averaged 22.7 Msps under the old 15-worker default. The current 8-worker default ran ~25.3 Msps on the same hardware. If you still see bursty `OOO`, bump `MESHTASTIC_SAMPLE_QUEUE=N` above the 256 default.

</details>

---

## Outputs

- **JSON** on stdout, and to UDP endpoints (`--feed=HOST:PORT`, repeatable)
- **MQTT** (`--mqtt=HOST[:PORT]`)
- **ZMQ PUB** (`--zmq=tcp://*:7008`) with optional CurveZMQ (`--zmq-curve-secret=PATH`)
- **CoT XML multicast** (`--cot-multicast=239.2.3.1:6969`) for ATAK-CIV / WinTAK / iTAK
- **PCAP streaming** (`--pcap=PATH` rotating file, `--pcap-fifo=PATH` named pipe)
- **Daily gzipped JSONL archive** (`--archive=DIR`)
- **Web dashboard** (`--web=8888`): Live map, Activity, Topology, Config tabs

The web dashboard's Config tab adds keys and `meshtastic.org/e/` channel-share URLs at runtime. Equivalent endpoints at `POST /api/keys` and `POST /api/share-url`. Optional bearer-token auth: `--api-token=SECRET`.

<details>
<summary>JSON event schema</summary>

`./meshtastic-sniffer --schema` dumps the canonical JSON Schema 2020-12 for everything emitted.

Per-frame fields include `from`, `to`, `packet_id`, `channel_hash`, optional `freq_hz` and `slot_id`, `hop_limit`, `hop_start`, `rssi_db`, `snr_db`, and a `cfo_hz` drift estimate when out of tolerance.

Trust labels:

- `payload_crc_ok` is `true`/`false` when the wire carried an explicit CRC; absent for implicit-header frames.
- `fields_trusted: true` means the decoded `from`/`to`/`packet_id` and decoded port fields are safe for maps and node sightings. Untrusted frames stay in the feed for RF debugging.

Decoded port fields (text, lat/lon, telemetry) only appear when the key is known *and* the LoRa CRC passed *and* the payload parsed. AES-CTR will happily decrypt bytes from a CRC-failed frame, so those are suppressed.

Top-level `event` discriminator distinguishes the non-packet events: `STATS`, `OFF_GRID_LORA`, `REPLAY_SUSPECTED`, `GEOFENCE_ENTRY`/`EXIT`, `PSK_DISCOVERED`, `GEOLOCATED`, `HEARTBEAT`.

Multilateration timing: `station_t_ns` (host realtime ns at first-replica receive) and `station_t_acc_ns` (operator-self-reported clock-discipline class: 100 for GPSDO+1PPS, 1000 for chrony+PPS, 1000000 for NTP).

</details>

<details>
<summary>Stats heartbeat and pipeline diagnostics</summary>

Every 5 s, a one-line summary goes to stderr:

```
[stats] 18.45 Msps in, 12 LoRa frames, CRC 75.0% (6/8, 2 no-CRC), 9 decrypted
```

The CRC ratio is against frames that had an explicit CRC on the wire; `no-CRC` tallies implicit-header frames separately. With `--diagnostics`, the shutdown dump includes per-SF preamble/sync/header/CRC counters and focus-pool telemetry.

```
sample-pump:    submitted=147624 processed=147624 queue_waits=14841
pfb sink pool:  submitted=5113024 completed=5113024 queue_bp=0 freebuf_waits=0
focus-pool:     promotions total=18 matched_existing=15 assigned_idle=3
                dropped_busy=0 below_snr=12
```

`queue_waits` non-zero is fine for bursty traffic; sustained-high means DSP is behind. `queue_bp` and `freebuf_waits` should be zero in normal operation. Sink-worker count defaults to `min(nproc-1, 8)`; override via `MESHTASTIC_SINK_WORKERS=N`.

</details>

---

## Off-grid scan

`--scan` (no decode) or `--scan-and-decode` (both) enables an occupied-bandwidth scanner that flags LoRa-shaped energy outside the configured Meshtastic grid as `OFF_GRID_LORA` events. Useful for finding custom community channels, drone telemetry, or any non-standard LoRa traffic in the band.

```bash
./meshtastic-sniffer --hackrf --scan --alert-off-grid
```

---

## Offline PSK recovery

[meshtastic-recover](recover/) reads a pcap and a wordlist, runs the same channel-hash prefilter + AES-CTR + protobuf-shape verifier the live decoder uses, and prints any keys that decrypt. OpenMP-parallel; hashcat plugin handles GPU.

```bash
./meshtastic-recover --pcap=session.pcap --simple-keys --output=recovered.keys
./meshtastic-sniffer --file=session.pcap --keys-file=recovered.keys
```

Default channels and weak passphrases recover quickly; strong randomly-generated 16/32-byte PSKs are not feasible to recover.

---

## Multi-station

[meshtastic-fusion](fusion/) takes ZMQ feeds from N sniffer stations and runs hyperbolic-TDOA when 3+ time-disciplined stations hear the same packet. Sub-100 m with GPSDO+1PPS, around 300 m with chrony+PPS, more with NTP.

```bash
./meshtastic-sniffer --hackrf --keys=default --station-id=rooftop \
                    --gpsd=localhost:2947 --zmq=tcp://*:7008 \
                    --announce-to=http://fusion.local:9000/api/sensors
```

---

## Limitations

- A single SDR can't direction-find on amplitude alone. Multi-station with GPSDO-locked clocks is the path to sub-100 m.
- Strong close-range LoRa transmitters bleed chirp energy into adjacent same-SF channels via the wideband PFB. Dedup collapses the feed-level copies, and `--deep-decode=auto` helps individual slots get a clean second look, but the underlying physics doesn't go away. Add attenuation or distance.
- 16 known port numbers parse into structured fields. Others surface as raw bytes.
- AdminMessage ed25519 signature verification is not yet implemented; admin packets decode but aren't authenticated.
- CurveZMQ is sniffer-side only; the Go aggregator can't yet authenticate to a CURVE-protected PUB (`go-zeromq/zmq4` v0.17 limitation). Use a libzmq-based proxy or VPN-gate the link.

---

## Self-test

```bash
./meshtastic-sniffer --selftest    # channelizer routing + AES + protobuf end-to-end
bash tests/test_smoke.sh           # SigMF auto-config, --list, web /api round-trip
```

Both pass under AddressSanitizer + UBSan. ThreadSanitizer is clean under concurrent `/api/keys` load.

<details>
<summary>Generating a known-good test IQ from gr-lora_sdr</summary>

If `gnuradio` and `gr-lora_sdr` are installed, generate a real Meshtastic-shaped capture without any radio hardware:

```bash
python3 tools/gen_meshtastic_iq.py --out=/tmp/meshtastic_test.cf32 \
                                    --text="Hello" --sf=11 --bw=250000 --cr=5
./meshtastic-sniffer --file=/tmp/meshtastic_test.cf32 --rate=250000 \
                    --center=903000000 \
                    --extra-freq=903000000:bw=250000:sf=11:cr=5 \
                    --keys=default
```

`MESHTASTIC_LORA_TRACE=1` enables per-symbol decoder trace on stderr.

</details>

---

## License

GPL-3.0-or-later. Copyright (c) 2026 CEMAXECUTER LLC.

This project is independent of and not affiliated with Meshtastic. "Meshtastic" is a trademark of [Meshtastic LLC](https://meshtastic.org). Protocol constants used here (default PSK, channel hash, AES-CTR nonce layout, region and preset tables) are interoperability facts derived from the upstream firmware at <https://github.com/meshtastic/firmware> (also GPL-3.0-or-later); no proprietary code is included.

### Upstream attribution

- **gr-lora_sdr** by Joachim Tapparel @ EPFL TCL Lab (<https://github.com/tapparelj/gr-lora_sdr>, GPL-3.0-or-later). Significant portions of `lora.c`'s bit-level decode path (hard-decode Hamming, deinterleave, gray, dewhiten, preamble-mode-vote) are ported from gr-lora_sdr and verified bit-exact against its stage outputs. Per-stage citations are inline at the relevant call sites.
- **Meshtastic firmware** (<https://github.com/meshtastic/firmware>, GPL-3.0-or-later). Wire format, default PSK, simpleN PSK derivation, channel-hash function, AES-CTR nonce layout, region/preset tables, and port number assignments come from the upstream firmware. Implementation is original; only the on-the-air constants are derived.
- **Felipe Kersting** — `blocking_queue.h` and `fair_lock.h` are vendored MIT-licensed primitives (Copyright (c) 2020).
