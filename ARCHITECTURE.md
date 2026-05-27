# meshtastic-sniffer architecture

Single-binary wideband Meshtastic LoRa receiver. One SDR -> one wide IQ stream -> polyphase channelizer -> N parallel LoRa decoders -> AES-CTR + protobuf decode -> stdout / UDP / MQTT / ZMQ (optional CurveZMQ) / CoT multicast / PCAP file or fifo / daily-rotated gzipped JSONL archive / web SSE.

## Pipeline

```
   SDR / VITA-49 / IQ file
            |
            v   sample_buf_t (int8 or float complex IQ)
        push_samples()
            |
            +-- channelizer_process_*()
            |   one or more pfb_t instances (one per bw_hz/os_factor group),
            |   critically-sampled M-channel polyphase filterbank:
            |     1. pre-shift NCO aligns input bin grid to channel grid
            |     2. forward commutator distributes input across M branches
            |     3. per-branch length-L FIR (Hamming-windowed sinc prototype)
            |     4. forward M-point FFT
            |     5. emit Y[bin] -> each registered bin's sink list
            |        |
            |        v   per-channel baseband at Fs/M
            |    on_channel_baseband() -> lora_decoder_feed()
            |        |
            |        v   2^SF samples per LoRa symbol
            |    [dechirp * conj(upchirp), N-point FFTW3f, argmax bin]
            |        |
            |        v   IDLE -> PREAMBLE_OK -> HEADER -> PAYLOAD -> DELIVER
            |    [Gray, diagonal deinterleave, Hamming(8,4), dewhiten, CRC16]
            |        |
            |        v   raw bytes (16-byte radio header + ciphertext)
            |    on_lora_frame() -> dedup ring (PFB bin-leakage filter)
            |        |
            |        v   (best replica picked at window expiry by drainer)
            |    mesh_packet_decode_with_radio()
            |        |
            |        v   channel-hash dispatch -> 1..few candidate keys
            |        |   -> AES-CTR decrypt -> protobuf parse_data_envelope
            |        v   mesh_event_t (port, payload, RSSI/SNR, channel name)
            |    on_mesh_event() -> feed_publish_event()
            |        |
            |        +-- stdout JSON
            |        +-- UDP feed (--feed=HOST:PORT, repeatable)
            |        +-- MQTT (--mqtt=HOST[:PORT], topic meshtastic/<station>)
            |        +-- ZMQ PUB (--zmq=tcp://*:7008, optional CurveZMQ via
            |        |   --zmq-curve-secret=PATH; --zmq-curve-keygen=PATH
            |        |   creates the keypair)
            |        +-- CoT XML multicast (--cot-multicast=GROUP:PORT)
            |        +-- libpcap (--pcap=PATH file or --pcap-fifo=PATH for
            |        |   live Wireshark via DLT_USER0)
            |        +-- Daily gzipped JSONL archive (--archive=DIR)
            |        +-- Geofence ENTRY/EXIT events (--geofence=PATH)
            |        +-- Web SSE (--web=PORT, all events tee'd to /events)
            |
            +-- psk_dict.c (when --psk-wordlist=PATH)
            |    background thread tries each wordlist entry against
            |    undecrypted frames; discovered keys auto-add to keyset
            |    and emit a PSK_DISCOVERED event.
            |
            +-- scanner_feed_*()  (when --scan / --scan-and-decode / --alert-off-grid)
                     |
                     v   N-point FFT, EWMA per bin, peakfind @ 4 Hz
                 OFF_GRID_LORA event with occupied-BW estimate,
                 only when peak isn't on the configured grid
                 and bandwidth >= 50 kHz (LoRa minimum is 62.5 kHz)
```

## File map

| File | Purpose |
|---|---|
| main.c | entry point, channel-set builder, signal handling, dedup ring + drainer, drainer-watchdog + stragglers counter, stats heartbeat, replay-attack flagging |
| options.{c,h} | full CLI parser, shared runtime state, per-backend gain controls |
| meshtastic.{c,h} | regions, presets, port enum, channel-hash, default PSK, AES nonce layout |
| channelizer.{c,h} | groups channels by `(bw_hz, os_factor)`, one PFB per group, atomic n_channels for runtime add |
| pfb.{c,h} | critically-sampled M-channel polyphase filterbank: pre-shift NCO + forward commutator + per-branch FIR + forward FFT |
| lora.{c,h} | LoRa CSS demod (state machine + Gray + Hamming + dewhiten + CRC + FFTW3f dechirp) -- bit-level stages ported from gr-lora_sdr |
| keyset.{c,h} | multi-key dispatch, channel-hash buckets, rwlock for runtime add; `keyset_add_raw` for hash-only inserts from PSK dictionary attack |
| psk_dict.{c,h} | background dictionary attack on undecrypted frames; on success adds the discovered key and emits PSK_DISCOVERED |
| protobuf.{c,h} | minimal varint/tag/wire-type reader |
| mesh_packet.{c,h} | radio header, AES-CTR via OpenSSL, multi-key try, Data envelope |
| mesh_decoders.{c,h} | 16 per-port decoders (POSITION, NODEINFO, TELEMETRY, ROUTING, TRACEROUTE, WAYPOINT, ADMIN, NEIGHBORINFO, KEY_VERIFICATION, MAP_REPORT, ATAK_PLUGIN, REMOTE_HARDWARE, DETECTION_SENSOR, PAXCOUNTER, STORE_FORWARD; TEXT_MESSAGE handled inline) |
| node_db.{c,h} | id -> name cache, used by CoT for callsigns |
| feed.{c,h} | JSON serialiser, fanout to stdout/UDP/MQTT/ZMQ/CoT/PCAP/archive/geofence/web |
| mqtt.c | libmosquitto sink (stub if not present) |
| zmq_pub.c | libzmq PUB sink (stub if not present); CurveZMQ server-side wiring |
| cot.{c,h} | CoT XML for ATAK PLIs and POSITION packets, multicast, runtime endpoint |
| pcap_out.{c,h} | libpcap streaming export; rotating file or named-pipe FIFO for live Wireshark, DLT_USER0 |
| archive.{c,h} | daily-rotated gzipped JSONL archive (`meshtastic-YYYYMMDD.jsonl.gz`) for SIEM ingest |
| geofence.{c,h} | INI-style polygon parser; ray-cast point-in-polygon; emits ENTRY/EXIT events |
| announce.{c,h} | `--announce-to=URL` periodic POST of this sensor's registry entry to fusion |
| c2.{c,h} | transport-independent C2 dispatch (`keys_add`, `share_url`, `extra_freq`, `cot_multicast`); shared between HTTP and DEALER paths |
| c2_dealer.{c,h} | outbound ZMQ DEALER socket (`--c2-dealer=tcp://fusion:7009`) for NAT-friendly C2; heartbeats + reply matching |
| schema.{c,h} | static JSON Schema 2020-12 definition emitted by `--schema` |
| scanner.{c,h} | wideband FFT, off-grid energy detector with occupied-BW estimate, spectrum snapshot |
| web.{c,h} | HTTP+SSE server, embedded Leaflet/Activity/Topology dashboard, `/api/*` endpoints with optional `--api-token` bearer auth |
| gpsd.{c,h} | gpsd client tagging events with station_lat/station_lon/station_alt_m |
| sigmf.{c,h} | `.sigmf-meta` reader for --file auto-config |
| file_src.{c,h} | CI8/CI16/CF32 IQ replay |
| hackrf/bladerf/rtlsdr/soapysdr/sdrplay/airspy/usrp/vita49.c | 8 SDR backends |
| simd_*.{c,h} | AVX2/SSE4.2/NEON/generic kernels (one per ISA tier, runtime-detected) |
| blocking_queue.h, fair_lock.h | MIT-licensed primitives (vendored, Felipe Kersting) |
| fusion/ | Go binary `meshtastic-fusion`: aggregator that subscribes to N sniffer ZMQ feeds, fans HTTP / DEALER C2 commands back, exposes a 5-tab dashboard. Includes hyperbolic-TDOA mlat solver in `fusion/mlat.go` that emits `GEOLOCATED` events when 3+ time-disciplined stations hear the same `(from, packet_id)`. See [fusion/README.md](fusion/README.md). |
| recover/ | Companion CLI binary `meshtastic-recover`: offline PSK recovery from a captured pcap + wordlist. Reuses `keyset.c`, `mesh_packet.c`, `meshtastic.c`, `protobuf.c` from the parent. OpenMP-parallel candidate loop with channel-hash 8-bit prefilter. Also produces hashcat-compatible hash files via `--hashcat-export=PATH` for the upcoming hashcat custom-mode plugin. See [recover/README.md](recover/README.md). |

Build is warning-free with `-Wall -Wextra -Werror=implicit-function-declaration`. AddressSanitizer + UndefinedBehaviorSanitizer + ThreadSanitizer all clean against the smoke-test suite.

## Polyphase channelizer

`pfb.c` implements a critically-sampled decimator-by-M polyphase filterbank. One PFB is created per unique LoRa bandwidth (500 / 250 / 125 kHz on US `--presets=all`), so the wide IQ stream is filtered once per bandwidth and split into FFT bins that feed the per-channel LoRa decoders.

At a high level:

1. Build a Hamming-windowed sinc prototype lowpass (length `L*M`, cutoff `1/(2M)`, L=12 by default)
2. Decompose into M polyphase branches: `h_p[i][k] = h[k*M + i]`
3. Per cycle of M input samples: forward commutator distributes across branches, each branch FIRs against its polyphase row, then one M-point FFT produces all M output bins at `Fs/M` rate
4. Dispatch each output bin to its registered sinks (the per-channel LoRa decoders)

This replaces a per-channel-cascade DDC approach. The structural win: filtering cost scales with the number of unique bandwidths, not with every configured Meshtastic channel. The inner FIR is `L` complex MACs per branch per output cycle, plus the M-point FFT — qualitatively much cheaper than running an independent DDC per channel.

The reverse-ring delay layout in `pfb_t.dly` (each branch's window stored newest-to-oldest, duplicated) keeps the dot product contiguous so the compiler can auto-vectorise it under `-march=native`. There is no hand-written AVX2 polyphase kernel today; the cost reduction is mostly architectural, not SIMD.

Channels are bound to PFB output bins via `pfb_register_bin` — multiple decoders may bind to the same bin (a bin's callback list is a tiny linked list). The pre-shift NCO multiplies input by `exp(-j*2*pi*pre_shift_hz/Fs * n)` so the FFT's bin 0 lines up exactly with the configured channel grid.

### Measured adjacent-channel rejection

Sweeping a CW tone across every grid slot in each US bandwidth group (`--selftest-rejection`, 20 Msps, 33,320 source/leak pairs across 125/250/500 kHz groups) yields:

| metric | dB | location |
|---|---|---|
| worst   | 49.94  | 250 kHz, source slot 52, leak slot 50 |
| median  | 100.42 | 250 kHz, source slot 64, leak slot 45 |
| best    | 134.63 | 125 kHz, source slot 141, leak slot 56 |
| mean    | 92.66  | — |

Reproduce: `./meshtastic-sniffer --selftest-rejection` (override `--region=` / `--rate=` / `--center=` to characterize a different grid). CSV written to `/tmp/meshtastic-pfb-rejection-<timestamp>.csv` with columns `rate_hz,bw_hz,source_ch,leak_ch,target_dbfs,leak_dbfs,acr_db,n_samples`.

The 49.94 dB worst-case is the system's actual adjacent-channel floor — measured end-to-end through the cs8 ingest path, polyphase FIR, FFT, and bin dispatch — not an asymptotic window property. Real-world leakage will additionally include SDR front-end and quantization contributions outside the channelizer.

Worst-case ACR vs source amplitude (`--selftest-rejection-amplitude`, US grid, cs8 ingest):

| amplitude (dBFS) | worst ACR (dB) |
|---|---|
| -40.0 |  4.15 |
| -20.0 | 28.70 |
| -10.0 | 41.19 |
|  -3.0 | 47.34 |
|  -0.1 | 49.65 |

Monotonically rising; consistent with the cs8 ingest's quantization floor setting the measurement ceiling at low input. The channelizer's structural rejection becomes visible once the tone clears that floor, converging on the `--selftest-rejection` full-amp number (~50 dB) by -3 dBFS.

Two-tone test (`--selftest-rejection-twotone`, strong tone in slot N, weak tone at -20 dBFS in slot N+1, strong swept across -20..-0.1 dBFS): max |desense| of weak-bin power was **0.56 dB** — measurement noise. The channelizer doesn't generate software-side adjacent-channel desense. Any close-range desense observed in the field is therefore SDR front-end (mixer overload), not our processing.

Off-bin sweep (`--selftest-rejection-offbin`, tone at source+δ*BW for δ ∈ {0, 1/8, 1/4, 3/8, 1/2}): at δ=0.5 the energy distributes equally between source bin and source+1 bin (both at ~-9 dBFS while a single on-bin tone peaks at ~-3 dBFS), with non-adjacent bins ≤ -63 dB. Practical consequence: an emitter drifted to the half-bin point between channel centers lights up both adjacent grid channels simultaneously. The off-grid scanner thresholds should expect this split.

Processing-gain / dynamic-range sweep (`--selftest-rejection-procgain`, AWGN added at the cs8 ingest, full-band input SNR vs per-bin output SNR):

| BW (kHz) | M | 10·log10(M) (dB) | measured mean (dB) | residual (dB) |
|---|---|---|---|---|
| 500 |  40 | 16.02 | 17.17 | +1.15 |
| 250 |  80 | 19.03 | 20.12 | +1.09 |
| 125 | 160 | 22.04 | 23.14 | +1.10 |

Per-bin output SNR exceeds input full-band SNR by `10·log10(M)` plus a consistent ~+1 dB offset across all three BW groups. That small residual is consistent with the prototype filter's actual bin/noise bandwidth and normalization, but has not been analytically subtracted from the measurement. Sigma=0.5 LSB rows in the CSV are below the cs8 quantization step and have unreliable statistics; sigma ≥ 1.0 LSB rows give the stable measurement.

### LoRa-chirp leakage, not CW

The `--selftest-rejection*` numbers above were taken with a CW tone. A LoRa chirp is broadband — it sweeps the full channel BW every symbol and its instantaneous energy passes right through the channel boundary, where any real filter is at most -6 dB. So chirp leakage looks very different from tone leakage in the same PFB. `tests/test_pfb_bin_power.c` measures per-bin RMS for a synthetic LoRa frame injected at a known slot.

Profile for the production config (M=80, L=12), one SF9/BW250 frame at slot 40 (915.125 MHz):

| bin offset from target | noiseless | with AWGN at 15 dB in-bin SNR |
|---|---|---|
| 0 (target) | 0 dB ref | 0 dB ref |
| ±1 | -3.6 dB | -3.2 dB (signal leakage still dominates) |
| ±2 | -14.6 dB | -10 to -15 dB |
| ±3 | -18.7 dB | (noise floor takes over) |
| ±40 (band edges) | -37.7 dB | -12.2 dB (noise floor) |

Reproduce: `tests/pfb_slot_leakage.sh` (counts decoder activity per slot) + `./build/test_pfb_bin_power --file=...` (per-bin RMS).

The shape is a clean Hamming-windowed sinc rolloff — the filter math is doing what L=12 lets it do. The -3.6 dB adjacent number is set by two things: the chirp itself crosses the bin boundary at every symbol, and L=12 is a fairly short prototype. A longer L (say 24) would noticeably tighten the rolloff; you don't get to zero adjacent leakage but you can push it down. We haven't paid that 2× FIR cost yet because the real failure mode below has a cheaper fix.

In practice: a strong nearby transmitter (close-range, modest attenuation) drops a -3 dB coherent copy into each adjacent slot and a -10 to -20 dB copy a few slots out. In a noiseless test that's enough for the LoRa preamble check (peak > 2× noise *inside* the dechirped FFT, not vs. RF thermal) to lock the state machine on the leaked copy. At realistic mesh-distance SNR (~15 dB in-bin), thermal noise drowns the far-bin leakage and only ±1/±2 adjacent slots still produce phantom decodes — those get folded into the CRC-pass cluster by the tier-3 dedup rule (`CRC-pass winner suppresses CRC-fail copies in same SF/BW within the emit window`) so the published feed sees one frame per TX.

**Operational note for close-range deployments.** A 900 MHz transmitter within a few meters of the SDR antenna can light up same-SF phantom decoders across many slots. The published feed is protected, but demod CPU is still spent on the phantoms before they're suppressed. Attenuate the close transmitter or move it physically further if CPU headroom matters. A pre-demod energy gate (drop a channel's decoder feed when its RMS sits well below the group peak in a short window) is the next planned fix — much cheaper than redesigning the prototype filter.

### Async sink dispatch

The PFB writes FFT outputs into per-sink ring buffers (`SINK_RING_N = 4`, 1024 samples each). When a buffer fills, ownership passes to a worker in a shared pool sharded by `channel_id % n_workers` (default `min(nproc-1, 8)` after live tuning on the 16-core B205mini host). Each LoRa decoder is touched by exactly one worker, so per-channel state stays single-threaded without locks. The PFB thread blocks on a full free pool rather than dropping samples; this is the only backpressure path in the pipeline.

Combined with the sample-pump queue between the SDR recv thread and the channelizer thread (see *Live throughput* below), this keeps `lora_decoder_feed` off the channelizer hot path entirely.

## PFB bin-leakage dedup

Each LoRa transmission lights up roughly 30 leakage replicas across adjacent PFB output bins. Per-replica bit errors are independent across bins; the cleanest decode is whichever bin had the highest SNR. Picking the first replica that arrives is random; picking the highest-SNR replica is deterministically the best-quality copy.

Implementation in `main.c`:

1. New replica arrives -> compute payload fingerprint (64-bit XOR-fold of payload bytes; bit-error replicas produce near-identical fingerprints, real transmissions produce uncorrelated ones)
2. Find an existing cluster within Hamming distance 14 (real transmissions typically differ by ~32 bits; bit-error replicas by 1-5)
3. If found and this replica has higher SNR: replace cluster's stored best
4. If not found: open a new cluster, schedule emit at `now + 30 ms`
5. Drainer thread polls every 5 ms; when a cluster's emit time passes, hand its best-stored replica to `mesh_packet_decode_with_radio` -- single attempt, with the cleanest SNR copy = best decrypt odds

Density-safe: 100 simultaneous distinct transmissions create 100 distinct clusters (random fingerprints don't collide within 14 Hamming bits). The 30 ms window swallows leakage cluster from a single chirp without merging adjacent unrelated transmissions.

Result: one JSON line per real transmission, regardless of how many leakage replicas the channelizer emitted.

The drainer thread stamps a wall-clock heartbeat (`g_drainer_last_tick_us`) every 5 ms tick. The stats heartbeat checks this each cycle; if the drainer has gone silent for more than 5x the dedup window (150 ms), `[stats] WARN dedup drainer silent for ...` lands on stderr -- so a wedged drainer surfaces within seconds rather than silently swallowing every frame. A `g_dedup_stragglers` atomic counts emits that came in more than 2x the window late (CPU-saturation diagnostic) and ships out in the SSE STATS event so the dashboard can show it.

## Threading

```
main thread:
  -- options_parse()
  -- simd_init()
  -- build_channel_set() / keyset / channelizer / scanner / feed / web init
  -- create dedup_drainer_thread (5 ms tick, batches expirations under one lock)
  -- create stats_thread (1 s tick + 5 s heartbeat to stderr + STATS SSE)
  -- create input_thread (one of: hackrf_stream_thread, ..., file_src_thread, vita49_thread)
  -- poll loop: while (running) usleep(100000)
  -- pthread_join + cleanup

input_thread:
  drains the SDR (or file / VITA-49 socket) into sample_buf_t,
  calls push_samples() in this thread.

push_samples() (called from input_thread, not its own thread):
  -- enqueue sample_buf_t into the sample-pump queue and return quickly

sample-pump thread:
  -- dequeue sample_buf_t and run the original DSP path:
  -- channelizer_process_int8/float
       -> pfb_process per group (OpenMP fanout when available)
            -> per-bin sink buffers submitted to sharded PFB workers
                 -> on_channel_baseband -> lora_decoder_feed
                 -> state machine -> on_lora_frame
                      -> dedup ring insert (under g_dedup_mu)
  -- scanner_feed_int8/float -> wideband FFT -> peakfind -> on_off_grid_discovery

dedup_drainer_thread:
  every 5 ms wakes up, batches up to 64 expired clusters under one
  lock acquire, then for each: mesh_packet_decode_with_radio ->
  on_mesh_event -> feed_publish_event -> stdout / UDP / MQTT / ZMQ /
  CoT / web SSE.

web thread:
  accept() loop, single-threaded request handling.
  Serves GET / (dashboard HTML), GET /events (SSE upgrade),
  POST /api/keys, POST /api/share-url, POST /api/extra-freq, POST /api/cot-multicast.
  SSE clients are kept in a small list (max 8) and broadcast to from
  feed_publish_event() via web_publish_line().

stats thread:
  every 1 s wakes up; every 5 s prints stderr heartbeat and pushes a
  STATS SSE event so the dashboard's persistent header has live counts.
```

All cross-thread state uses one of:

- `volatile sig_atomic_t running` (set by signal handler, polled by every thread)
- `__atomic_*` for hot counters (g_samples_total, g_frames_total, ...) and `channelizer.n_channels` (release/acquire ordering for race-free runtime channel addition)
- `pthread_rwlock_t` on `keyset_t` (write-lock around add, read-lock during decode lookup-and-decrypt)
- `pthread_mutex_t` on web SSE client list, cot endpoint state, node_db, dedup ring

## Multi-key dispatch (no per-packet brute-force)

Meshtastic frames carry a 1-byte `channel` field in the radio header equal to `xorHash(channel_name) ^ xorHash(psk)`. At `keyset_add` time the same hash is precomputed for each loaded `(name, psk)` pair and bucketed into `buckets[256]`. Per packet `header.channel` reads, looks up the bucket, and tries the (typically 1, occasionally 2) candidate keys. A successful protobuf parse is the confirmation. **Adding more keys does not slow per-packet decode** -- steady-state cost is one AES-CTR op + one protobuf parse, regardless of how many keys are loaded.

Bucket capacity is 7 collisions per single-byte hash. With well-distributed keys ~50 entries fit before the first bucket fills.

## Runtime mutability

The web Config tab can add keys, paste channel-share URLs, add extra-frequency decoder slots, and change the CoT multicast destination -- all without restarting the binary.

- `keyset_t` has a `pthread_rwlock_t` -- `keyset_add` takes the write lock briefly, `keyset_lookup` callers hold the read lock for the duration of lookup-and-decrypt. New keys take effect on the very next packet.
- `channelizer_t::n_channels` is `__atomic_store_n`-released after the new channel pointer is fully initialised; the hot loop does `__atomic_load_n`-acquire. Newly-added channels start receiving samples on the next channelizer_process_* call.
- `cot.c` keeps the multicast destination behind a mutex; `cot_set_endpoint(host, port)` reopens the socket atomically. Empty body to `POST /api/cot-multicast` disables CoT entirely.
- `scanner_t` known-grid array is replaced wholesale on each `scanner_set_known_grid` call; new extra-freq slots immediately start being excluded from the off-grid alert path.

## Validation

What's verified:

- **Channelizer routing** (smoke-tested in `tests/test_smoke.sh`): synthetic tone at 902.625 MHz lights up channel 2 at -2.13 dB inside a 20 MHz capture
- **AES + multi-key + protobuf round-trip**: synthesized `TEXT_MESSAGE_APP` packet decodes back to "Hello"
- **LoRa bit-level stages**: hard-decode Hamming, deinterleave, gray, dewhiten verified bit-exact against gr-lora_sdr stage outputs (fixtures at `tests/fixtures/lora_stages/`)
- **End-to-end LoRa decode**: real-radio HackRF capture on US LongFast / ShortFast / ShortTurbo decrypts back to plaintext text+position+nodeinfo
- **SigMF auto-config**: rate / freq / datatype picked up from `.sigmf-meta` sibling
- **All 4 web `/api/*` endpoints**: round-trip via curl
- **STATS SSE event**: arrives at the dashboard within one heartbeat
- **AddressSanitizer + UndefinedBehaviorSanitizer**: zero findings on the smoke-test suite (selftest, file replay, web API hits, key adds)
- **ThreadSanitizer**: zero data races under concurrent `/api/keys` POSTs hitting while the demod thread is in `keyset_lookup`
- **Live throughput**: short B205mini validation runs reached 26.02-26.03 Msps at `--presets=all` (1024 concurrent channels covering full US 902-928 MHz: 52 ShortTurbo + 104 each of ShortFast/Slow/MediumFast/Slow/LongFast + 208 each of LongModerate/LongSlow + 36 LongTurbo), zero `OOO` overflows, on a 16-core host with `--usrp-otw=sc8`. A later 7.8-hour soak was stable with clean worker/pump drains and no memory/FD/thread leak, but averaged 22.72 Msps with the old 15-worker default and a steady trickle of UHD overflows. A tuning matrix found 8 sink workers best on that host (25.30 Msps mean); that is now the default. The remaining long-run bottleneck is sustained DSP throughput. File-replay A/B harness (`tests/ab_replay.sh`) on a 4 GB lf.cs8 capture matches an 8-frame CRC-pass set bit-for-bit across runs.

Known runtime concerns deliberately not blocked-on:

- SDRplay's proprietary `libsdrplay_api.so.3` has a double-free in its `sdrplay_api_Close()` exit handler (third-party; surfaces only at process exit when `--list` enumerated SoapySDR drivers). Not actionable from our side.

## Self-test entry points

`./meshtastic-sniffer --selftest` runs two synthesized smoke checks (channelizer + AES end-to-end). `bash tests/test_smoke.sh` adds SigMF auto-config, `--list`, web `/api/*` round-trip, STATS SSE heartbeat, and stats heartbeat. Both run clean under sanitizers (`-fsanitize=address,undefined`).

## Sensitivity benchmark + open soft-decode question

`tests/sensitivity.py` synthesizes Meshtastic-shape LoRa frames (via `tests/sensitivity_synth.py` driving gr-lora_sdr's `lora_tx`), adds AWGN at a target SNR, and runs three decoders on the same `.cs8`:
- our `meshtastic-sniffer --extra-freq=…`
- gr-lora_sdr (`tools/gr_lora_usrp_rx.py`)
- dxlaprs `lorarx` (set `LORARX_BIN`, GPL-2.0+, built externally)

Each cell reports `ours_pass / gr_pass / lorarx_pass`. The baseline sweep (9 presets × 6 SNR cells) confirms our hard-decode path is within 0–2 frames of both references at every cell where they decode anything; gaps live at the cliff edge of each preset.

**Open research question** (documented because two attempts in this direction failed and it would be tempting to retry without recording why):

Soft decoding with a per-symbol confidence metric is a textbook ~2–3 dB sensitivity gain over hard. We tried two variants:

1. Replace per-bin `|Y|^2` with envelope `|Y|` in `compute_symbol_llrs` so one strong FFT peak doesn't dwarf cross-symbol confidence integration.
2. Port gr-lora_sdr's per-symbol `Ps_est/Pn_est` normalization from `fft_demod_impl.cc:148–225` exactly.

Both improved the synthetic harness substantially (Long-* SNR=-15 dB cells went 0/3/3 hard → 3/3/3 soft). Both **regressed real captures** on `b205_cluster2.cs8`: variant 1 dropped a distinct CRC-pass packet ID in 2 of 3 replays, variant 2 lost 2 of 4 distinct IDs every run. Branch `soft-decode-envelope` keeps variant 1 as a documented dead-end.

Working hypothesis: the soft confidence estimator assumes a single signal peak surrounded by Gaussian noise. Real wideband captures have PFB cross-bin leakage from adjacent slots and structured non-Gaussian interference, both of which violate that assumption and inflate the noise estimate. The pure-AWGN harness can't reproduce the failure mode.

Acceptance bar for the next attempt:
- An interference-aware noise estimator (e.g. order-statistic / trimmed-mean over non-peak bins, or excluding bins above a per-symbol percentile)
- No regression in `tests/sensitivity.py` 3/3/3 cells
- ≥ 4 distinct CRC-pass on `b205_cluster2.cs8` in 5 of 5 consecutive replays
- Hard remains default; soft optional via env knob until consistent on real captures across all four `tests/gr_lora_diff.py` fixtures

`MESHTASTIC_LORA_TRACE=1` enables a per-symbol state-machine trace on stderr, useful for debugging decode against a known-good reference.
