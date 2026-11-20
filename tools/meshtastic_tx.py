#!/usr/bin/env python3
"""
meshtastic_tx.py -- transmit a Meshtastic packet with a HackRF.

Pipeline:
  1. Build a meshtastic.Data protobuf (TEXT_MESSAGE_APP by default, optionally
     preceded by a NODEINFO_APP packet so receivers show a name).
  2. Encrypt it with AES-CTR using the channel PSK (Meshtastic nonce layout).
  3. Prepend the 16-byte over-the-air header (to/from/id/flags/hash/...).
  4. Modulate it with gr-lora_sdr (sync word 0x2B, explicit header, CRC on,
     16-symbol preamble, LDRO auto) at a HackRF-legal sample rate.
  5. Shift it off the HackRF's DC/LO spur, convert to int8 IQ and play it
     with hackrf_transfer.

Requirements (Linux; DragonOS ships all of them):
  gnuradio + gr-lora_sdr, numpy, python3-cryptography, hackrf (hackrf_transfer)

Examples:
  # Dry run: write IQ files only, nothing is transmitted
  ./tools/meshtastic_tx.py --region US --text "hello mesh" --dry-run

  # Transmit on the default LongFast channel (US, slot 19 = 906.875 MHz)
  ./tools/meshtastic_tx.py --region US --text "hello mesh" --tx-gain 20

  # Private channel, also announce a name
  ./tools/meshtastic_tx.py --region EU_433 --channel MyChan \\
      --psk 'base64key==' --long-name "Sniffer TX" --short-name STX \\
      --text "test"

Only transmit on channels you operate, within your region's power and
duty-cycle limits. The HackRF is half-duplex: stop meshtastic-sniffer (or any
other program using the HackRF) before transmitting.

SPDX-License-Identifier: GPL-3.0-or-later
"""

import argparse
import base64
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import time

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------------------------
# Meshtastic constants (mirrors meshtastic.h in this repo)
# ---------------------------------------------------------------------------

# Expansion of the 1-byte default PSK "AQ==" (protocol-public, not a secret).
MESH_DEFAULT_PSK = bytes([
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
])

MESH_SYNC_WORD = 0x2B          # Meshtastic private sync word (SX126x 0x24B4)
BROADCAST = 0xFFFFFFFF

PORT_TEXT = 1
PORT_NODEINFO = 4

# name -> (display/channel name, SF, CR(5..8), BW sub-GHz, preamble)
PRESETS = {
    "SHORT_TURBO":   ("ShortTurbo",  7, 5, 500000, 16),
    "SHORT_FAST":    ("ShortFast",   7, 5, 250000, 16),
    "SHORT_SLOW":    ("ShortSlow",   8, 5, 250000, 16),
    "MEDIUM_FAST":   ("MediumFast",  9, 5, 250000, 16),
    "MEDIUM_SLOW":   ("MediumSlow", 10, 5, 250000, 16),
    "LONG_FAST":     ("LongFast",   11, 5, 250000, 16),
    "LONG_MODERATE": ("LongMod",    11, 8, 125000, 16),
    "LONG_SLOW":     ("LongSlow",   12, 8, 125000, 16),
    "LONG_TURBO":    ("LongTurbo",  11, 8, 500000, 16),
}

# name -> (f_lo MHz, f_hi MHz). Sub-GHz only: the HackRF tops out at 6 GHz but
# LORA_24 uses different bandwidths and is not handled here.
REGIONS = {
    "US": (902.0, 928.0),       "EU_433": (433.0, 434.0),
    "EU_868": (869.4, 869.65),  "CN": (470.0, 510.0),
    "JP": (920.5, 923.5),       "ANZ": (915.0, 928.0),
    "ANZ_433": (433.05, 434.79), "RU": (868.7, 869.2),
    "KR": (920.0, 923.0),       "TW": (920.0, 925.0),
    "IN": (865.0, 867.0),       "NZ_865": (864.0, 868.0),
    "TH": (920.0, 925.0),       "UA_433": (433.0, 434.7),
    "UA_868": (868.0, 868.6),   "MY_433": (433.0, 435.0),
    "MY_919": (919.0, 924.0),   "SG_923": (917.0, 925.0),
    "PH_433": (433.0, 434.7),   "PH_868": (868.0, 869.4),
    "PH_915": (915.0, 918.0),   "KZ_433": (433.075, 434.775),
    "KZ_863": (863.0, 868.0),   "NP_865": (865.0, 868.0),
    "BR_902": (902.0, 907.5),
}


def norm_key(name: str) -> str:
    return name.upper().replace("-", "_").replace(" ", "_")


def lookup_preset(name: str):
    key = norm_key(name)
    if key in PRESETS:
        return key, PRESETS[key]
    # accept "LongFast" style too
    flat = key.replace("_", "")
    for k, v in PRESETS.items():
        if k.replace("_", "") == flat or v[0].upper() == flat:
            return k, v
    raise SystemExit(f"unknown preset {name!r}; choose from {', '.join(PRESETS)}")


# ---------------------------------------------------------------------------
# Channel / frequency helpers (match firmware RadioInterface.cpp)
# ---------------------------------------------------------------------------

def djb2(s: str) -> int:
    h = 5381
    for c in s.encode("utf-8"):
        h = (h * 33 + c) & 0xFFFFFFFF
    return h


def channel_freq_hz(region: str, bw_hz: int, channel_name: str, slot):
    f_lo, f_hi = REGIONS[region]
    n_slots = int(((f_hi - f_lo) * 1e6) // bw_hz)
    if n_slots <= 0:
        raise SystemExit(f"region {region} is narrower than {bw_hz} Hz")
    if slot is None:
        slot = djb2(channel_name) % n_slots
    elif not 0 <= slot < n_slots:
        raise SystemExit(f"--slot must be 0..{n_slots - 1} for {region} @ {bw_hz} Hz")
    f = f_lo * 1e6 + bw_hz / 2 + slot * bw_hz
    return int(round(f)), slot, n_slots


def expand_psk(psk_arg: str) -> bytes:
    """Return the effective AES key (b'' means unencrypted channel)."""
    if psk_arg.lower() in ("none", ""):
        return b""
    if psk_arg.lower() == "default":
        psk_arg = "AQ=="
    raw = base64.b64decode(psk_arg)
    if len(raw) == 0:
        return b""
    if len(raw) == 1:
        idx = raw[0]
        if idx == 0:
            return b""
        key = bytearray(MESH_DEFAULT_PSK)
        key[-1] = (key[-1] + idx - 1) & 0xFF
        return bytes(key)
    if len(raw) < 16:
        return raw.ljust(16, b"\x00")
    if 16 < len(raw) < 32:
        return raw.ljust(32, b"\x00")
    if len(raw) > 32:
        raise SystemExit("PSK longer than 32 bytes")
    return raw


def xor_hash(b: bytes) -> int:
    h = 0
    for c in b:
        h ^= c
    return h


# ---------------------------------------------------------------------------
# Minimal protobuf encoding
# ---------------------------------------------------------------------------

def pb_varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def pb_field_varint(num: int, v: int) -> bytes:
    return pb_varint((num << 3) | 0) + pb_varint(v)


def pb_field_bytes(num: int, b: bytes) -> bytes:
    return pb_varint((num << 3) | 2) + pb_varint(len(b)) + b


def data_envelope(port: int, payload: bytes) -> bytes:
    """meshtastic.Data { portnum = 1; payload = 2; }"""
    return pb_field_varint(1, port) + pb_field_bytes(2, payload)


def user_protobuf(node_num: int, long_name: str, short_name: str) -> bytes:
    """meshtastic.User { id=1; long_name=2; short_name=3; hw_model=5 }"""
    return (pb_field_bytes(1, f"!{node_num:08x}".encode())
            + pb_field_bytes(2, long_name.encode("utf-8"))
            + pb_field_bytes(3, short_name.encode("utf-8"))
            + pb_field_varint(5, 255))          # HardwareModel.PRIVATE_HW


# ---------------------------------------------------------------------------
# Over-the-air frame
# ---------------------------------------------------------------------------

MAX_LORA_PAYLOAD = 255
HEADER_LEN = 16


def build_frame(inner: bytes, key: bytes, channel_name: str, from_node: int,
                to_node: int, packet_id: int, hop_limit: int,
                want_ack: bool) -> bytes:
    if key:
        nonce = (struct.pack("<Q", packet_id) + struct.pack("<I", from_node)
                 + b"\x00\x00\x00\x00")
        enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
        body = enc.update(inner) + enc.finalize()
    else:
        body = inner

    # flags: hop_limit[2:0] | want_ack[3] | via_mqtt[4] | hop_start[7:5]
    flags = (hop_limit & 7) | (0x08 if want_ack else 0) | ((hop_limit & 7) << 5)
    chan_hash = xor_hash(channel_name.encode("utf-8")) ^ xor_hash(key)

    hdr = (struct.pack("<III", to_node, from_node, packet_id)
           + bytes([flags, chan_hash, 0x00, from_node & 0xFF]))  # next_hop, relay_node
    frame = hdr + body
    if len(frame) > MAX_LORA_PAYLOAD:
        raise SystemExit(f"frame is {len(frame)} bytes; max is {MAX_LORA_PAYLOAD} "
                         f"(shorten the text by {len(frame) - MAX_LORA_PAYLOAD} bytes)")
    return frame


# ---------------------------------------------------------------------------
# LoRa modulation via gr-lora_sdr
# ---------------------------------------------------------------------------

def modulate_frame(frame: bytes, sf: int, cr: int, bw: int, samp_rate: int,
                   preamble: int, out_path: str) -> np.ndarray:
    from gnuradio import gr, blocks, lora_sdr

    class Tx(gr.top_block):
        def __init__(self):
            gr.top_block.__init__(self, "meshtastic-tx")
            tag = gr.tag_t()
            tag.offset = 0
            tag.key = gr.pmt.intern("packet_len")
            tag.value = gr.pmt.from_long(len(frame))
            src = blocks.vector_source_b(list(frame), False, 1, [tag])
            gr_cr = max(1, min(4, cr - 4))          # 4/5..4/8 -> 1..4
            pad = int(20 * (1 << sf) * samp_rate / bw)
            chain = [
                src,
                lora_sdr.whitening(False, True, ",", "packet_len"),
                lora_sdr.header(False, True, gr_cr),  # explicit header, CRC on
                lora_sdr.add_crc(True),
                lora_sdr.hamming_enc(gr_cr, sf),
                lora_sdr.interleaver(gr_cr, sf, 2, bw),  # ldro=2: auto (>16 ms)
                lora_sdr.gray_demap(sf),
                lora_sdr.modulate(sf, samp_rate, bw, [MESH_SYNC_WORD], pad, preamble),
                blocks.file_sink(gr.sizeof_gr_complex, out_path, False),
            ]
            for a, b in zip(chain, chain[1:]):
                self.connect(a, b)

    if os.path.exists(out_path):
        os.remove(out_path)
    tb = Tx()
    tb.start()
    # The tagged one-shot source doesn't reliably propagate "done" through the
    # lora_sdr blocks, so wait for the output file to stop growing.
    last, stable, deadline = -1, 0, time.time() + 30
    while time.time() < deadline:
        time.sleep(0.1)
        size = os.path.getsize(out_path) if os.path.exists(out_path) else 0
        if size > 0 and size == last:
            stable += 1
            if stable >= 5:
                break
        else:
            stable = 0
        last = size
    tb.stop()
    tb.wait()

    iq = np.fromfile(out_path, dtype=np.complex64)
    if iq.size == 0:
        raise SystemExit("gr-lora_sdr produced no samples; check your gr-lora_sdr install")
    return iq


def to_hackrf_int8(iq: np.ndarray, samp_rate: int, if_offset: float,
                   lead_s: float = 0.02) -> bytes:
    n = np.arange(iq.size, dtype=np.float64)
    shifted = iq * np.exp(2j * np.pi * if_offset * n / samp_rate).astype(np.complex64)
    peak = np.max(np.abs(shifted)) or 1.0
    shifted = shifted / peak * 0.95
    lead = np.zeros(int(lead_s * samp_rate), dtype=np.complex64)
    sig = np.concatenate([lead, shifted])
    out = np.empty(sig.size * 2, dtype=np.int8)
    out[0::2] = np.clip(np.round(sig.real * 127), -127, 127).astype(np.int8)
    out[1::2] = np.clip(np.round(sig.imag * 127), -127, 127).astype(np.int8)
    return out.tobytes()


def airtime_s(n_bytes: int, sf: int, cr: int, bw: int, preamble: int) -> float:
    t_sym = (1 << sf) / bw
    de = 1 if t_sym > 0.016 else 0
    num = 8 * n_bytes - 4 * sf + 28 + 16  # CRC on, explicit header
    n_payload = 8 + max(int(np.ceil(num / (4 * (sf - 2 * de)))) * cr, 0)
    return (preamble + 4.25 + n_payload) * t_sym


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def parse_node(s: str) -> int:
    s = s.strip()
    if s.startswith("!"):
        s = "0x" + s[1:]
    if s.lower() in ("broadcast", "all", "^all"):
        return BROADCAST
    return int(s, 0) & 0xFFFFFFFF


def main():
    ap = argparse.ArgumentParser(
        description="Transmit a Meshtastic packet with a HackRF.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    g = ap.add_argument_group("message")
    g.add_argument("--text", required=True, help="text message to send")
    g.add_argument("--to", default="broadcast",
                   help="destination node (!aabbccdd, 0x..., or broadcast)")
    g.add_argument("--from-node", default=None,
                   help="our node number (!aabbccdd / 0x...); random if omitted")
    g.add_argument("--hop-limit", type=int, default=3, choices=range(0, 8))
    g.add_argument("--want-ack", action="store_true")
    g.add_argument("--long-name", help="also send a NodeInfo with this long name first")
    g.add_argument("--short-name", help="NodeInfo short name (<=4 chars)")

    g = ap.add_argument_group("channel / radio")
    g.add_argument("--region", default="US", help=", ".join(REGIONS))
    g.add_argument("--preset", default="LONG_FAST", help=", ".join(PRESETS))
    g.add_argument("--channel", default=None,
                   help="channel name (default: preset name, e.g. LongFast)")
    g.add_argument("--psk", default="AQ==",
                   help="channel PSK, base64 as in the app ('AQ==' = default key, 'none')")
    g.add_argument("--slot", type=int, default=None,
                   help="frequency slot (default: firmware hash of the channel name)")
    g.add_argument("--freq", type=float, default=None,
                   help="override center frequency in Hz (ignores region/slot)")

    g = ap.add_argument_group("HackRF")
    g.add_argument("--rate", type=int, default=2_000_000,
                   help="HackRF sample rate; must be an integer multiple of the LoRa BW")
    g.add_argument("--if-offset", type=float, default=500e3,
                   help="put the signal this far from the LO to dodge the DC spur")
    g.add_argument("--ppm", type=float, default=0.0,
                   help="HackRF clock correction (positive if the HackRF reads high)")
    g.add_argument("--tx-gain", type=int, default=20, help="TX VGA gain 0-47 dB")
    g.add_argument("--amp", action="store_true", help="enable the +14 dB RF amp")
    g.add_argument("--repeat", type=int, default=1, help="send N separate packets")
    g.add_argument("--interval", type=float, default=10.0,
                   help="seconds between repeats")
    g.add_argument("--dry-run", action="store_true",
                   help="build IQ files but do not transmit")
    g.add_argument("--keep", default=None,
                   help="directory to keep the generated .cf32/.s8 files in")
    g.add_argument("--emit-json", action="store_true",
                   help="machine-readable mode (used by the sniffer's web send box): "
                        "one JSON line per generated packet on stdout, logs on stderr")
    args = ap.parse_args()

    log_stream = sys.stderr if args.emit_json else sys.stdout

    def log(*a):
        print(*a, file=log_stream, flush=True)

    region = norm_key(args.region)
    if region not in REGIONS:
        raise SystemExit(f"unknown region {args.region!r}; choose from {', '.join(REGIONS)}")
    preset_key, (preset_name, sf, cr, bw, preamble) = lookup_preset(args.preset)
    channel_name = args.channel or preset_name
    key = expand_psk(args.psk)

    if args.freq:
        freq = int(args.freq)
        slot, n_slots = None, None
    else:
        freq, slot, n_slots = channel_freq_hz(region, bw, channel_name, args.slot)

    if args.rate % bw:
        raise SystemExit(f"--rate {args.rate} must be a multiple of BW {bw}")
    if args.rate < 2_000_000:
        raise SystemExit("HackRF needs --rate >= 2000000")
    if abs(args.if_offset) + bw / 2 > 0.4 * args.rate:
        raise SystemExit("--if-offset too large for this --rate")
    if not 0 <= args.tx_gain <= 47:
        raise SystemExit("--tx-gain must be 0..47")
    if args.short_name and len(args.short_name.encode()) > 4:
        raise SystemExit("--short-name must be at most 4 bytes")

    from_node = (parse_node(args.from_node) if args.from_node
                 else random.randint(0x10000000, 0xFFFFFFFE))
    to_node = parse_node(args.to)

    lo_freq = int(round((freq - args.if_offset) * (1 - args.ppm * 1e-6)))
    hackrf = shutil.which("hackrf_transfer")
    if not args.dry_run and not hackrf:
        raise SystemExit("hackrf_transfer not found in PATH (install hackrf tools)")

    log(f"[tx] region={region} preset={preset_key} channel={channel_name!r} "
          f"SF{sf} CR4/{cr} BW{bw // 1000}k preamble={preamble} sync=0x{MESH_SYNC_WORD:02X}")
    slot_txt = f" (slot {slot} of {n_slots})" if slot is not None else ""
    log(f"[tx] freq={freq / 1e6:.6f} MHz{slot_txt}  HackRF LO={lo_freq / 1e6:.6f} MHz "
          f"rate={args.rate / 1e6:g} Msps if_offset={args.if_offset / 1e3:g} kHz")
    log(f"[tx] from=!{from_node:08x} to="
          f"{'broadcast' if to_node == BROADCAST else f'!{to_node:08x}'} "
          f"encryption={'AES-%d' % (len(key) * 8) if key else 'none'} "
          f"chan_hash=0x{xor_hash(channel_name.encode()) ^ xor_hash(key):02x}")

    workdir = args.keep or tempfile.mkdtemp(prefix="meshtx_")
    os.makedirs(workdir, exist_ok=True)

    def send(inner: bytes, label: str, idx: int):
        packet_id = random.randint(1, 0xFFFFFFFF)
        frame = build_frame(inner, key, channel_name, from_node, to_node
                            if label == "text" else BROADCAST,
                            packet_id, args.hop_limit,
                            args.want_ack and label == "text")
        cf32 = os.path.join(workdir, f"{label}_{idx}_{packet_id:08x}.cf32")
        s8 = cf32[:-5] + ".s8"
        iq = modulate_frame(frame, sf, cr, bw, args.rate, preamble, cf32)
        with open(s8, "wb") as f:
            f.write(to_hackrf_int8(iq, args.rate, args.if_offset))
        t_air = airtime_s(len(frame), sf, cr, bw, preamble)
        log(f"[tx] {label}: id=0x{packet_id:08x} {len(frame)} bytes, "
              f"airtime ~{t_air * 1000:.0f} ms, {iq.size} samples -> {s8}")
        if args.emit_json:
            print(json.dumps({
                "tx": label, "s8": os.path.abspath(s8), "freq": freq,
                "lo_freq": lo_freq, "rate": args.rate, "id": packet_id,
                "from": from_node, "airtime_ms": int(t_air * 1000),
            }), flush=True)
        if args.dry_run:
            keyspec = ("default" if key == MESH_DEFAULT_PSK
                       else f"base64:{base64.b64encode(key).decode()}")
            log(f"     verify: meshtastic-sniffer --file={cf32} --rate={args.rate} "
                  f"--center={freq} --region={region} --presets={preset_name} "
                  f"--keys={channel_name}={keyspec}")
            return
        cmd = [hackrf, "-t", s8, "-f", str(lo_freq), "-s", str(args.rate),
               "-x", str(args.tx_gain), "-a", "1" if args.amp else "0"]
        log("     " + " ".join(cmd))
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stdout)
            raise SystemExit("hackrf_transfer failed (is another program using the HackRF?)")

    for i in range(args.repeat):
        if args.long_name:
            short = args.short_name or args.long_name[:4]
            send(data_envelope(PORT_NODEINFO,
                               user_protobuf(from_node, args.long_name, short)),
                 "nodeinfo", i)
            if not args.dry_run:
                time.sleep(1.0)
        send(data_envelope(PORT_TEXT, args.text.encode("utf-8")), "text", i)
        if i + 1 < args.repeat:
            time.sleep(args.interval)

    if not args.keep and not args.dry_run:
        shutil.rmtree(workdir, ignore_errors=True)
    elif args.dry_run:
        log(f"[tx] dry run: files kept in {workdir}")


if __name__ == "__main__":
    main()
