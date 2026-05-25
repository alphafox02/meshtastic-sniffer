#!/usr/bin/env python3
"""
Generate a clean Meshtastic-shaped LoRa IQ capture for validating
meshtastic-sniffer's demod against a known-good reference.

Pipeline:
  1. Build the inner Data envelope protobuf (port=TEXT_MESSAGE_APP, payload="Hello").
  2. AES-128-CTR encrypt with the default Meshtastic PSK + the standard nonce
     (packet_id LE | from_node LE | counter BE).
  3. Prepend the 16-byte radio header (to/from/packet_id/flags/channel-hash/...).
  4. Feed those raw bytes into gr-lora_sdr's TX block chain
     (whitening -> header -> add_crc -> hamming_enc -> interleaver -> gray_demap
      -> modulate).
  5. Tail-pad with silence and write to a .cf32 file.

The output file is suitable for `meshtastic-sniffer --file=PATH --rate=BW
--center=...`. With the LoRa demod fully working we should see the message
"Hello" on TEXT_MESSAGE_APP in the JSON feed.

Copyright (c) 2026 CEMAXECUTER LLC
SPDX-License-Identifier: GPL-3.0-or-later
"""

import argparse
import os
import struct
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gnuradio import gr, blocks, lora_sdr


# Meshtastic stock default-channel PSK (the "AQ==" expansion). These are
# protocol-public bytes -- not a secret.
MESH_DEFAULT_PSK = bytes([
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
])


def xor_hash(b: bytes) -> int:
    h = 0
    for c in b:
        h ^= c
    return h & 0xff


def build_data_envelope(port: int, payload: bytes) -> bytes:
    """meshtastic.Data { portnum=1 (varint), payload=2 (bytes) }"""
    out = bytearray()
    # field 1, wire 0 (varint), value = port
    out.append((1 << 3) | 0)
    while True:
        b = port & 0x7f
        port >>= 7
        if port:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    # field 2, wire 2 (length), payload (varint length, so >127 byte payloads work too)
    out.append((2 << 3) | 2)
    L = len(payload)
    while True:
        b = L & 0x7f
        L >>= 7
        if L:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    out += payload
    return bytes(out)


def build_meshtastic_frame(channel_name: str = "LongFast",
                           psk: bytes = MESH_DEFAULT_PSK,
                           text: str = "Hello",
                           from_node: int = 0xDEADBEEF,
                           to_node: int = 0xFFFFFFFF,
                           packet_id: int = 0x12345678,
                           flags: int = 0x07) -> bytes:
    """Construct: 16-byte radio header + AES-CTR(Data envelope)."""
    inner = build_data_envelope(1, text.encode("utf-8"))

    # Nonce: packet_id (8 LE, upper 32 zero OTA) | from_node (4 LE) | counter (4 BE = 0)
    nonce = struct.pack("<Q", packet_id) + struct.pack("<I", from_node) + b"\x00\x00\x00\x00"

    cipher = Cipher(algorithms.AES(psk), modes.CTR(nonce))
    enc = cipher.encryptor()
    ciphertext = enc.update(inner) + enc.finalize()

    channel_hash = xor_hash(channel_name.encode()) ^ xor_hash(psk)

    header = bytearray()
    header += struct.pack("<I", to_node)
    header += struct.pack("<I", from_node)
    header += struct.pack("<I", packet_id)
    header.append(flags & 0xff)
    header.append(channel_hash)
    header.append(0)  # next_hop
    header.append(0)  # relay_node
    return bytes(header) + ciphertext


class TxFlowgraph(gr.top_block):
    """gr-lora_sdr TX chain emitting one frame to a .cf32 file."""

    def __init__(self, frame_bytes: bytes, sf: int, cr: int, bw: int,
                 samp_rate: int, out_path: str, preamb_len: int = 16):
        gr.top_block.__init__(self, "meshtastic-iq-gen")
        # We want one shot, so write the frame to a tempfile and read it via
        # blocks.file_source. The frame ends with a "packet_len" tag that
        # lora_sdr.whitening uses to delimit one packet.
        # Easier: feed bytes from a vector_source with the proper tag set.
        n = len(frame_bytes)
        # Tag the very first sample with `packet_len = n` so whitening sees a
        # single packet boundary.
        tag = gr.tag_t()
        tag.offset = 0
        tag.key = gr.pmt.intern("packet_len")
        tag.value = gr.pmt.from_long(n)
        self.src = blocks.vector_source_b(list(frame_bytes), False, 1, [tag])

        # Map our cr (5..8 = 4/5..4/8) to gr-lora_sdr cr (1..4).
        gr_cr = max(1, min(4, cr - 4))

        self.whitening = lora_sdr.whitening(False, True, ',', 'packet_len')
        self.header = lora_sdr.header(False, True, gr_cr)
        self.add_crc = lora_sdr.add_crc(True)
        self.hamming = lora_sdr.hamming_enc(gr_cr, sf)
        # ldro=2 (AUTO) lets gr-lora_sdr decide based on symbol_duration > 16ms.
        # Hardcoding 0 produces invalid frames at SF12@125kHz which even
        # gr-lora_sdr's own RX cannot decode.
        self.interleaver = lora_sdr.interleaver(gr_cr, sf, 2, bw)
        self.gray = lora_sdr.gray_demap(sf)
        # Sync words list = [0x12] for Meshtastic.
        # inter_frame_padd: number of zero samples after the chirped frame.
        # Pad generously after the frame so the receiver state machine has
        # slack to drain (gr-lora_sdr's own simulation uses 20 symbols).
        inter_pad = int(20 * (1 << sf) * samp_rate / bw)
        self.modulate = lora_sdr.modulate(sf, samp_rate, bw, [0x12], inter_pad, preamb_len)
        self.sink = blocks.file_sink(gr.sizeof_gr_complex, out_path, False)
        self.sink.set_unbuffered(False)

        self.connect(self.src, self.whitening)
        self.connect(self.whitening, self.header)
        self.connect(self.header, self.add_crc)
        self.connect(self.add_crc, self.hamming)
        self.connect(self.hamming, self.interleaver)
        self.connect(self.interleaver, self.gray)
        self.connect(self.gray, self.modulate)
        self.connect(self.modulate, self.sink)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/meshtastic_test.cf32")
    ap.add_argument("--text", default="Hello")
    ap.add_argument("--channel", default="LongFast")
    ap.add_argument("--sf",  type=int, default=11)
    ap.add_argument("--cr",  type=int, default=5,
                    help="our convention: 5/6/7/8 for 4/5..4/8")
    ap.add_argument("--bw",  type=int, default=250000)
    ap.add_argument("--samp-rate", type=int, default=250000,
                    help="defaults to bw (1 sample/chirp-slope). bump for oversampling.")
    ap.add_argument("--from-node", type=lambda x: int(x, 0), default=0xDEADBEEF)
    args = ap.parse_args()

    frame = build_meshtastic_frame(
        channel_name=args.channel, text=args.text, from_node=args.from_node)
    print(f"frame: {len(frame)} bytes (16 header + {len(frame)-16} ciphertext)")
    print(f"  channel_hash = 0x{frame[13]:02x}")

    samp_rate = args.samp_rate or args.bw
    print(f"running gr-lora_sdr TX: SF{args.sf} CR4/{args.cr} BW{args.bw} -> {args.out}")
    tb = TxFlowgraph(frame, args.sf, args.cr, args.bw, samp_rate, args.out)
    tb.start()
    # Give the flowgraph time to push the single frame through.
    time.sleep(0.5)
    tb.stop()
    tb.wait()
    sz = os.path.getsize(args.out)
    print(f"wrote {sz} bytes ({sz//8} complex samples) to {args.out}")
    print(f"replay with: ./meshtastic-sniffer --file={args.out} "
          f"--rate={samp_rate} --center=903000000 --presets=LongFast --keys=default")


if __name__ == "__main__":
    main()
