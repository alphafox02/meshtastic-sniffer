#!/usr/bin/env python3
"""Synthesize a Meshtastic-shape LoRa stream of N frames at a target SNR.

Drives gr-lora_sdr's lora_tx hier-block to produce CRC-bearing LoRa frames,
adds AWGN at a configurable SNR, and writes the result as a .cs8 file at
the channel sample rate (bw * os_factor). The output file plays as one
slot's worth of IQ -- meshtastic-sniffer --file=PATH --rate=channel_rate
or gr_lora_usrp_rx.py --source=file --in=PATH consume it directly.

Used by tests/sensitivity.py as the synthesis step in the sensitivity
sweep. Not a deployment tool.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import numpy as np
import pmt
from gnuradio import blocks, channels, gr
from gnuradio import lora_sdr


class SynthTx(gr.top_block):
    def __init__(self, args: argparse.Namespace) -> None:
        gr.top_block.__init__(self, "sensitivity_synth_tx")

        self.channel_rate = args.bw * args.os_factor

        # AWGN level. SNR_dB = 10 log10(P_signal / P_noise). gr-lora_sdr's
        # modulator output is unit-amplitude per chirp sample, so noise
        # voltage scaling reduces to 10^(-SNR_dB/20).
        noise_voltage = 10.0 ** (-args.snr_db / 20.0)

        # LoRa TX hier-block. sync_word=0x2b matches Meshtastic firmware.
        self.lora_tx = lora_sdr.lora_sdr_lora_tx(
            bw=args.bw,
            cr=args.cr,
            has_crc=True,
            impl_head=False,
            samp_rate=self.channel_rate,
            sf=args.sf,
            ldro_mode=2,
            frame_zero_padd=2 ** args.sf,
            sync_word=[0x2b],
        )

        # Strobe a fixed payload at a long-enough period that consecutive
        # frames don't overlap. Pick the period from the worst-case
        # frame length for this (sf, bw) combo.
        worst_case_samples = 200 * (1 << args.sf)
        strobe_period_ms = max(50,
                               int(1000.0 * worst_case_samples / self.channel_rate) + 30)
        self.strobe_period_ms = strobe_period_ms

        # Each strobe sends a UNIQUE payload so our dedup sees N distinct
        # frames instead of folding identical retransmits into one cluster.
        # payload_id_inc takes a separator char and bumps the counter after
        # the separator -- e.g. "M..M:0" -> "M..M:1" -> "M..M:2".
        base = "M" * max(1, args.payload_bytes - 4) + ":0"
        self.strobe = blocks.message_strobe(pmt.intern(base), strobe_period_ms)
        self.id_inc = lora_sdr.payload_id_inc(":")
        self.msg_connect((self.strobe, "strobe"), (self.id_inc, "msg_in"))
        self.msg_connect((self.strobe, "strobe"), (self.lora_tx, "in"))
        self.msg_connect((self.id_inc, "msg_out"), (self.strobe, "set_msg"))

        # AWGN + optional CFO via channels.channel_model.
        freq_offset_norm = args.cfo_hz / self.channel_rate if args.cfo_hz else 0.0
        self.chan = channels.channel_model(
            noise_voltage=noise_voltage,
            frequency_offset=freq_offset_norm,
            epsilon=1.0,        # no SFO drift yet
            taps=[1.0 + 0j],
            noise_seed=args.seed,
            block_tags=False,
        )
        self.connect((self.lora_tx, 0), (self.chan, 0))

        # int16 output stream. complex_to_interleaved_short(False) emits
        # shorts scaled 1:1 with the float input (no auto-scaling), so
        # the LoRa unit-amplitude chirps land in the int8 range directly.
        self.to_short = blocks.complex_to_interleaved_short(False)
        self.connect((self.chan, 0), (self.to_short, 0))

        self.sink = blocks.file_sink(gr.sizeof_short, args.out + ".s16", False)
        self.sink.set_unbuffered(True)
        self.connect((self.to_short, 0), (self.sink, 0))


def s16_to_cs8(s16_path: str, cs8_path: str) -> None:
    raw = np.fromfile(s16_path, dtype=np.int16)
    # complex_to_interleaved_short(False) passes the float through to
    # short with no scaling. Our signal is unit-amplitude complex with
    # noise on top -> stays in int8 range. Saturating clip handles any
    # excursions cleanly.
    out = np.clip(raw, -128, 127).astype(np.int8)
    out.tofile(cs8_path)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sf", type=int, required=True)
    p.add_argument("--cr", type=int, required=True,
                   help="gr-lora cr enum: 1=4/5, 2=4/6, 3=4/7, 4=4/8")
    p.add_argument("--bw", type=int, required=True)
    p.add_argument("--snr-db", type=float, default=20.0)
    p.add_argument("--cfo-hz", type=float, default=0.0)
    p.add_argument("--n-frames", type=int, default=10)
    p.add_argument("--payload-bytes", type=int, default=20)
    p.add_argument("--os-factor", type=int, default=4)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", required=True,
                   help="Output .cs8 path (an .s16 sidecar is written and removed)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    tb = SynthTx(args)
    tb.start()
    # Strobe period is sized so each fire's frame finishes before the next
    # arrives. Wait for n_frames strobes, then a half-period margin for
    # the last frame's samples to drain into the sink.
    runtime_s = ((args.n_frames + 0.4) * tb.strobe_period_ms / 1000.0)
    time.sleep(runtime_s)
    tb.stop()
    tb.wait()
    s16_path = args.out + ".s16"
    s16_to_cs8(s16_path, args.out)
    try:
        os.unlink(s16_path)
    except OSError:
        pass
    size = os.path.getsize(args.out)
    print(f"wrote {args.out}: {size} bytes ({size/2:.0f} complex samples, "
          f"{size/2/tb.channel_rate:.2f} s at {tb.channel_rate:.0f} sps)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
