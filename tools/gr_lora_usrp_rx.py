#!/usr/bin/env python3
"""Single-channel gr-lora_sdr validation receiver.

This is intentionally not a wideband scanner. It is a truth probe for one
exact Meshtastic slot: tune/translate that slot to baseband, run the upstream
gr-lora_sdr decoder, and print each CRC-checked payload as hex.
"""

from __future__ import annotations

import argparse
import signal
import sys
import time

import numpy as np
import pmt
from gnuradio import blocks, filter, gr, uhd
from gnuradio.fft import window
from gnuradio import lora_sdr
from gnuradio.filter import firdes


class PayloadPrinter(gr.sync_block):
    def __init__(self) -> None:
        gr.sync_block.__init__(
            self,
            name="payload_printer",
            in_sig=[np.int8],
            out_sig=[],
        )
        self.current: dict | None = None

    @staticmethod
    def _dict_get(info, key: str, default=None):
        val = pmt.dict_ref(info, pmt.intern(key), pmt.PMT_NIL)
        if pmt.eqv(val, pmt.PMT_NIL):
            return default
        if pmt.is_bool(val):
            return bool(pmt.to_bool(val))
        if pmt.is_integer(val):
            return int(pmt.to_long(val))
        return val

    def _start_frame(self, info) -> None:
        pay_len = self._dict_get(info, "pay_len", 0)
        crc_valid = self._dict_get(info, "crc_valid", None)
        cr = self._dict_get(info, "cr", None)
        has_crc = self._dict_get(info, "crc", None)
        err = self._dict_get(info, "err", None)
        self.current = {
            "pay_len": max(0, int(pay_len)),
            "crc_valid": crc_valid,
            "cr": cr,
            "has_crc": has_crc,
            "err": err,
            "buf": bytearray(),
        }

    def _finish_frame(self) -> None:
        if not self.current:
            return
        b = bytes(self.current["buf"])
        crc = self.current["crc_valid"]
        crc_s = "unknown" if crc is None else ("ok" if crc else "fail")
        print(
            f"gr-rx: crc={crc_s} has_crc={self.current['has_crc']} "
            f"cr={self.current['cr']} err={self.current['err']} "
            f"len={len(b)} payload={b.hex()}",
            flush=True,
        )
        self.current = None

    def work(self, input_items, output_items):  # noqa: D401 - GNU Radio API
        data = input_items[0]
        nread = self.nitems_read(0)
        tags_by_pos: dict[int, list] = {}
        for tag in self.get_tags_in_window(0, 0, len(data)):
            tags_by_pos.setdefault(int(tag.offset - nread), []).append(tag)

        for i, val in enumerate(data):
            for tag in tags_by_pos.get(i, []):
                if pmt.symbol_to_string(tag.key) == "frame_info":
                    self._start_frame(tag.value)
            if self.current is not None:
                self.current["buf"].append(int(val) & 0xff)
                if len(self.current["buf"]) >= self.current["pay_len"]:
                    self._finish_frame()
        return len(data)


class GrLoraValidateRx(gr.top_block):
    def __init__(self, args: argparse.Namespace) -> None:
        gr.top_block.__init__(self, "gr_lora_validate_rx")
        channel_rate = args.bw * args.os_factor
        decim_f = args.rate / channel_rate
        decim = int(round(decim_f))
        if decim < 1 or abs(decim_f - decim) > 1e-6:
            raise SystemExit(
                f"rate must be an integer multiple of bw*os_factor: "
                f"{args.rate:g} / {channel_rate:g} = {decim_f:g}"
            )

        offset = args.channel_freq - args.center
        taps = None
        if decim != 1 or abs(offset) > 1e-6:
            taps = firdes.low_pass(
                1.0,
                args.rate,
                args.bw / 2.0,
                args.bw / 10.0,
                window.WIN_HAMMING,
                6.76,
            )

        if args.source == "usrp":
            self.usrp_source = uhd.usrp_source(
                ",".join((args.usrp_args, "")),
                uhd.stream_args(
                    cpu_format="fc32",
                    otw_format=args.otw,
                    channels=[0],
                ),
            )
            src = self.usrp_source
            src.set_samp_rate(args.rate)
            src.set_center_freq(args.center, 0)
            src.set_gain(args.gain, 0)
            if args.antenna:
                src.set_antenna(args.antenna, 0)
            src.set_min_output_buffer(int(np.ceil(args.rate / args.bw * (2**args.sf + 2))))
            source = src
        elif args.in_format == "cf32":
            self.file_source = blocks.file_source(gr.sizeof_gr_complex, args.input, False)
            source = self.file_source
        else:
            self.file_source = blocks.file_source(gr.sizeof_char, args.input, False)
            self.cs8_to_complex = blocks.interleaved_char_to_complex(False, 1.0 / 127.0)
            self.connect(self.file_source, self.cs8_to_complex)
            source = self.cs8_to_complex

        if args.duration > 0:
            self.head = blocks.head(gr.sizeof_gr_complex, int(args.duration * args.rate))
            self.connect(source, self.head)
            source = self.head

        self.ddc = None
        if taps is not None:
            self.ddc = filter.freq_xlating_fir_filter_ccc(decim, taps, offset, args.rate)
        self.rx = lora_sdr.lora_sdr_lora_rx(
            bw=args.bw,
            cr=args.gr_cr,
            has_crc=True,
            impl_head=False,
            pay_len=255,
            samp_rate=int(channel_rate),
            sf=args.sf,
            sync_word=args.sync_word,
            soft_decoding=args.soft,
            ldro_mode=2,
            print_rx=[False, True],
        )
        self.printer = PayloadPrinter()

        if self.ddc is not None:
            self.connect(source, self.ddc)
            self.connect(self.ddc, self.rx)
        else:
            self.connect(source, self.rx)
        self.connect(self.rx, self.printer)

        print(
            "gr-rx: "
            f"source={args.source} rate={args.rate:g} center={args.center:g} "
            f"channel={args.channel_freq:g} offset={offset:+g} "
            f"bw={args.bw} sf={args.sf} os={args.os_factor} "
            f"decim={decim} sync={args.sync_word} soft={args.soft}",
            file=sys.stderr,
            flush=True,
        )


def parse_sync_word(s: str):
    if s.lower() in ("ignore", "none", "0,0", "[0,0]"):
        return [0, 0]
    if "," in s:
        return [int(x, 0) for x in s.split(",") if x.strip()]
    return [int(s, 0)]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", choices=("usrp", "file"), default="usrp")
    p.add_argument("--in", dest="input", help="Input IQ file when --source=file")
    p.add_argument("--in-format", choices=("cf32", "cs8"), default="cf32")
    p.add_argument("--rate", type=float, required=True, help="Wideband input sample rate")
    p.add_argument("--center", type=float, required=True, help="SDR/file center frequency in Hz")
    p.add_argument("--channel-freq", type=float, required=True, help="Target LoRa slot center in Hz")
    p.add_argument("--bw", type=int, required=True, help="LoRa bandwidth in Hz")
    p.add_argument("--sf", type=int, required=True, help="LoRa spreading factor")
    p.add_argument("--gr-cr", type=int, default=1, help="gr-lora_sdr CR enum, 1 means 4/5")
    p.add_argument("--os-factor", type=int, default=4)
    p.add_argument("--sync-word", type=parse_sync_word, default=[0, 0],
                   help="0x12, 0x2b, 'ignore', or comma pair. Default ignores sync.")
    p.add_argument("--hard", action="store_true", help="Disable gr-lora_sdr soft decoding")
    p.add_argument("--duration", type=float, default=0.0, help="Seconds to run; 0 = until Ctrl-C/file EOF")
    p.add_argument("--usrp-args", default="", help="UHD device args, e.g. serial=...")
    p.add_argument("--otw", default="sc8", help="UHD over-the-wire format")
    p.add_argument("--gain", type=float, default=40.0)
    p.add_argument("--antenna", default="TX/RX")
    args = p.parse_args()
    if args.source == "file" and not args.input:
        p.error("--source=file requires --in")
    args.soft = not args.hard
    return args


def main() -> int:
    args = parse_args()
    tb = GrLoraValidateRx(args)

    stop = False

    def _stop(_signum, _frame):
        nonlocal stop
        stop = True
        tb.stop()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    tb.start()
    try:
        if args.duration > 0 or args.source == "file":
            tb.wait()
        else:
            while not stop:
                time.sleep(0.25)
    finally:
        tb.stop()
        tb.wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
