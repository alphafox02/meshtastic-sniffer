"""lora_tx.c vs the real gr-lora_sdr TX blocks: identical symbols, IQ equal
within 1e-2, for every Meshtastic preset and several payload sizes.
Usage: lora_tx_check.py HARNESS   (needs gnuradio + gr-lora_sdr + numpy)"""
import os
import random
import subprocess
import sys
import tempfile
import time

import numpy as np
from gnuradio import blocks, gr, lora_sdr

HARNESS = sys.argv[1]
PRESETS = [  # name, sf, cr(4/x), bw
    ("SHORT_TURBO", 7, 5, 500000), ("SHORT_FAST", 7, 5, 250000), ("SHORT_SLOW", 8, 5, 250000),
    ("MEDIUM_FAST", 9, 5, 250000), ("MEDIUM_SLOW", 10, 5, 250000), ("LONG_FAST", 11, 5, 250000),
    ("LONG_MODERATE", 11, 8, 125000), ("LONG_SLOW", 12, 8, 125000), ("LONG_TURBO", 11, 8, 500000),
]
RATE = 2000000
fails = 0


def check(cond, msg):
    global fails
    print(("ok   " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


def gr_reference(frame, sf, cr, bw, path):
    """The same block chain as tools/meshtastic_tx.py, with a symbol tap."""
    tb = gr.top_block()
    tag = gr.tag_t()
    tag.offset, tag.key, tag.value = 0, gr.pmt.intern("packet_len"), gr.pmt.from_long(len(frame))
    src = blocks.vector_source_b(list(frame), False, 1, [tag])
    gcr = cr - 4
    pad = int(20 * (1 << sf) * RATE / bw)
    gray = lora_sdr.gray_demap(sf)
    chain = [src, lora_sdr.whitening(False, True, ",", "packet_len"),
             lora_sdr.header(False, True, gcr), lora_sdr.add_crc(True),
             lora_sdr.hamming_enc(gcr, sf), lora_sdr.interleaver(gcr, sf, 2, bw), gray,
             lora_sdr.modulate(sf, RATE, bw, [0x2B], pad, 16),
             blocks.file_sink(gr.sizeof_gr_complex, path, False)]
    for a, b in zip(chain, chain[1:]):
        tb.connect(a, b)
    sym_sink = blocks.vector_sink_i()
    tb.connect(gray, sym_sink)
    tb.start()
    last, stable, deadline = -1, 0, time.time() + 30
    while time.time() < deadline:
        time.sleep(0.05)
        size = os.path.getsize(path) if os.path.exists(path) else 0
        if size > 0 and size == last:
            stable += 1
            if stable >= 6:
                break
        else:
            stable = 0
        last = size
    tb.stop()
    tb.wait()
    return list(sym_sink.data()), np.fromfile(path, dtype=np.complex64)


rng = random.Random(7)
with tempfile.TemporaryDirectory() as d:
    for name, sf, cr, bw in PRESETS:
        for n in (16, 37, 128, 237):
            frame = bytes(rng.randrange(256) for _ in range(n))
            ref_syms, ref_iq = gr_reference(frame, sf, cr, bw, f"{d}/gr.cf32")
            out = subprocess.run([HARNESS, frame.hex(), str(sf), str(cr - 4), str(bw), str(RATE),
                                  f"{d}/c.cf32"], capture_output=True, text=True)
            c_syms = [int(x) for x in out.stdout.split()]
            c_iq = np.fromfile(f"{d}/c.cf32", dtype=np.complex64)
            same_syms = c_syms == ref_syms
            same_len = c_iq.size == ref_iq.size
            err = float(np.max(np.abs(c_iq - ref_iq))) if same_len else float("inf")
            # symbols must be identical; IQ to 1e-2 (-40 dB): at SF12 x16 the chirp
            # phase reaches ~1.3e4 rad, where float phase steps are ~1e-3 rad in
            # gr-lora_sdr's own float-phase chirps too.
            check(out.returncode == 0 and same_syms and same_len and err < 1e-2,
                  f"{name:13s} {n:3d} B: {len(c_syms)} symbols "
                  f"{'identical' if same_syms else 'DIFFER'}, {c_iq.size} samples "
                  f"(gr {ref_iq.size}), max |dIQ| {err:.1e}")
print("FAILS:", fails)
sys.exit(1 if fails else 0)
