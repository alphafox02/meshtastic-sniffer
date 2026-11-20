"""Stand-in for tools/meshtastic_tx.py in the tx.c test.

Loads the REAL tool (so its argparse, channel plan, frame building and
--emit-json output are exercised) with numpy/cryptography/gnuradio stubbed:
modulation is replaced by a fixed-size dummy IQ file.
FAKE_MODE=fail -> exit 1; FAKE_MODE=outside -> emit an s8 path outside --keep.
Every argv is appended to $FAKE_LOG as JSON.
"""
import importlib.util
import json
import math
import os
import subprocess
import sys
import types

with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")

mode = os.environ.get("FAKE_MODE", "ok")
if mode == "fail":
    print("simulated generator failure", file=sys.stderr)
    sys.exit(1)
if mode == "outside":
    print(json.dumps({"tx": "text", "s8": "/tmp/evil.s8", "freq": 1, "lo_freq": 1,
                      "rate": 2000000, "id": 1, "from": 1, "airtime_ms": 1}))
    sys.exit(0)

np_stub = types.ModuleType("numpy")
np_stub.ceil = math.ceil
sys.modules["numpy"] = np_stub


class _Alg:
    def __init__(self, key): self.key = key


class _CTR:
    def __init__(self, nonce): self.nonce = nonce


class _Enc:
    def __init__(self, key, nonce): self.key, self.nonce, self.buf = key, nonce, b""

    def update(self, b):
        self.buf += b
        return b""

    def finalize(self):
        m = {16: "aes-128-ctr", 32: "aes-256-ctr"}[len(self.key)]
        return subprocess.run(["openssl", "enc", "-" + m, "-K", self.key.hex(), "-iv",
                               self.nonce.hex(), "-nopad"], input=self.buf,
                              capture_output=True, check=True).stdout


class _Cipher:
    def __init__(self, alg, mode): self.alg, self.mode = alg, mode

    def encryptor(self): return _Enc(self.alg.key, self.mode.nonce)


ciph = types.ModuleType("cryptography.hazmat.primitives.ciphers")
ciph.Cipher = _Cipher
ciph.algorithms = types.SimpleNamespace(AES=_Alg)
ciph.modes = types.SimpleNamespace(CTR=_CTR)
try:  # use the real library when installed (needed for public-key DMs)
    import cryptography.hazmat.primitives.ciphers.aead  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
    for name in ["cryptography", "cryptography.hazmat", "cryptography.hazmat.primitives"]:
        sys.modules[name] = types.ModuleType(name)
    sys.modules["cryptography.hazmat.primitives.ciphers"] = ciph

spec = importlib.util.spec_from_file_location("mtx", os.environ["REAL_TOOL"])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

DUMMY_BYTES = 40000  # 20000 int8 IQ samples


class FakeIQ:
    size = DUMMY_BYTES // 2


def fake_modulate(frame, sf, cr, bw, samp_rate, preamble, out_path):
    with open(out_path, "wb") as f:
        f.write(frame)  # keep the frame bytes around for inspection
    return FakeIQ()


m.modulate_frame = fake_modulate
m.to_hackrf_int8 = lambda iq, rate, off, lead_s=0.02: bytes([1, 2]) * (DUMMY_BYTES // 2)
sys.argv[0] = "meshtastic_tx.py"
m.main()
