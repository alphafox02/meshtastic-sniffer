"""Build frames with tools/meshtastic_tx.py and decode them with the sniffer's C code."""
import base64
import importlib.util
import math
import subprocess
import sys
import types

REPO = sys.argv[1]
HARNESS = sys.argv[2]

# numpy is only needed for modulation; stub it so the frame code imports.
np_stub = types.ModuleType("numpy")
np_stub.ceil = math.ceil
sys.modules["numpy"] = np_stub


# Test-only AES shim backed by the openssl CLI (python3-cryptography is not
# installed here). Independent of the C decoder's EVP code path.
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
        mode = {16: "aes-128-ctr", 32: "aes-256-ctr"}[len(self.key)]
        return subprocess.run(["openssl", "enc", "-" + mode, "-K", self.key.hex(),
                               "-iv", self.nonce.hex(), "-nopad"],
                              input=self.buf, capture_output=True, check=True).stdout


class _Cipher:
    def __init__(self, alg, mode): self.alg, self.mode = alg, mode

    def encryptor(self): return _Enc(self.alg.key, self.mode.nonce)


ciph = types.ModuleType("cryptography.hazmat.primitives.ciphers")
ciph.Cipher = _Cipher
ciph.algorithms = types.SimpleNamespace(AES=_Alg)
ciph.modes = types.SimpleNamespace(CTR=_CTR)
for name in ["cryptography", "cryptography.hazmat", "cryptography.hazmat.primitives"]:
    sys.modules[name] = types.ModuleType(name)
sys.modules["cryptography.hazmat.primitives.ciphers"] = ciph

spec = importlib.util.spec_from_file_location("mtx", REPO + "/tools/meshtastic_tx.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

fails = 0


def check(cond, msg):
    global fails
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond:
        fails += 1


# --- channel plan (known firmware defaults) ---
check(m.channel_freq_hz("US", 250000, "LongFast", None)[:2] == (906875000, 19),
      "US LongFast -> 906.875 MHz slot 19")
check(m.channel_freq_hz("EU_868", 250000, "LongFast", None)[0] == 869525000,
      "EU_868 LongFast -> 869.525 MHz")
check(m.channel_freq_hz("EU_433", 250000, "LongFast", None)[0] == 433875000,
      "EU_433 LongFast -> 433.875 MHz")
check(m.channel_freq_hz("US", 250000, "MediumFast", None)[0] == 913125000,
      "US MediumFast -> 913.125 MHz")
check(m.channel_freq_hz("US", 250000, "LongFast", 0)[0] == 902125000,
      "explicit slot 0 -> 902.125 MHz")

# --- PSK expansion ---
check(m.expand_psk("AQ==") == m.MESH_DEFAULT_PSK, "AQ== -> default key")
check(m.expand_psk("Ag==")[-1] == (m.MESH_DEFAULT_PSK[-1] + 1) & 0xFF,
      "Ag== -> simple2 (last byte +1)")
check(m.expand_psk("none") == b"" and m.expand_psk("AA==") == b"",
      "none / AA== -> unencrypted")
check(len(m.expand_psk(base64.b64encode(bytes(range(32))).decode())) == 32,
      "32-byte key kept (AES-256)")

# --- airtime sanity (Semtech formula, LongFast 30 B ~ 477 ms) ---
check(abs(m.airtime_s(30, 11, 5, 250000, 16) - 0.4772) < 0.002,
      "airtime LongFast 30 B ~= 477 ms")

# --- frames through the C decoder ---
key256 = bytes(range(1, 33))
b64_256 = base64.b64encode(key256).decode()
user = m.user_protobuf(0x1234ABCD, "Sniffer TX", "STX")
cases = [
    ("LongFast=default",
     m.build_frame(m.data_envelope(1, "hello mesh".encode()), m.MESH_DEFAULT_PSK,
                   "LongFast", 0x1234ABCD, m.BROADCAST, 0x0BADF00D, 3, False),
     dict(frm="1234abcd", to="ffffffff", pid="0badf00d", hl=3, hs=3, ack=0,
          relay="cd", dec=1, chan="LongFast", port=1, payload="hello mesh".encode().hex())),
    (f"Ops=base64:{b64_256}",
     m.build_frame(m.data_envelope(1, "dm é".encode()), key256,
                   "Ops", 0x10203040, 0xAABBCCDD, 0x00000042, 5, True),
     dict(frm="10203040", to="aabbccdd", pid="00000042", hl=5, hs=5, ack=1,
          relay="40", dec=1, chan="Ops", port=1, payload="dm é".encode().hex())),
    ("LongFast=default",
     m.build_frame(m.data_envelope(4, user), m.MESH_DEFAULT_PSK,
                   "LongFast", 0x1234ABCD, m.BROADCAST, 0x77, 3, False),
     dict(frm="1234abcd", to="ffffffff", pid="00000077", hl=3, hs=3, ack=0,
          relay="cd", dec=1, chan="LongFast", port=4, payload=user.hex())),
]

inp = "".join(f"{spec}\t{frame.hex()}\n" for spec, frame, _ in cases)
out = subprocess.run([HARNESS], input=inp, capture_output=True, text=True,
                     check=True).stdout.splitlines()
print("\n".join("  C: " + line for line in out))
for (spec, frame, e), line in zip(cases, out):
    f = dict(kv.split("=", 1) for kv in line.split() if "=" in kv)
    tag = f"[{spec.split('=')[0]} port {e['port']}]"
    check(f.get("from") == e["frm"] and f.get("to") == e["to"] and f.get("id") == e["pid"],
          tag + " header from/to/id")
    check(f.get("hop_limit") == str(e["hl"]) and f.get("hop_start") == str(e["hs"])
          and f.get("want_ack") == str(e["ack"]), tag + " flags (hop_limit/hop_start/want_ack)")
    check(f.get("relay") == e["relay"], tag + " relay_node byte")
    check(f.get("dec") == str(e["dec"]) and f.get("chan") == e["chan"],
          tag + " decrypted with the right channel key")
    check(f.get("port") == str(e["port"]) and f.get("payload") == e["payload"],
          tag + " portnum + payload")
check(len(out) == len(cases), "decoder emitted one event per frame")
print("FAILS:", fails)
sys.exit(1 if fails else 0)
