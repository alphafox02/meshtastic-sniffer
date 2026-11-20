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
try:  # use the real library when installed (needed for public-key DMs)
    import cryptography.hazmat.primitives.ciphers.aead  # noqa: F401
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
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

# node requests (want_response) and a text reply (reply_id)
for kind, port in [("position", 3), ("nodeinfo", 4), ("telemetry", 67), ("traceroute", 70)]:
    body = m.request_payload(kind, user)
    cases.append(("LongFast=default",
                  m.build_frame(m.data_envelope(m.KINDS[kind], body, want_response=True),
                                m.MESH_DEFAULT_PSK, "LongFast", 0x1234ABCD, 0xAABBCCDD,
                                0x100 + port, 3, True),
                  dict(frm="1234abcd", to="aabbccdd", pid=f"{0x100 + port:08x}", hl=3, hs=3,
                       ack=1, relay="cd", dec=1, chan="LongFast", port=port,
                       payload=body.hex(), want_resp=1, req="00000000", reply="00000000")))
check(m.request_payload("telemetry", user) == bytes([0x12, 0x00]),
      "telemetry request = Telemetry{device_metrics={}}")
check(m.request_payload("position", user) == b"" and m.request_payload("traceroute", user) == b"",
      "position / traceroute requests have empty bodies")
cases.append(("LongFast=default",
              m.build_frame(m.data_envelope(1, b"ok", reply_id=0x1A2B3C4D, request_id=0x55),
                            m.MESH_DEFAULT_PSK, "LongFast", 0x1234ABCD, m.BROADCAST, 0x99, 3, False),
              dict(frm="1234abcd", to="ffffffff", pid="00000099", hl=3, hs=3, ack=0, relay="cd",
                   dec=1, chan="LongFast", port=1, payload=b"ok".hex(), want_resp=0,
                   req="00000055", reply="1a2b3c4d")))

# public-key DMs (firmware 2.5+), only with the real cryptography library
if HAVE_CRYPTO:
    # the firmware's own test_PKC packet, re-encrypted by the tool with the
    # packet's extra nonce, must be byte-identical
    fw_priv = bytes.fromhex("a00330633e63522f8a4d81ec6d9d1e6617f6c8ffd3a4c698229537d44e522277")
    fw_pub = bytes.fromhex("db18fc50eea47f00251cb784819a3cf5fc361882597f589f0d7ff820e8064457")
    fw_radio = bytes.fromhex("8c646d7a2909000062d6b2136b00000040df24abfcc30a17a3d9046726099e796a1c036a792b")
    shared = m.pki_shared_key(fw_priv, fw_pub)
    check(shared[:8].hex() == "777b1545c9d6f9a2", "tool: firmware test_PKC shared key")
    check(m.pki_encrypt(bytes.fromhex("08011204746573744800"), shared, 0x0929, 0x13b2d662,
                        0x2b796a03) == fw_radio[16:],
          "tool: encrypts the firmware's test_PKC packet byte for byte")
    # tool -> C: a DM from A to B, decrypted by B's key in the C decoder
    a_priv, b_priv = bytes(range(1, 33)), bytes(range(33, 65))
    a_pub, b_pub = m.pki_public_key(a_priv), m.pki_public_key(b_priv)
    dm = m.data_envelope(1, "secret dm".encode(), reply_id=0x42)
    frame = m.build_frame(dm, m.MESH_DEFAULT_PSK, "LongFast", 0x1234ABCD, 0xAABBCCDD,
                          0x5150, 3, True, m.pki_shared_key(a_priv, b_pub))
    check(frame[13] == 0 and len(frame) == 16 + len(dm) + 12, "PKI frame: channel hash 0, +12 bytes")
    cases.append((f"pki:{b_priv.hex()}:{a_pub.hex()}:aabbccdd:1234abcd", frame,
                  dict(frm="1234abcd", to="aabbccdd", pid="00005150", hl=3, hs=3, ack=1,
                       relay="cd", dec=1, chan="PKI", port=1, payload="secret dm".encode().hex(),
                       want_resp=0, req="00000000", reply="00000042")))
    u = m.user_protobuf(0x1234ABCD, "Sniffer TX", "STX", a_pub)
    check(u.endswith(bytes([0x42, 32]) + a_pub), "NodeInfo carries public_key (User field 8)")
else:
    print("(python3-cryptography not installed: PKI checks skipped)")

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
    if "want_resp" in e:
        check(f.get("want_resp") == str(e["want_resp"]) and f.get("req") == e["req"]
              and f.get("reply") == e["reply"], tag + " want_response / request_id / reply_id")
check(len(out) == len(cases), "decoder emitted one event per frame")
print("FAILS:", fails)
sys.exit(1 if fails else 0)
