"""mesh_tx.c (C frame builder) vs tools/meshtastic_tx.py: identical frames,
frequencies, LO and airtime for text / replies / every request kind / PKI /
announcements, with the tool's random ids pinned. With gr-lora_sdr, also the
int8 HackRF IQ of a real modulation.
Usage: mesh_tx_check.py REPO HARNESS"""
import importlib.util
import json
import os
import random
import subprocess
import sys
import tempfile

REPO, HARNESS = sys.argv[1], sys.argv[2]
fails = 0


def check(cond, msg):
    global fails
    print(("ok   " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


def load_tool():
    spec = importlib.util.spec_from_file_location("mtx", REPO + "/tools/meshtastic_tx.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_tool(args, ids, xn, modulate):
    """Run the tool's main() with pinned randomness; return its packets."""
    m = load_tool()
    seq = list(ids)
    state = {"in_build": False}
    def fake_randint(a, b):
        if a == 1 and b == 0xFFFFFFFF:   # packet id, or (inside build_frame) the PKI extra nonce
            return xn if state["in_build"] else seq.pop(0)
        raise AssertionError((a, b))
    m.random.randint = fake_randint
    frames = []
    real_build = m.build_frame
    def capture_build(*a, **k):
        state["in_build"] = True
        try:
            f = real_build(*a, **k)
        finally:
            state["in_build"] = False
        frames.append(f)
        return f
    m.build_frame = capture_build
    if not modulate:
        class FakeIQ:
            size = 1
        m.modulate_frame = lambda *a, **k: FakeIQ()
        m.to_hackrf_int8 = lambda *a, **k: b"\0\0"
    d = tempfile.mkdtemp()
    out = []
    import io, contextlib
    buf = io.StringIO()
    sys.argv = ["meshtastic_tx.py", "--emit-json", "--dry-run", "--keep", d] + args
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        m.main()
    for line, frame in zip(buf.getvalue().splitlines(), frames):
        j = json.loads(line)
        j["frame"] = frame.hex()
        out.append(j)
    return out, d


def run_c(kv):
    r = subprocess.run([HARNESS] + [f"{k}={v}" for k, v in kv.items()], capture_output=True, text=True)
    pk = []
    for line in r.stdout.splitlines():
        if line.startswith("ERROR"):
            return line
        label, pid, pki, freq, lo, air, frame = line.split()
        pk.append(dict(tx=label, id=int(pid, 16), pki=pki == "1", freq=int(freq), lo_freq=int(lo),
                       airtime_ms=int(air), frame=frame))
    return pk


m = load_tool()
a_priv, b_priv = bytes(range(1, 33)), bytes(range(33, 65))
b_pub = m.pki_public_key(b_priv)
kf = tempfile.NamedTemporaryFile("w", delete=False)
kf.write(__import__("base64").b64encode(a_priv).decode() + "\n")
kf.close()

CASES = [  # (name, tool args, C key=values)
    ("broadcast text, US LongFast",
     ["--region", "US", "--text", "hello mesh"], dict(region="US", text="hello mesh")),
    ("EU_868 MediumFast, ppm 13, hop 5",
     ["--region", "EU_868", "--preset", "MEDIUM_FAST", "--text", "ciao", "--ppm", "13", "--hop-limit", "5"],
     dict(region="EU_868", preset="MEDIUM_FAST", text="ciao", ppm="13", hop="5")),
    ("DM + ack + reply id, private AES-256 channel",
     ["--region", "EU_433", "--preset", "LONG_SLOW", "--channel", "Ops", "--psk",
      __import__("base64").b64encode(bytes(range(32))).decode(), "--to", "!aabbccdd", "--want-ack",
      "--text", "dm é", "--reply-id", "0x1a2b3c4d"],
     dict(region="EU_433", preset="LONG_SLOW", channel="Ops",
          psk=__import__("base64").b64encode(bytes(range(32))).decode(), to="aabbccdd", ack="1",
          text="dm é", reply="1a2b3c4d")),
    ("short PSK zero-padded, explicit slot, unencrypted none",
     ["--region", "US", "--psk", "AAECAwQ=", "--slot", "3", "--text", "x"],
     dict(region="US", psk="AAECAwQ=", slot="3", text="x")),
    ("simple2 key + NodeInfo announce (long name)",
     ["--region", "US", "--psk", "Ag==", "--text", "hi", "--long-name", "Sniffer TX", "--short-name", "STX"],
     dict(region="US", psk="Ag==", text="hi", long="Sniffer TX", short="STX")),
] + [
    (f"{k} request", ["--region", "US", "--kind", k, "--to", "!aabbccdd", "--want-ack"],
     dict(region="US", kind=k, to="aabbccdd", ack="1"))
    for k in ("position", "nodeinfo", "telemetry", "traceroute")
] + [
    ("PKI DM with announce + our public key",
     ["--region", "EU_868", "--preset", "MEDIUM_FAST", "--to", "!aabbccdd", "--text", "secret",
      "--pki-key-file", kf.name, "--dest-pubkey", b_pub.hex(), "--announce-dest", "--want-ack"],
     dict(region="EU_868", preset="MEDIUM_FAST", to="aabbccdd", text="secret",
          priv=a_priv.hex(), dest=b_pub.hex(), announce="1", ack="1")),
    ("PKI telemetry request",
     ["--region", "EU_868", "--preset", "MEDIUM_FAST", "--kind", "telemetry", "--to", "!aabbccdd",
      "--pki-key-file", kf.name, "--dest-pubkey", b_pub.hex()],
     dict(region="EU_868", preset="MEDIUM_FAST", kind="telemetry", to="aabbccdd",
          priv=a_priv.hex(), dest=b_pub.hex())),
    ("traceroute with a dest key stays channel-encrypted",
     ["--region", "EU_868", "--preset", "MEDIUM_FAST", "--kind", "traceroute", "--to", "!aabbccdd",
      "--pki-key-file", kf.name, "--dest-pubkey", b_pub.hex()],
     dict(region="EU_868", preset="MEDIUM_FAST", kind="traceroute", to="aabbccdd",
          priv=a_priv.hex(), dest=b_pub.hex())),
]

IDS, XN = (0x11111111, 0x22222222), 0x33333333
for name, targs, ckv in CASES:
    tool, _ = run_tool(targs + ["--from-node", "!12345678"], IDS, XN, modulate=False)
    ckv = dict(ckv, **{"from": "12345678", "ids": f"{IDS[0]:x},{IDS[1]:x}", "xn": f"{XN:x}",
                       "frames_only": "1"})
    c = run_c(ckv)
    if isinstance(c, str):
        check(False, f"{name}: C {c}")
        continue
    same = len(tool) == len(c) and all(
        t["frame"] == x["frame"] and t["tx"] == x["tx"] and t["id"] == x["id"] and t["freq"] == x["freq"]
        and t["lo_freq"] == x["lo_freq"] and t["airtime_ms"] == x["airtime_ms"] and t["pki"] == x["pki"]
        for t, x in zip(tool, c))
    check(same, f"{name}: {len(c)} packet(s) {'identical' if same else 'DIFFER'}"
                + ("" if same else f"\n  tool {tool}\n  C    {c}"))

# C refuses what the tool refuses
for name, ckv in [("request to broadcast", dict(kind="position")),
                  ("text with a request", dict(kind="traceroute", to="aabbccdd", text="x")),
                  ("too long", dict(text="x" * 240))]:
    c = run_c(dict(ckv, **{"from": "12345678", "frames_only": "1"}))
    check(isinstance(c, str), f"C rejects {name}: {c if isinstance(c, str) else c}")

# real modulation: the C int8 IQ vs the tool's (gr-lora_sdr) int8 IQ
try:
    from gnuradio import lora_sdr  # noqa: F401
    have_gr = True
except Exception:
    have_gr = False
if have_gr:
    import numpy as np
    for preset in ("MEDIUM_FAST", "LONG_SLOW"):
        targs = ["--region", "EU_868", "--preset", preset, "--text", "iq check", "--ppm", "13"]
        tool, d = run_tool(targs + ["--from-node", "!12345678"], IDS, XN, modulate=True)
        cd = tempfile.mkdtemp()
        run_c(dict(region="EU_868", preset=preset, text="iq check", ppm="13", **{"from": "12345678"},
                   ids=f"{IDS[0]:x},{IDS[1]:x}", out=cd))
        t = np.fromfile(tool[0]["s8"], dtype=np.int8).astype(int)
        x = np.fromfile(f"{cd}/text.s8", dtype=np.int8).astype(int)
        diff = np.abs(t - x) if t.size == x.size else None
        check(diff is not None and diff.max() <= 2 and (diff > 0).mean() < 0.01,
              f"{preset}: int8 IQ {x.size} bytes, tool {t.size}; "
              + (f"max diff {diff.max()}, {100 * (diff > 0).mean():.3f}% differ" if diff is not None else "size differs"))
else:
    print("(gr-lora_sdr not importable: IQ comparison skipped)")
os.unlink(kf.name)
print("FAILS:", fails)
sys.exit(1 if fails else 0)
