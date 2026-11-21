"""TX/RX parameter parity: what tools/meshtastic_tx.py modulates must be what
the sniffer demodulates. Compares the tool's tables and helpers with the
receiver's (dumped by params_check.c) for every region x preset x slot,
channel hashes and expanded keys for a set of key specs, and ppm tuning.
Usage: params_check.py /path/to/meshtastic_tx.py /path/to/params_check"""
import base64
import importlib.util
import json
import subprocess
import sys
import types

tool_path, dumper = sys.argv[1], sys.argv[2]

# The tool imports numpy + cryptography at module level; only its pure
# helpers are used here, so stub them when they aren't installed.
for name in ("numpy", "cryptography", "cryptography.hazmat",
             "cryptography.hazmat.primitives", "cryptography.hazmat.primitives.ciphers"):
    try:
        importlib.import_module(name)
    except ImportError:
        mod = types.ModuleType(name)
        if name.endswith("ciphers"):
            mod.Cipher = mod.algorithms = mod.modes = None
        sys.modules[name] = mod
spec = importlib.util.spec_from_file_location("mtx", tool_path)
tx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tx)

KEY16 = bytes(range(1, 17))
KEY32 = bytes(range(0x40, 0x60))
CASES = [  # (channel name, psk as the app/tool takes it, RX spec)
    ("LongFast", "AQ==", "default"),
    ("MediumFast", "AQ==", "base64:AQ=="),
    ("LongFast", "Ag==", "base64:Ag=="),
    ("ShortTurbo", "Cg==", "base64:Cg=="),
    ("Toscana", base64.b64encode(KEY16).decode(), "hex:" + KEY16.hex()),
    ("Ops", base64.b64encode(KEY32).decode(), "base64:" + base64.b64encode(KEY32).decode()),
    ("Short5", base64.b64encode(KEY16[:5]).decode(), "hex:" + KEY16[:5].hex()),
    ("Mid20", base64.b64encode(KEY32[:20]).decode(), "hex:" + KEY32[:20].hex()),
    ("Clear", "none", "none"),
    ("TooLong", base64.b64encode(bytes(33)).decode(), "hex:" + "00" * 33),
]

rx = json.loads(subprocess.run([dumper] + [f"{n}={s}" for n, _, s in CASES],
                               capture_output=True, text=True, check=True).stdout)
fails = 0


def check(ok, msg):
    global fails
    print(("ok   " if ok else "FAIL ") + msg)
    fails += not ok


# --- presets: what each preset name modulates with ---
rx_presets = {p["key"]: p for p in rx["presets"]}
check(set(rx_presets) == set(tx.PRESETS),
      f"same preset list (rx-only {sorted(set(rx_presets) - set(tx.PRESETS))}, "
      f"tx-only {sorted(set(tx.PRESETS) - set(rx_presets))})")
for key, (name, sf, cr, bw, pre) in tx.PRESETS.items():
    p = rx_presets.get(key)
    if p:
        same = (p["name"], p["sf"], p["cr"], p["bw"], p["preamble"]) == (name, sf, cr, bw, pre)
        check(same, f"{key}: TX {name} SF{sf} CR4/{cr} BW{bw} pre{pre} vs RX "
                    f"{p['name']} SF{p['sf']} CR4/{p['cr']} BW{p['bw']} pre{p['preamble']}")
        # LDRO: RX decides it (lora.c) as symbol time > 16 ms; gr-lora_sdr's
        # auto mode (ldro=2, used by the tool) uses the same 16 ms rule.
        sym_ms = (1 << sf) * 1000.0 / bw
        print(f"     {key}: symbol {sym_ms:.2f} ms -> LDRO {'on' if sym_ms > 16 else 'off'} both sides")

# --- regions and every channel-slot frequency ---
sub = [r for r in rx["regions"] if not r["wide"]]
check({r["name"] for r in sub} == set(tx.REGIONS),
      f"same sub-GHz region list ({len(sub)} RX, {len(tx.REGIONS)} TX)")
for r in rx["regions"]:
    if r["wide"]:
        try:
            tx.channel_freq_hz(r["name"], 812000, "LongFast", None)
            check(False, f"{r['name']}: TX must refuse it (not supported), but accepted it")
        except (SystemExit, KeyError):
            check(True, f"{r['name']}: 2.4 GHz region refused by TX (RX-only)")
        continue
    lo, hi = tx.REGIONS.get(r["name"], (None, None))
    check((lo, hi) == (round(r["f_lo"], 6), round(r["f_hi"], 6)),
          f"{r['name']}: band {lo}-{hi} MHz vs RX {r['f_lo']}-{r['f_hi']}")
    if lo is None:
        continue
    bad = []
    for key, plan in r["plans"].items():
        bw = plan["bw"]
        if plan["n"] == 0:
            try:
                tx.channel_freq_hz(r["name"], bw, "x", None)
                bad.append(f"{key}: RX has 0 slots, TX accepted")
            except SystemExit:
                pass
            continue
        for s, f_rx in enumerate(plan["freqs"]):
            f_tx, slot, n = tx.channel_freq_hz(r["name"], bw, "x", s)
            if (f_tx, n) != (f_rx, plan["n"]):
                bad.append(f"{key} slot {s}: TX {f_tx} Hz/{n} slots vs RX {f_rx} Hz/{plan['n']}")
                break
    nslots = sum(p["n"] for p in r["plans"].values())
    check(not bad, f"{r['name']}: all {nslots} preset slots on the same frequency"
                   + ("" if not bad else " -- " + "; ".join(bad[:3])))

# --- channel hash + expanded key for the same name and key ---
for (name, psk, rx_spec), h in zip(CASES, rx["hashes"]):
    try:
        key = tx.expand_psk(psk)
        tx_ok = True
    except SystemExit:
        tx_ok = False
    if not (tx_ok and h["ok"]):
        check(tx_ok == h["ok"], f"{name}={rx_spec}: TX {'accepts' if tx_ok else 'refuses'}, "
                                f"RX {'accepts' if h['ok'] else 'refuses'}")
        continue
    th = tx.xor_hash(name.encode()) ^ tx.xor_hash(key)
    check(th == h["hash"] and key.hex() == h["key"],
          f"{name}={rx_spec}: hash 0x{th:02x}/{len(key)}B key vs RX 0x{h['hash']:02x}/"
          f"{len(h['key']) // 2}B")

# --- ppm: TX LO correction == RX tuning correction ---
bad = [t for t in rx["tune"] if tx.ppm_tune_hz(t["f"], t["ppm"]) != t["hz"]]
check(not bad, f"ppm tuning identical for {len(rx['tune'])} (freq, ppm) pairs"
               + ("" if not bad else f" -- e.g. {bad[0]}"))

print("FAILS:", fails)
sys.exit(1 if fails else 0)
