# meshtastic-recover

Offline PSK recovery for Meshtastic LoRa captures. The aircrack-ng of
the Meshtastic audit suite.

## What it does

Reads a libpcap file produced by `meshtastic-sniffer --pcap=PATH` and a
wordlist of candidate keys, and prints any keys that successfully
decrypt one or more captured frames. Output is in `--keys-file=`
compatible format so you can immediately re-feed the recovered keys to
`meshtastic-sniffer` to decrypt past or future traffic on those
channels.

## Why it exists

- **Defensive auditing**: validate that your channel keys survive a
  wordlist attack (rockyou-class lists run in seconds).
- **Lost-key recovery**: get back into a channel whose
  `meshtastic.org/e/` URL you misplaced, when you still have a recent
  pcap from a sniffer that recorded the encrypted traffic.
- **Education**: demonstrate the security model -- the channel-hash
  byte is an 8-bit fingerprint of the key, AES-CTR has no integrity
  check, and the protobuf parse on a successful decrypt is the
  confirmation. Same primitives apply to anyone designing a similar
  scheme.
- **Authorized pentesting**: where Meshtastic is in scope. Same
  dual-use posture as aircrack-ng -- the binary is neutral, scope and
  authorization is the operator's responsibility.

## Algorithm

For each candidate (channel name, PSK) pair:

1. **Channel-hash prefilter** -- compute `xorHash(name) XOR xorHash(psk)`
   and skip any frame whose 1-byte header.channel field doesn't match.
   8-bit prefilter eliminates 99.6% of decrypt attempts per frame.
2. **AES-CTR decrypt** the still-encrypted Data envelope using the
   nonce from the cleartext header (packet_id + from + zeros).
3. **Protobuf parse** the result. A clean parse to a Data message with
   a non-zero portnum and non-empty payload is the confirmation that
   the candidate is the right key. Wrong-key decrypts produce uniform
   random bytes which essentially never satisfy this.

Wordlist entries can be:

| Form | Example | Behaviour |
|---|---|---|
| `base64:` prefix | `base64:AQ==` | raw 16/32-byte key, base64-encoded |
| `hex:` prefix | `hex:d4f1bb...01` | raw 16/32-byte key, hex-encoded |
| `simple<N>` | `simple1`, `simple7` | the firmware's simpleN derivation (1..255) |
| plain text | `hunter2`, `secret` | passphrase: padded/truncated to 16 bytes |

The `--simple-keys` flag also tries each of the 255 simpleN keys
against a built-in list of common channel names (`LongFast`,
`MediumFast`, etc.). Most factory-default Meshtastic deployments are
recovered instantly from this pass.

## Usage

```bash
# Capture some encrypted traffic with the sniffer
./meshtastic-sniffer --hackrf --pcap=/tmp/session.pcap

# Recover keys from the capture
./meshtastic-recover --pcap=/tmp/session.pcap \
                     --simple-keys \
                     --wordlist=/usr/share/dict/words \
                     --output=/tmp/recovered.keys

# Re-decode the same capture with the recovered keys
./meshtastic-sniffer --file=/tmp/session.pcap --keys-file=/tmp/recovered.keys
```

### Flags

```
--pcap=FILE         libpcap input (DLT_USER0 from --pcap=PATH on the sniffer)
--wordlist=FILE     candidate PSKs, one per line; supports base64:/hex:/simpleN/
                    plain-passphrase forms
--simple-keys       also try simple1..simple255 against common channel names
--output=FILE       append recovered keys here (default: stdout)
--max-frames=N      stop after testing N frames per candidate (0 = all)
-h, --help          this help
```

## Realistic attack surface

| Channel type | Recoverable? |
|---|---|
| Default key (PSK = `simple1` etc.) on a standard channel name | Instant via `--simple-keys` |
| Channel using a weak passphrase (in /usr/share/dict/words or rockyou) | Seconds with a wordlist pass |
| Channel using a strong random 16- or 32-byte key | Not feasible (2^128 search space) |

The sniffer's `--archive=DIR` and `--pcap=PATH` outputs are both
readable by this tool; pcap is preferred since the on-air bytes are
preserved exactly.

## Build

The recover binary is built alongside the main sniffer when you build
the parent project:

```bash
cd .. && mkdir -p build && cd build
cmake .. && make -j$(nproc)
# produces both build/meshtastic-sniffer and build/meshtastic-recover
```

It links against OpenSSL (for AES-CTR). No FFTW / SDR dependencies --
the cracker is a pure offline tool.

## GPU acceleration (planned)

CPU is fast for typical wordlists (millions of trials per second per
core, OpenMP-parallelized across all cores, channel-hash prefilter
eliminates 99.6% of work). A GPU port makes sense only for very large
keyspaces or distributed cracking.

The chosen architecture is a **hashcat custom-mode plugin**, not a
private OpenCL kernel inside this binary. Reasons:

- Hashcat's AES kernels are mature, hand-tuned, audited, and cover
  NVIDIA / AMD / Apple Silicon. Re-implementing them risks crypto bugs.
- Hashcat ships rule-based attacks, masks, distributed cracking,
  workload tuning -- all for free once the plugin exists.
- Submitting upstream means the work benefits more users than just our
  own.

`meshtastic-recover --hashcat-export=FILE` produces a hash file in a
hashcat-idiomatic format the plugin will consume. One line per frame:

```
$meshtastic$1*<chash>*<packet_id>*<from_node>*<name_hex>*<ciphertext>
```

| Field | Length | Meaning |
|---|---|---|
| `$meshtastic$` | 12 | scheme tag |
| `1` | 1 | format version (integer; bump on incompatible changes) |
| `<chash>` | 2 hex | 1-byte channel-hash from frame[13] |
| `<packet_id>` | 8 hex | uint32 LE from frame[8..11] |
| `<from_node>` | 8 hex | uint32 LE from frame[4..7] |
| `<name_hex>` | 0+ hex | UTF-8 channel name (when known); empty signals unknown |
| `<ciphertext>` | variable hex | frame[16..end] (encrypted Data envelope) |

`--channel-name=NAME` populates the name field (matches WPA-EAPOL's
ESSID-in-hash pattern; the realistic attack model is "operator knows
the channel name from cleartext NodeInfo broadcasts and brute-forces
the PSK"). When empty (default), the future plugin iterates a builtin
list of common preset names per candidate.

**Format precedents** (so hashcat maintainers can match it on sight):

- The dollar-tag + star-delimited shape mirrors **mode 22400 / AES Crypt**
  (`$aescrypt$1*<iv>*<salt>*<ct>*<hmac>`) — closest existing structural twin.
- The "expose nonce components separately, let the kernel reconstruct"
  choice mirrors **mode 22000 / WPA** (`WPA*01*<pmkid>*<mac_ap>*<mac_sta>*<essid_hex>*<anonce>*<eapol>*<msg_pair>`).
  Lets the GPU kernel build the 16-byte AES-CTR nonce inline:
  `packet_id_LE || 4 zero bytes || from_node_LE || 4 zero bytes`
  matching `build_nonce()` in `mesh_packet.c`.
- Lowercase hex throughout, integer version, fixed-length signature
  token verified via `TOKEN_ATTR_VERIFY_SIGNATURE` (the standard
  hashcat parser path).

**Plugin verifier** given a candidate `(channel_name, psk)`:

1. Compute `xorHash(channel_name) XOR xorHash(psk)`; compare to `<chash>`. Skip on mismatch (8-bit prefilter, eliminates ~99.6% of work per frame).
2. AES-CTR decrypt `<ciphertext>` using `psk` as the AES key and the
   reconstructed 16-byte nonce.
3. Confirm decrypted bytes parse as a Meshtastic Data envelope with
   `portnum > 0` and non-empty payload (same gate the CPU `meshtastic-recover` uses).

**Hash-mode number:** to be assigned by hashcat maintainers when the
plugin PR is reviewed (their convention: 100-step increments, recently
35000-series and 70000-series). Until then, treat as draft. The format
itself is forward-stable; if maintainers request changes, we bump
`$meshtastic$1` -> `$meshtastic$2` and update `--hashcat-export`
accordingly. The pcap remains the canonical archive; the hashcat
export is just a derived view.

## Honest limitations

- **The captured frame's bytes must be intact.** Bit errors in the
  cleartext header (from / packet_id) will mangle the AES-CTR nonce
  even with the right key, breaking recovery. Test your captures by
  running the sniffer against the same pcap and checking that frames
  come through with `payload_crc_ok` either passing or absent (i.e.
  no CRC failure).
- **No GPU support yet.** CPU-only.
- **No PMKID-style attack.** Meshtastic doesn't have an EAPOL handshake;
  the per-frame channel-hash + ciphertext is the only side-channel the
  attacker has, and we use both.

## License

GPL-3.0-or-later. See `../LICENSE`. Copyright (c) 2026 CEMAXECUTER LLC.
