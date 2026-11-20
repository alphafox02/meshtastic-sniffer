# meshtastic-sniffer for Android (HackRF over USB OTG)

The whole sniffer running on an Android 10+ phone with a HackRF One plugged
into its USB port: receive, decode, map, node actions, and transmit
(channel messages, replies, requests, public-key DMs). The UI is the
sniffer's own web dashboard in a WebView.

```
HackRF ──USB OTG──> hackrf_android (Java, USB bulk transfers)
                         │ 256 KiB int8 I/Q packets
                         v
          SnifferService ── Native.push ──> libmeshsniffer.so (the C sniffer,
                         ^                    --external-source, --web on 127.0.0.1)
                         └── Native.txPlay <── tx.c player (built-in C TX engine)
MainActivity: settings, start/stop, WebView of http://127.0.0.1:8889
```

- **Receive:** the app tunes the HackRF (2 Msps; centre, gains and ppm from
  the settings) and pushes the samples into the library (`ext_src.c`).
- **Transmit:** packets are built and LoRa-modulated in C (`mesh_tx.c`,
  `lora_tx.c`, no python); the library hands the I/Q to the app, which
  stops RX, transmits on the LO the library computed (ppm-corrected) and
  resumes RX.
- **Security:** the dashboard listens on 127.0.0.1 only, and every
  `POST /api/*` needs a random token the app generates and injects into
  the WebView. Other apps on the phone can read the dashboard but cannot
  transmit or change keys.
- **Identity:** the TX node number is fixed (Settings) and its X25519 key
  lives in the app's private storage (`files/tx_key`).

## Build

Needs the Android SDK (platform 35), NDK r27c, CMake 3.22.1 and JDK 17.

```bash
# 1. FFTW3f + libcrypto for arm64-v8a, into ~/Android/deps (once)
android/deps/build_deps.sh            # MESH_DEPS_DIR / ANDROID_NDK_HOME to override

# 2. the APK
cd android
echo "sdk.dir=$HOME/Android/sdk" > local.properties
JAVA_HOME=~/Android/jdk ./gradlew assembleDebug
# -> app/build/outputs/apk/debug/app-debug.apk
```

### Signed release APK

The release build is signed with a key kept outside the repo. Create it once:

```bash
K=~/.config/meshtastic-sniffer/android-release; mkdir -p -m 700 $K
PW=$(openssl rand -base64 24 | tr -d '/+=')
keytool -genkeypair -keystore $K/release.jks -storetype PKCS12 -alias meshsniffer \
  -keyalg RSA -keysize 4096 -validity 10000 -dname "CN=Mesh Sniffer" -storepass "$PW" -keypass "$PW"
printf 'storeFile=%s\nstorePassword=%s\nkeyAlias=meshsniffer\nkeyPassword=%s\n' \
  $K/release.jks "$PW" "$PW" > $K/keystore.properties; chmod 600 $K/*
```

Then build:

```bash
JAVA_HOME=~/Android/jdk ./gradlew assembleRelease
# -> app/build/outputs/apk/release/app-release.apk
```

To use a `keystore.properties` file somewhere else, pass `-PmeshKeystoreProps=PATH` or set `MESH_KEYSTORE_PROPS`. Without the file, `assembleRelease` builds an unsigned APK.

Back up `release.jks` and its password. Updates install over an existing release install only if they're signed with the same key. A release APK can't replace a debug install (different key): uninstall the debug app first, which deletes its settings and its TX key (`files/tx_key`).

The native library compiles the repo's C sources as they are, with
`SNIFFER_LIBRARY` (no `main()`); libhackrf, curl, MQTT and ZMQ are left
out (those backends and outputs compile to stubs). On the desktop,
`make check_tx` runs the same library path (`test_ext_src`).

## Install and run

1. Enable Developer options and USB debugging on the phone, connect it to
   the PC, then `adb install -r app/build/outputs/apk/debug/app-debug.apk`
   (or copy the APK to the phone and open it).
2. For logs while the HackRF occupies the USB port, switch adb to Wi-Fi
   before unplugging: `adb tcpip 5555`, then
   `adb connect <phone-ip>:5555` and `adb logcat -s meshsniffer`.
3. Plug the HackRF into the phone with an OTG cable or adapter. Android
   offers to open Mesh Sniffer; allow USB access.
4. Set region, preset, channel/PSK, gains and ppm, then **Start**. The
   dashboard opens when the sniffer is up. **Log** shows the sniffer's
   output; the notification has a Stop button.

The HackRF draws about 500 mA from the phone. If it resets or isn't
found, use a powered USB hub or Y-cable.

Settings that worked with the desktop setup (EU_868 MediumFast): centre
869.0 MHz (auto: 500 kHz below the channel, off the DC spike), LNA 40 /
VGA 30, ppm 13 for that HackRF, TX gain 25.

Only transmit on channels you operate, within your region's power and
duty-cycle limits.

## Third-party code

- `app/src/main/java/com/mantz_it/hackrf_android/`: hackrf_android by
  Dennis Mantz, GPL-2.0-or-later, with small changes listed in its README.
- FFTW 3.3.10 (GPL-2.0-or-later) and OpenSSL 3.0.15 libcrypto (Apache-2.0),
  linked statically, built by `deps/build_deps.sh`.
