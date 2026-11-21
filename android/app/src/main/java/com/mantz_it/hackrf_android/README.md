# hackrf_android (vendored)

Java USB driver for the HackRF by Dennis Mantz, from
https://github.com/demantz/hackrf_android at commit
`334e0046f23d00c1a6d27a8dd0dd1e529a47a498` (2025-08-13).
GPL-2.0-or-later: see `COPYING`.

Changes for meshtastic-sniffer, each marked `meshtastic-sniffer` in `Hackrf.java`:

- `transceiverMode` and `usbThread` are `volatile`; the USB thread reads
  the mode while other threads change it.
- `stop()` cancels the in-flight USB requests and joins the USB thread,
  so switching RX → TX → RX doesn't leave an old thread racing the new
  one for request completions in `requestWait()`.
- `isStreaming()`: whether the RX/TX thread is still running (RX stops by
  itself when the application doesn't drain the queue fast enough).
