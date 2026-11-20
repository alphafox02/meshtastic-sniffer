/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package org.meshsniffer.android;

/** JNI entry points of libmeshsniffer.so (app/src/main/cpp/jni_bridge.c). */
public final class Native {
    static { System.loadLibrary("meshsniffer"); }

    private Native() {}

    /** Plays int8 I/Q on the HackRF; returns null on success, else an error message. */
    public interface TxHandler {
        String play(byte[] iq, long loHz, int rate, int gain, boolean amp);
    }

    private static volatile TxHandler txHandler;

    static void setTxHandler(TxHandler h) { txHandler = h; }

    /** Called from C (tx.c's player) on a web-server thread. */
    @SuppressWarnings("unused")
    static String txPlay(byte[] iq, long loHz, int rate, int gain, boolean amp) {
        TxHandler h = txHandler;
        return h == null ? "the HackRF is not ready" : h.play(iq, loHz, rate, gain, amp);
    }

    /** Runs the sniffer (same arguments as the command line) on a native thread. */
    static native int start(String[] args, String logPath, String home, String tmp);
    /** Stops it and waits; returns its exit code. One run per process. */
    static native int stop();
    static native boolean isRunning();
    /** Feeds interleaved int8 I/Q; 0 if accepted. */
    static native int push(byte[] buf, int len);
    /** Channel centre (Hz) of a preset in a region (firmware slot hash), 0 if unknown. */
    static native long channelFreq(String region, String preset, String channel);

    /** Frequency to program so a HackRF with this clock error lands on f (same as hackrf.h). */
    static long tuneHz(double f, double ppm) {
        return (long) Math.floor(f * (1.0 - ppm * 1e-6) + 0.5);
    }
}
