/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package org.meshsniffer.android;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.usb.UsbManager;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;
import android.util.Log;

import com.mantz_it.hackrf_android.Hackrf;
import com.mantz_it.hackrf_android.HackrfCallbackInterface;
import com.mantz_it.hackrf_android.HackrfUsbException;

import java.io.File;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Owns the HackRF and the sniffer library. Runs as a foreground service in
 * its own process (":sniffer"), so stopping it can end the process and a
 * new run starts with fresh native state.
 *
 * RX: hackrf_android's USB thread fills a queue with 256 KiB int8 I/Q
 * packets; the pump thread hands them to the library (Native.push).
 * TX: the library calls play() (from its web server thread): stop RX, tune
 * the LO the library computed, stream the I/Q, then restore RX.
 */
public class SnifferService extends Service implements HackrfCallbackInterface, Native.TxHandler {
    static final String TAG = "meshsniffer";
    static final String ACTION_STOP = "org.meshsniffer.android.STOP";
    static final String ACTION_STATUS = "org.meshsniffer.android.STATUS";
    private static final String CHANNEL_ID = "sniffer";
    private static final int QUEUE_PACKETS = 64;          /* 16 MiB, ~4 s at 2 Msps */
    private static final int TX_TAIL_PACKETS = 6;         /* zeros after the frame (> 4 in flight) */

    private SnifferConfig cfg;
    private Hackrf hackrf;
    private volatile ArrayBlockingQueue<byte[]> rxQueue;
    private volatile boolean alive, rxWanted;
    private final ReentrantLock pumpLock = new ReentrantLock();
    private final Object radioLock = new Object();
    private Thread pumpThread;
    private HandlerThread worker;
    private Handler workerHandler;
    private PowerManager.WakeLock wakeLock;
    private volatile String status = "starting";
    private boolean started;

    private final BroadcastReceiver usbDetached = new BroadcastReceiver() {
        @Override public void onReceive(Context c, Intent i) {
            setStatus("HackRF disconnected");
            stopSelf();
        }
    };

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopSelf();
            return START_NOT_STICKY;
        }
        if (started || intent == null) {
            broadcastStatus();
            return START_NOT_STICKY;
        }
        started = true;
        cfg = SnifferConfig.fromIntent(intent);
        startForeground(1, notification("Starting..."));
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "meshsniffer:rx");
        wakeLock.acquire();
        registerReceiver(usbDetached, new IntentFilter(UsbManager.ACTION_USB_DEVICE_DETACHED));
        worker = new HandlerThread("hackrf-control");
        worker.start();
        workerHandler = new Handler(worker.getLooper());
        setStatus("Waiting for the HackRF (allow USB access)...");
        if (!Hackrf.initHackrf(this, this, QUEUE_PACKETS)) {
            setStatus("No HackRF found on USB");
            stopSelf();
        }
        return START_NOT_STICKY;
    }

    /* hackrf_android: called on the main thread once USB access is granted */
    @Override
    public void onHackrfReady(Hackrf h) {
        workerHandler.post(() -> startAll(h));
    }

    @Override
    public void onHackrfError(String message) {
        setStatus("HackRF error: " + message);
        stopSelf();
    }

    private void startAll(Hackrf h) {
        hackrf = h;
        try {
            Log.i(TAG, "HackRF board " + Hackrf.convertBoardIdToString(h.getBoardID())
                    + ", firmware " + h.getVersionString().trim());
            File key = new File(getFilesDir(), "tx_key");
            File log = new File(getFilesDir(), "sniffer.log");
            Native.setTxHandler(this);
            if (Native.start(cfg.args(key.getAbsolutePath()), log.getAbsolutePath(),
                             getFilesDir().getAbsolutePath(), getCacheDir().getAbsolutePath()) != 0)
                throw new IllegalStateException("the sniffer did not start");
            configureRx();
            alive = true;
            rxQueue = hackrf.startRX();
            rxWanted = true;
            pumpThread = new Thread(this::pump, "rx-pump");
            pumpThread.setPriority(Thread.MAX_PRIORITY);
            pumpThread.start();
            setStatus(String.format(java.util.Locale.ROOT, "Receiving %s %s at %.3f MHz",
                    cfg.region, cfg.preset, cfg.centerHz / 1e6));
        } catch (Exception e) {
            Log.e(TAG, "start failed", e);
            setStatus("Start failed: " + e.getMessage());
            stopSelf();
        }
    }

    private void configureRx() throws HackrfUsbException {
        int rate = SnifferConfig.RATE;
        hackrf.setSampleRate(rate, 1);
        /* libhackrf's set_sample_rate also sets this (75% of the rate) */
        hackrf.setBasebandFilterBandwidth(Hackrf.computeBasebandFilterBandwidth((int) (0.75 * rate)));
        hackrf.setFrequency(Native.tuneHz(cfg.centerHz, cfg.ppm));
        hackrf.setRxLNAGain(cfg.lna);
        hackrf.setRxVGAGain(cfg.vga);
        hackrf.setAmp(cfg.amp);
    }

    /* Drain hackrf_android's queue into the library. Holding pumpLock while
     * polling keeps us off the queue while play() uses it for TX. */
    private void pump() {
        long pushed = 0, dropped = 0, lastLog = System.currentTimeMillis();
        while (alive) {
            pumpLock.lock();
            try {
                if (!rxWanted) { Thread.sleep(20); continue; }
                byte[] b = rxQueue.poll(200, TimeUnit.MILLISECONDS);
                if (b != null) {
                    if (Native.push(b, b.length) == 0) ++pushed; else ++dropped;
                    hackrf.returnBufferToBufferPool(b);
                } else if (alive && rxWanted && !hackrf.isStreaming()) {
                    /* hackrf_android ends RX when its queue overflows: restart */
                    Log.w(TAG, "RX stopped; restarting");
                    synchronized (radioLock) {
                        hackrf.stop();
                        configureRx();
                        rxQueue = hackrf.startRX();
                    }
                }
            } catch (InterruptedException e) {
                break;
            } catch (Exception e) {
                Log.e(TAG, "pump", e);
            } finally {
                pumpLock.unlock();
            }
            long now = System.currentTimeMillis();
            if (now - lastLog > 30000) {
                Log.i(TAG, "rx: " + pushed + " packets in, " + dropped + " not accepted, "
                        + hackrf.getAverageTransceiveRate() / 1000 + " kB/s");
                lastLog = now;
            }
        }
    }

    /* Native.TxHandler: called by the library on a web-server thread. */
    @Override
    public String play(byte[] iq, long loHz, int rate, int gain, boolean amp) {
        synchronized (radioLock) {
            if (hackrf == null || !alive) return "the HackRF is not ready";
            long t0 = System.currentTimeMillis();
            rxWanted = false;
            pumpLock.lock();       /* the pump is off the queue from here on */
            long tLock = System.currentTimeMillis();
            String err = null;
            try {
                hackrf.stop();
                Log.i(TAG, "TX: pump lock " + (tLock - t0) + " ms, RX stop "
                        + (System.currentTimeMillis() - tLock) + " ms");
                hackrf.setSampleRate(rate, 1);
                hackrf.setBasebandFilterBandwidth(Hackrf.computeBasebandFilterBandwidth((int) (0.75 * rate)));
                hackrf.setFrequency(loHz);
                hackrf.setTxVGAGain(gain);
                hackrf.setAmp(amp);
                ArrayBlockingQueue<byte[]> q = hackrf.startTX();
                int ps = hackrf.getPacketSize();
                for (int off = 0; off < iq.length && err == null; off += ps) {
                    byte[] p = new byte[ps];
                    System.arraycopy(iq, off, p, 0, Math.min(ps, iq.length - off));
                    if (!q.offer(p, 2, TimeUnit.SECONDS)) err = "TX stalled (USB)";
                }
                for (int i = 0; i < TX_TAIL_PACKETS && err == null; ++i)
                    if (!q.offer(new byte[ps], 2, TimeUnit.SECONDS)) err = "TX stalled (USB)";
                long packetMs = 1000L * (ps / 2) / rate;
                long deadline = System.currentTimeMillis() + 3000 + packetMs * (iq.length / ps + TX_TAIL_PACKETS);
                while (err == null && !q.isEmpty() && hackrf.isStreaming() && System.currentTimeMillis() < deadline)
                    Thread.sleep(5);
                if (err == null && !q.isEmpty()) err = "TX did not complete";
                /* the last packets in flight are the zero tail: let them go */
                if (err == null) Thread.sleep(4 * packetMs + 20);
                Log.i(TAG, String.format(java.util.Locale.ROOT, "TX %d bytes at %.6f MHz gain %d amp %b: %s",
                        iq.length, loHz / 1e6, gain, amp, err == null ? "ok" : err));
            } catch (Exception e) {
                err = "TX failed: " + e.getMessage();
            } finally {
                try {
                    hackrf.stop();
                    configureRx();
                    rxQueue = hackrf.startRX();
                } catch (Exception e) {
                    if (err == null) err = "RX restart after TX failed: " + e.getMessage();
                }
                rxWanted = true;
                pumpLock.unlock();
            }
            return err;
        }
    }

    @Override
    public void onDestroy() {
        alive = false;
        rxWanted = false;
        try { unregisterReceiver(usbDetached); } catch (Exception ignored) { }
        Native.setTxHandler(null);
        if (pumpThread != null) pumpThread.interrupt();
        try { if (Native.isRunning()) Native.stop(); } catch (Throwable ignored) { }
        try { if (hackrf != null) hackrf.stop(); } catch (Exception ignored) { }
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        if (worker != null) worker.quitSafely();
        setStatus("Stopped");
        super.onDestroy();
        /* the native sniffer runs once per process: end it, the next run gets a fresh one */
        new Handler(Looper.getMainLooper()).postDelayed(
                () -> android.os.Process.killProcess(android.os.Process.myPid()), 300);
    }

    private void setStatus(String s) {
        status = s;
        Log.i(TAG, "status: " + s);
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (started) nm.notify(1, notification(s));
        broadcastStatus();
    }

    private void broadcastStatus() {
        Intent i = new Intent(ACTION_STATUS).setPackage(getPackageName());
        i.putExtra("status", status);
        i.putExtra("running", alive);
        sendBroadcast(i);
    }

    private Notification notification(String text) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm.getNotificationChannel(CHANNEL_ID) == null)
            nm.createNotificationChannel(new NotificationChannel(CHANNEL_ID, "Sniffer",
                    NotificationManager.IMPORTANCE_LOW));
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
                PendingIntent.FLAG_IMMUTABLE);
        PendingIntent stop = PendingIntent.getService(this, 1,
                new Intent(this, SnifferService.class).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_download)
                .setContentTitle("Meshtastic sniffer")
                .setContentText(text)
                .setContentIntent(open)
                .addAction(new Notification.Action.Builder(null, "Stop", stop).build())
                .setOngoing(true)
                .build();
    }
}
