/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package org.meshsniffer.android;

import android.content.Intent;
import android.content.SharedPreferences;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Run settings: stored in the activity's preferences, passed to the service in the Intent. */
final class SnifferConfig {
    static final String[] REGIONS = { "US", "EU_868", "EU_433", "CN", "JP", "ANZ", "ANZ_433", "RU", "KR",
            "TW", "IN", "NZ_865", "TH", "UA_433", "UA_868", "MY_433", "MY_919", "SG_923", "PH_433",
            "PH_868", "PH_915", "KZ_433", "KZ_863", "NP_865", "BR_902" };
    static final String[] PRESETS = { "LONG_FAST", "LONG_MODERATE", "LONG_SLOW", "LONG_TURBO",
            "MEDIUM_FAST", "MEDIUM_SLOW", "SHORT_FAST", "SHORT_SLOW", "SHORT_TURBO" };
    static final int RATE = 2_000_000;

    String region = "EU_868";
    String preset = "MEDIUM_FAST";
    String channel = "";          // "" = the preset's channel name
    String psk = "AQ==";          // as in the app
    long centerHz = 869_000_000L; // keep the channel off the HackRF's DC spike
    int lna = 40, vga = 30;
    boolean amp = false;
    double ppm = 0;
    boolean tx = true;
    String txNode = "";           // "!aabbccdd"
    String token = "";            // --api-token, injected into the dashboard
    int webPort = 8889;

    static SnifferConfig load(SharedPreferences p) {
        SnifferConfig c = new SnifferConfig();
        c.region = p.getString("region", c.region);
        c.preset = p.getString("preset", c.preset);
        c.channel = p.getString("channel", c.channel);
        c.psk = p.getString("psk", c.psk);
        c.centerHz = p.getLong("centerHz", c.centerHz);
        c.lna = p.getInt("lna", c.lna);
        c.vga = p.getInt("vga", c.vga);
        c.amp = p.getBoolean("amp", c.amp);
        c.ppm = Double.longBitsToDouble(p.getLong("ppm", Double.doubleToLongBits(c.ppm)));
        c.tx = p.getBoolean("tx", c.tx);
        c.txNode = p.getString("txNode", "");
        c.token = p.getString("token", "");
        SecureRandom rnd = new SecureRandom();
        if (c.txNode.isEmpty()) c.txNode = String.format(Locale.ROOT, "!%08x", 0x10000000 | (rnd.nextInt() & 0x0FFFFFFF));
        if (c.token.isEmpty()) {
            byte[] b = new byte[16];
            rnd.nextBytes(b);
            StringBuilder sb = new StringBuilder();
            for (byte x : b) sb.append(String.format(Locale.ROOT, "%02x", x));
            c.token = sb.toString();
        }
        return c;
    }

    void save(SharedPreferences.Editor e) {
        e.putString("region", region).putString("preset", preset).putString("channel", channel)
         .putString("psk", psk).putLong("centerHz", centerHz).putInt("lna", lna).putInt("vga", vga)
         .putBoolean("amp", amp).putLong("ppm", Double.doubleToLongBits(ppm)).putBoolean("tx", tx)
         .putString("txNode", txNode).putString("token", token).apply();
    }

    void toIntent(Intent i) {
        i.putExtra("region", region).putExtra("preset", preset).putExtra("channel", channel)
         .putExtra("psk", psk).putExtra("centerHz", centerHz).putExtra("lna", lna).putExtra("vga", vga)
         .putExtra("amp", amp).putExtra("ppm", ppm).putExtra("tx", tx).putExtra("txNode", txNode)
         .putExtra("token", token).putExtra("webPort", webPort);
    }

    static SnifferConfig fromIntent(Intent i) {
        SnifferConfig c = new SnifferConfig();
        c.region = i.getStringExtra("region");
        c.preset = i.getStringExtra("preset");
        c.channel = i.getStringExtra("channel");
        c.psk = i.getStringExtra("psk");
        c.centerHz = i.getLongExtra("centerHz", c.centerHz);
        c.lna = i.getIntExtra("lna", c.lna);
        c.vga = i.getIntExtra("vga", c.vga);
        c.amp = i.getBooleanExtra("amp", c.amp);
        c.ppm = i.getDoubleExtra("ppm", 0);
        c.tx = i.getBooleanExtra("tx", c.tx);
        c.txNode = i.getStringExtra("txNode");
        c.token = i.getStringExtra("token");
        c.webPort = i.getIntExtra("webPort", c.webPort);
        return c;
    }

    /** The channel name the preset uses when none is given ("MediumFast"). */
    String channelName() {
        if (channel != null && !channel.isEmpty()) return channel;
        StringBuilder sb = new StringBuilder();
        for (String w : preset.split("_")) {
            String x = w.equals("MODERATE") ? "Mod" : w.charAt(0) + w.substring(1).toLowerCase(Locale.ROOT);
            sb.append(x);
        }
        return sb.toString();
    }

    /** Command line for the sniffer library. */
    String[] args(String txKeyPath) {
        List<String> a = new ArrayList<>();
        a.add("--external-source");
        a.add("--rate=" + RATE);
        a.add("--center=" + centerHz);
        a.add("--region=" + region);
        a.add("--presets=" + preset);
        String keys = "default";
        if (psk != null && !psk.isEmpty())
            keys = channelName() + "=base64:" + psk + ",default";
        a.add("--keys=" + keys);
        a.add("--ppm=" + ppm);
        a.add("--scan-and-decode");
        a.add("--web=" + webPort);
        a.add("--web-bind=127.0.0.1");     // never reachable from the network
        a.add("--api-token=" + token);      // other apps on the phone can't transmit either
        if (tx) {
            a.add("--tx");
            a.add("--tx-node=" + txNode);
            a.add("--tx-key=" + txKeyPath);
        }
        return a.toArray(new String[0]);
    }
}
