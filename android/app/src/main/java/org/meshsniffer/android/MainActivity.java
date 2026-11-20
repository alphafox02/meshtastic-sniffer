/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package org.meshsniffer.android;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.File;
import java.io.RandomAccessFile;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Settings + start/stop, and the sniffer's own web dashboard in a WebView. */
public class MainActivity extends Activity {
    private SharedPreferences prefs;
    private Spinner region, preset, lna, vga;
    private EditText channel, psk, center, ppm, txNode;
    private CheckBox amp, tx;
    private TextView statusView, logView;
    private ScrollView settingsView, logScroll;
    private WebView web;
    private FrameLayout root;
    private boolean webInjected;
    private final Handler ui = new Handler(Looper.getMainLooper());

    private final BroadcastReceiver statusReceiver = new BroadcastReceiver() {
        @Override public void onReceive(Context c, Intent i) {
            statusView.setText(i.getStringExtra("status"));
            if (i.getBooleanExtra("running", false)) waitForDashboard(0);
        }
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        prefs = getSharedPreferences("settings", MODE_PRIVATE);
        SnifferConfig c = SnifferConfig.load(prefs);
        c.save(prefs.edit());     /* keep the generated node id + token */

        LinearLayout form = new LinearLayout(this);
        form.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(16);
        form.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("Meshtastic sniffer (HackRF)");
        title.setTextSize(20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        form.addView(title);
        statusView = new TextView(this);
        statusView.setText("Stopped. Connect the HackRF with a USB OTG cable.");
        statusView.setPadding(0, dp(6), 0, dp(10));
        form.addView(statusView);

        LinearLayout buttons = new LinearLayout(this);
        Button start = button("Start", v -> startSniffer());
        Button stop = button("Stop", v -> stopSniffer());
        Button dash = button("Dashboard", v -> showWeb());
        Button logs = button("Log", v -> showLog());
        buttons.addView(start); buttons.addView(stop); buttons.addView(dash); buttons.addView(logs);
        form.addView(buttons);

        region = spinner(form, "Region", SnifferConfig.REGIONS, c.region);
        preset = spinner(form, "Preset", SnifferConfig.PRESETS, c.preset);
        channel = edit(form, "Channel name (empty: the preset's, e.g. MediumFast)", c.channel, InputType.TYPE_CLASS_TEXT);
        psk = edit(form, "Channel PSK, base64 as in the app (AQ== = default key)", c.psk, InputType.TYPE_CLASS_TEXT);
        center = edit(form, "RX centre frequency, MHz (auto: 500 kHz below the channel)",
                String.format(Locale.ROOT, "%.6f", c.centerHz / 1e6),
                InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_FLAG_DECIMAL);
        String[] lnaSteps = steps(0, 40, 8), vgaSteps = steps(0, 62, 2);
        lna = spinner(form, "LNA gain (dB)", lnaSteps, String.valueOf(c.lna));
        vga = spinner(form, "VGA gain (dB)", vgaSteps, String.valueOf(c.vga));
        amp = check(form, "RX +14 dB amp", c.amp);
        ppm = edit(form, "HackRF clock error, ppm (positive = fast)", String.valueOf(c.ppm),
                InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_FLAG_DECIMAL | InputType.TYPE_NUMBER_FLAG_SIGNED);
        tx = check(form, "Enable transmit (Send box, node actions, DMs)", c.tx);
        txNode = edit(form, "Transmit as node (!aabbccdd; keep it fixed)", c.txNode, InputType.TYPE_CLASS_TEXT);
        TextView note = new TextView(this);
        note.setText("Only transmit on channels you operate, within your region's power and duty-cycle limits.");
        note.setPadding(0, dp(12), 0, 0);
        form.addView(note);

        AdapterView.OnItemSelectedListener autoCenter = new AdapterView.OnItemSelectedListener() {
            boolean first = true;
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) {
                if (first) { first = false; return; }
                updateCenter();
            }
            @Override public void onNothingSelected(AdapterView<?> p) { }
        };
        region.setOnItemSelectedListener(autoCenter);
        preset.setOnItemSelectedListener(autoCenter);

        settingsView = new ScrollView(this);
        settingsView.addView(form);

        web = new WebView(this);
        WebSettings ws = web.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        web.setWebViewClient(new WebViewClient() {
            @Override public void onPageFinished(WebView v, String url) { injectToken(); }
        });

        logView = new TextView(this);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextSize(10);
        logView.setPadding(pad, pad, pad, pad);
        logView.setTextIsSelectable(true);
        logScroll = new ScrollView(this);
        logScroll.addView(logView);

        root = new FrameLayout(this);
        root.addView(settingsView);
        root.addView(web);
        root.addView(logScroll);
        show(settingsView);
        setContentView(root);
    }

    @Override protected void onStart() {
        super.onStart();
        androidx.core.content.ContextCompat.registerReceiver(this, statusReceiver,
                new IntentFilter(SnifferService.ACTION_STATUS),
                androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED);
        waitForDashboard(0);   /* already running from before? */
    }

    @Override protected void onStop() {
        unregisterReceiver(statusReceiver);
        super.onStop();
    }

    @Override public void onBackPressed() {
        if (web.getVisibility() == View.VISIBLE && web.canGoBack()) web.goBack();
        else if (settingsView.getVisibility() != View.VISIBLE) show(settingsView);
        else super.onBackPressed();
    }

    private SnifferConfig readForm() {
        SnifferConfig c = SnifferConfig.load(prefs);
        c.region = (String) region.getSelectedItem();
        c.preset = (String) preset.getSelectedItem();
        c.channel = channel.getText().toString().trim();
        c.psk = psk.getText().toString().trim();
        try { c.centerHz = Math.round(Double.parseDouble(center.getText().toString().trim()) * 1e6); }
        catch (NumberFormatException e) { /* keep the saved value */ }
        c.lna = Integer.parseInt((String) lna.getSelectedItem());
        c.vga = Integer.parseInt((String) vga.getSelectedItem());
        c.amp = amp.isChecked();
        try { c.ppm = Double.parseDouble(ppm.getText().toString().trim()); } catch (NumberFormatException e) { c.ppm = 0; }
        c.tx = tx.isChecked();
        String n = txNode.getText().toString().trim().toLowerCase(Locale.ROOT);
        if (n.matches("!?[0-9a-f]{8}")) c.txNode = n.startsWith("!") ? n : "!" + n;
        return c;
    }

    private void updateCenter() {
        SnifferConfig c = readForm();
        long f = Native.channelFreq(c.region, c.preset, c.channel);
        if (f > 0) center.setText(String.format(Locale.ROOT, "%.6f", (f - 500_000) / 1e6));
    }

    private void startSniffer() {
        SnifferConfig c = readForm();
        long f = Native.channelFreq(c.region, c.preset, c.channel);
        if (f > 0 && Math.abs(f - c.centerHz) > 900_000) {
            statusView.setText(String.format(Locale.ROOT,
                    "The channel (%.3f MHz) is outside the 2 MHz around the centre: set the centre near it.", f / 1e6));
            return;
        }
        c.save(prefs.edit());
        webInjected = false;
        Intent i = new Intent(this, SnifferService.class);
        c.toIntent(i);
        startForegroundService(i);
        statusView.setText("Starting... allow USB access to the HackRF when asked.");
        waitForDashboard(0);
    }

    private void stopSniffer() {
        startService(new Intent(this, SnifferService.class).setAction(SnifferService.ACTION_STOP));
        web.loadUrl("about:blank");
        show(settingsView);
    }

    private String baseUrl() { return "http://127.0.0.1:" + new SnifferConfig().webPort; }

    /* Poll /api/tx until the sniffer's web server answers, then open the dashboard. */
    private void waitForDashboard(int attempt) {
        new Thread(() -> {
            boolean up = false;
            String pub = null;
            try {
                HttpURLConnection h = (HttpURLConnection) new URL(baseUrl() + "/api/tx").openConnection();
                h.setConnectTimeout(500);
                h.setReadTimeout(1000);
                if (h.getResponseCode() == 200) {
                    up = true;
                    java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
                    try (java.io.InputStream in = h.getInputStream()) {   /* readAllBytes() is API 33+ */
                        byte[] buf = new byte[4096];
                        for (int n; (n = in.read(buf)) > 0; ) body.write(buf, 0, n);
                    }
                    pub = new JSONObject(body.toString("UTF-8")).optString("public_key", null);
                }
                h.disconnect();
            } catch (Exception ignored) { }
            final boolean ok = up;
            final String key = pub;
            ui.post(() -> {
                if (ok) {
                    if (key != null && !key.isEmpty())
                        statusView.setText(statusView.getText() + "\nPublic key (for DMs): " + key);
                    if (web.getUrl() == null || !web.getUrl().startsWith(baseUrl())) showWeb();
                } else if (attempt < 60) {
                    ui.postDelayed(() -> waitForDashboard(attempt + 1), 1000);
                }
            });
        }).start();
    }

    private void showWeb() {
        if (web.getUrl() == null || !web.getUrl().startsWith(baseUrl())) web.loadUrl(baseUrl() + "/");
        show(web);
    }

    /* The dashboard sends the token from sessionStorage (Config -> Transmit):
     * put it there, plus Send settings matching the receive channel the
     * first time, then reload once so the page picks them up. */
    private void injectToken() {
        if (webInjected || web.getUrl() == null || !web.getUrl().startsWith(baseUrl())) return;
        webInjected = true;
        SnifferConfig c = SnifferConfig.load(prefs);
        try {
            JSONObject s = new JSONObject();
            s.put("preset", c.preset).put("channel", c.channel).put("psk", c.psk).put("gain", "25")
             .put("slot", "").put("to", "").put("hop", "3").put("long_name", "").put("short_name", "")
             .put("amp", false);
            String js = "(function(){try{var t=" + JSONObject.quote(c.token) + ";"
                    + "var changed=sessionStorage.getItem('txToken')!==t;"
                    + "sessionStorage.setItem('txToken',t);"
                    + "if(!localStorage.getItem('txSettings')){localStorage.setItem('txSettings',"
                    + JSONObject.quote(s.toString()) + ");changed=true;}"
                    + "if(changed)location.reload();}catch(e){}})()";
            web.evaluateJavascript(js, null);
        } catch (Exception ignored) { }
    }

    private void showLog() {
        File f = new File(getFilesDir(), "sniffer.log");
        String text = "(no log yet)";
        try (RandomAccessFile r = new RandomAccessFile(f, "r")) {
            long len = r.length(), from = Math.max(0, len - 64 * 1024);
            byte[] b = new byte[(int) (len - from)];
            r.seek(from);
            r.readFully(b);
            text = new String(b, StandardCharsets.UTF_8);
        } catch (Exception ignored) { }
        logView.setText(text);
        show(logScroll);
        logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
    }

    private void show(View v) {
        settingsView.setVisibility(v == settingsView ? View.VISIBLE : View.GONE);
        web.setVisibility(v == web ? View.VISIBLE : View.GONE);
        logScroll.setVisibility(v == logScroll ? View.VISIBLE : View.GONE);
    }

    /* ---- small view helpers ---- */

    private int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }

    private Button button(String text, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(text);
        b.setOnClickListener(l);
        b.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        return b;
    }

    private void label(LinearLayout parent, String text) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setPadding(0, dp(10), 0, 0);
        parent.addView(t);
    }

    private Spinner spinner(LinearLayout parent, String label, String[] items, String selected) {
        label(parent, label);
        Spinner s = new Spinner(this);
        s.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, items));
        for (int i = 0; i < items.length; ++i) if (items[i].equals(selected)) s.setSelection(i);
        parent.addView(s);
        return s;
    }

    private EditText edit(LinearLayout parent, String label, String value, int type) {
        label(parent, label);
        EditText e = new EditText(this);
        e.setText(value);
        e.setInputType(type);
        e.setSingleLine(true);
        parent.addView(e);
        return e;
    }

    private CheckBox check(LinearLayout parent, String label, boolean value) {
        CheckBox c = new CheckBox(this);
        c.setText(label);
        c.setChecked(value);
        parent.addView(c);
        return c;
    }

    private static String[] steps(int from, int to, int step) {
        String[] s = new String[(to - from) / step + 1];
        for (int i = 0; i < s.length; ++i) s[i] = String.valueOf(from + i * step);
        return s;
    }
}
