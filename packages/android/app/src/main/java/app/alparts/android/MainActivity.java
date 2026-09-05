package app.alparts.android;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowManager;
import android.webkit.CookieManager;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebChromeClient;
import android.webkit.ValueCallback;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.webkit.JavaScriptReplyProxy;
import androidx.webkit.WebViewCompat;
import androidx.webkit.WebViewFeature;
import org.json.JSONObject;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public final class MainActivity extends Activity {
    private WebView web;
    private SecretVault vault;
    private String origin;
    private boolean unlocked;
    private boolean authenticating;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable idleLock = this::lock;
    private int idleMinutes = 5;
    private JavaScriptReplyProxy saveReply;
    private int saveRequest;
    private long expectedBytes, writtenBytes;
    private String saveToken;
    private OutputStream saveStream;
    private Uri saveUri;
    private ValueCallback<Uri[]> fileSelection;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        try { vault = new SecretVault(this); }
        catch (Exception ignored) { showStatus("この端末でデータを安全に保存できません。"); return; }
        origin = getPreferences(MODE_PRIVATE).getString("server", null);
        try { if (origin != null) origin = ServerAddress.normalize(origin); }
        catch (RuntimeException ignored) { showStatus("保存された接続先を確認できません。"); return; }
        idleMinutes = getPreferences(MODE_PRIVATE).getInt("idleMinutes", 5);
        unlock();
    }

    private void showStatus(String message) {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 64, 32, 32);
        TextView text = new TextView(this);
        text.setText(message);
        layout.addView(text);
        Button retry = new Button(this);
        retry.setText("ロックを解除");
        retry.setOnClickListener(view -> unlock());
        layout.addView(retry);
        setContentView(layout);
    }

    private void unlock() {
        if (authenticating || vault == null) return;
        KeyguardManager manager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        if (!manager.isDeviceSecure()) {
            showStatus("端末の画面ロックを設定してから、もう一度お試しください。");
            return;
        }
        Intent intent = manager.createConfirmDeviceCredentialIntent("alparts", "続けるには端末のロックを解除してください。");
        if (intent == null) return;
        authenticating = true;
        startActivityForResult(intent, 10);
    }

    private void connectionSetup() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 64, 32, 32);
        TextView label = new TextView(this);
        label.setText("管理者から案内された接続先を入力してください。");
        EditText address = new EditText(this);
        address.setSingleLine(true);
        address.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_URI);
        address.setHint("https://chat.example.com");
        Button connect = new Button(this);
        connect.setText("接続する");
        connect.setOnClickListener(view -> {
            try {
                origin = ServerAddress.normalize(address.getText().toString());
                if (!getPreferences(MODE_PRIVATE).edit().putString("server", origin).commit()) throw new IllegalStateException();
                openClient();
            } catch (RuntimeException ignored) { address.setError("接続先を確認してください。"); }
        });
        layout.addView(label); layout.addView(address); layout.addView(connect);
        setContentView(layout);
    }

    @android.annotation.SuppressLint("SetJavaScriptEnabled") // Only APK code runs; exact-origin, main-frame bridge and CSP are enforced below.
    private void openClient() {
        if (!unlocked) return;
        if (origin == null) { connectionSetup(); return; }
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            showStatus("Android System WebView を更新してください。"); return;
        }
        web = new WebView(this);
        WebView.setWebContentsDebuggingEnabled(false);
        WebSettings settings = web.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
        settings.setSaveFormData(false);
        settings.setSupportMultipleWindows(false);
        CookieManager.getInstance().setAcceptThirdPartyCookies(web, false);
        web.setWebChromeClient(new WebChromeClient() {
            @Override public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if (!unlocked || fileSelection != null || saveReply != null) return false;
                fileSelection = callback;
                try {
                    startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), 21);
                } catch (RuntimeException ignored) { fileSelection = null; callback.onReceiveValue(null); }
                return true;
            }
        });
        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) WebViewCompat.addWebMessageListener(web, "alpartsNative", Set.of(origin), (view, message, source, mainFrame, reply) -> {
            if (!mainFrame || !unlocked || !ServerAddress.sameOrigin(origin, source.toString())) return;
            handleBridge(message.getData(), reply);
        });
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                // All document navigation stays within bundled content; external links open in the browser.
                if (request.isForMainFrame() && request.hasGesture()
                        && Set.of("https", "http").contains(request.getUrl().getScheme())) {
                    try { startActivity(new Intent(Intent.ACTION_VIEW, request.getUrl())); } catch (RuntimeException ignored) { }
                }
                return true;
            }
            @Override public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (!ServerAddress.sameOrigin(origin, uri.toString())) return blocked();
                String path = uri.getPath();
                if (path == null || path.contains("..") || path.contains("\\")) return blocked();
                // Only API requests can reach the server. No remote HTML or script is used as the app UI.
                if (path.startsWith("/api/") && !request.isForMainFrame()) return null;
                if (!"GET".equals(request.getMethod())) return blocked();
                String asset = path.equals("/") ? "index.html" : path.substring(1);
                try {
                    InputStream input = getAssets().open("web/" + asset);
                    if (asset.equals("index.html")) {
                        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                        byte[] part = new byte[8192];
                        int length;
                        while ((length = input.read(part)) != -1) {
                            if (buffer.size() + length > 256 * 1024) throw new IllegalStateException();
                            buffer.write(part, 0, length);
                        }
                        String html = new String(buffer.toByteArray(), StandardCharsets.UTF_8);
                        input.close();
                        input = new ByteArrayInputStream(html.replace("<head>", "<head><script src=\"/android-bridge.js\"></script>").getBytes(StandardCharsets.UTF_8));
                    }
                    String mime = asset.endsWith(".html") ? "text/html" : asset.endsWith(".js") ? "text/javascript"
                        : asset.endsWith(".css") ? "text/css" : asset.endsWith(".svg") ? "image/svg+xml"
                        : asset.endsWith(".png") ? "image/png" : "application/octet-stream";
                    return new WebResourceResponse(mime, "UTF-8", 200, "OK", Map.of(
                        "Cache-Control", "no-store", "X-Content-Type-Options", "nosniff",
                        "Content-Security-Policy", "default-src 'none'; script-src " + origin + "/assets/ " + origin + "/android-bridge.js; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self' " + origin.replace("https:", "wss:") + "; frame-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'",
                        "Referrer-Policy", "no-referrer"), input);
                } catch (Exception ignored) { return blocked(); }
            }
        });
        setContentView(web);
        web.loadUrl(origin + "/");
        resetIdle();
    }

    private WebResourceResponse blocked() {
        return new WebResourceResponse("text/plain", "UTF-8", 403, "Forbidden", Map.of("Cache-Control", "no-store"), new ByteArrayInputStream(new byte[0]));
    }

    private void handleBridge(String raw, JavaScriptReplyProxy reply) {
        int id = -1;
        try {
            if (raw == null || raw.length() > 1_500_000) throw new IllegalArgumentException();
            JSONObject request = new JSONObject(raw);
            id = request.getInt("id");
            String method = request.getString("method");
            JSONObject args = request.optJSONObject("args");
            Object result = Boolean.TRUE;
            switch (method) {
                case "info": result = new JSONObject().put("platform", "android").put("version", BuildConfig.VERSION_NAME)
                    .put("serverUrl", origin).put("idleLockMinutes", idleMinutes).put("locked", false)
                    .put("secureStorageReady", true).put("serverManaged", true); break;
                case "get": result = vault.get(origin, args.getString("name")); break;
                case "set": vault.set(origin, args.getString("name"), args.getString("value")); break;
                case "delete": vault.delete(origin, args.getString("name")); break;
                case "idle":
                    int minutes = args.getInt("minutes");
                    if (!Set.of(1, 5, 15, 30, 60).contains(minutes)) throw new IllegalArgumentException();
                    idleMinutes = minutes;
                    if (!getPreferences(MODE_PRIVATE).edit().putInt("idleMinutes", minutes).commit()) throw new IllegalStateException();
                    resetIdle(); result = minutes; break;
                case "lock": handler.post(this::lock); break;
                case "unlock": break; // OS authentication gates creation of this WebView.
                case "beginSave":
                    if (saveReply != null || saveStream != null) throw new IllegalStateException();
                    expectedBytes = args.getLong("expectedBytes");
                    if (expectedBytes < 0 || expectedBytes > 100L * 1024 * 1024) throw new IllegalArgumentException();
                    String name = args.getString("name").replaceAll("[\\\\/\\p{Cntrl}]", "_");
                    if (name.isEmpty() || name.length() > 240) throw new IllegalArgumentException();
                    saveReply = reply; saveRequest = id;
                    if (args.optBoolean("dangerous") || name.toLowerCase(java.util.Locale.ROOT).matches(".*\\.(apk|exe|msi|bat|cmd|ps1|sh|html?|svg|js|jar)$")) {
                        new android.app.AlertDialog.Builder(this)
                            .setMessage("このファイルを開くと、端末やデータに影響する可能性があります。送信者と内容を確認してから開いてください。")
                            .setPositiveButton("保存する", (dialog, which) -> launchSave(name))
                            .setNegativeButton("キャンセル", (dialog, which) -> cancelSaveDialog())
                            .setOnCancelListener(dialog -> cancelSaveDialog()).show();
                    } else launchSave(name);
                    return;
                case "writeSave":
                    requireSave(args);
                    byte[] bytes = android.util.Base64.decode(args.getString("chunk"), android.util.Base64.NO_WRAP);
                    if (bytes.length > 1024 * 1024 || writtenBytes + bytes.length > expectedBytes) throw new IllegalArgumentException();
                    saveStream.write(bytes); writtenBytes += bytes.length; result = writtenBytes; break;
                case "finishSave":
                    requireSave(args);
                    if (writtenBytes != expectedBytes) throw new IllegalStateException();
                    saveStream.close(); saveStream = null; saveUri = null; saveToken = null; break;
                case "cancelSave": requireSave(args); cancelSave(); break;
                default: throw new IllegalArgumentException();
            }
            respond(reply, id, result, null);
        } catch (Exception ignored) { respond(reply, id, null, "操作を完了できませんでした。"); }
    }
    private void requireSave(JSONObject args) throws Exception {
        if (saveStream == null || !args.getString("token").equals(saveToken)) throw new IllegalArgumentException();
    }
    private void launchSave(String name) {
        if (!unlocked || saveReply == null) return;
        try {
            Intent save = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/octet-stream").putExtra(Intent.EXTRA_TITLE, name);
            startActivityForResult(save, 20);
        } catch (RuntimeException ignored) { cancelSaveDialog(); }
    }
    private void cancelSaveDialog() {
        if (saveReply != null) respond(saveReply, saveRequest, null, null);
        saveReply = null;
    }
    private void cancelSave() {
        try { if (saveStream != null) saveStream.close(); } catch (Exception ignored) { }
        try { if (saveUri != null) android.provider.DocumentsContract.deleteDocument(getContentResolver(), saveUri); } catch (Exception ignored) { }
        saveStream = null; saveUri = null; saveToken = null;
    }
    private void respond(JavaScriptReplyProxy reply, int id, Object result, String error) {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) return;
        try { reply.postMessage(new JSONObject().put("id", id).put("result", result == null ? JSONObject.NULL : result)
            .put("error", error == null ? JSONObject.NULL : error).toString()); } catch (Exception ignored) { }
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == 10) {
            authenticating = false;
            if (result == RESULT_OK) { unlocked = true; openClient(); }
            else showStatus("アプリはロックされています。");
        } else if (request == 20 && saveReply != null) {
            try {
                if (result == RESULT_OK && data != null && data.getData() != null) {
                    saveUri = data.getData();
                    saveStream = getContentResolver().openOutputStream(saveUri, "wt");
                    if (saveStream == null) throw new IllegalStateException();
                    saveToken = UUID.randomUUID().toString(); writtenBytes = 0;
                }
                respond(saveReply, saveRequest, saveToken, null);
            } catch (Exception ignored) { cancelSave(); respond(saveReply, saveRequest, null, "保存できませんでした。"); }
            saveReply = null;
            if (web != null) { web.setVisibility(View.VISIBLE); web.onResume(); }
            resetIdle();
        } else if (request == 21 && fileSelection != null) {
            fileSelection.onReceiveValue(result == RESULT_OK && data != null && data.getData() != null ? new Uri[]{data.getData()} : null);
            fileSelection = null;
            if (web != null) { web.setVisibility(View.VISIBLE); web.onResume(); }
            resetIdle();
        }
    }
    private void resetIdle() { handler.removeCallbacks(idleLock); if (unlocked) handler.postDelayed(idleLock, idleMinutes * 60_000L); }
    @Override public boolean dispatchTouchEvent(MotionEvent event) { resetIdle(); return super.dispatchTouchEvent(event); }
    private void lock() {
        unlocked = false;
        handler.removeCallbacks(idleLock);
        cancelSave();
        if (fileSelection != null) { fileSelection.onReceiveValue(null); fileSelection = null; }
        if (saveReply != null) { respond(saveReply, saveRequest, null, "アプリはロックされています。"); saveReply = null; }
        if (web != null) { web.stopLoading(); web.destroy(); web = null; }
        showStatus("アプリはロックされています。");
    }
    @Override protected void onStop() {
        super.onStop();
        if (saveReply != null || fileSelection != null) { if (web != null) { web.setVisibility(View.INVISIBLE); web.onPause(); } return; }
        if (unlocked) lock();
    }
    @Override protected void onDestroy() { handler.removeCallbacks(idleLock); cancelSave(); if (web != null) web.destroy(); super.onDestroy(); }
}
