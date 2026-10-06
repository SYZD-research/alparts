package app.alparts.android;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.webkit.CookieManager;
import android.webkit.PermissionRequest;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebChromeClient;
import android.webkit.ValueCallback;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.TextView;
import android.widget.Toast;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

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
    private final ExecutorService connections = Executors.newSingleThreadExecutor();
    private Future<?> connectionCheck;
    private int connectionGeneration;
    private static final int MICROPHONE_REQUEST = 30;
    private final MicrophonePermission<PermissionRequest> microphone = new MicrophonePermission<>();
    private WebView microphoneWeb;
    private AlertDialog microphoneDialog;
    private boolean resumed;
    private boolean microphoneDeniedPermanently;
    private boolean microphoneRequestCanceled;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        if (android.os.Build.VERSION.SDK_INT >= 31) getWindow().setHideOverlayWindows(true);
        try { vault = new SecretVault(this); }
        catch (Exception ignored) { showStatus(getString(R.string.status_storage_unavailable)); return; }
        origin = getPreferences(MODE_PRIVATE).getString("server", null);
        try { if (origin != null) origin = ServerAddress.normalize(origin); }
        catch (RuntimeException ignored) { showStatus(getString(R.string.status_saved_server_unreadable)); return; }
        idleMinutes = getPreferences(MODE_PRIVATE).getInt("idleMinutes", 5);
        unlock();
    }

    private void showStatus(String message) {
        View layout = nativeScreen();
        ((TextView) layout.findViewById(R.id.setup_title)).setText(R.string.app_name);
        ((TextView) layout.findViewById(R.id.setup_description)).setText(message);
        layout.findViewById(R.id.connection_fields).setVisibility(View.GONE);
        Button retry = layout.findViewById(R.id.setup_action);
        retry.setText(R.string.unlock);
        retry.setOnClickListener(view -> unlock());
        if (vault == null) retry.setVisibility(View.GONE);
    }

    private View nativeScreen() {
        ViewGroup content = findViewById(android.R.id.content);
        View layout = getLayoutInflater().inflate(R.layout.native_screen, content, false);
        layout.setFilterTouchesWhenObscured(true);
        View card = layout.findViewById(R.id.setup_card);
        int gutter = Math.round(48 * getResources().getDisplayMetrics().density);
        int maxWidth = Math.round(448 * getResources().getDisplayMetrics().density);
        layout.addOnLayoutChangeListener((view, left, top, right, bottom, oldLeft, oldTop, oldRight, oldBottom) -> {
            int width = Math.min(maxWidth, right - left - view.getPaddingLeft() - view.getPaddingRight() - gutter);
            if (width > 0 && card.getLayoutParams().width != width) {
                card.getLayoutParams().width = width;
                card.requestLayout();
            }
        });
        setContentView(layout);
        return layout;
    }

    private void unlock() {
        if (authenticating || vault == null) return;
        KeyguardManager manager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        if (!manager.isDeviceSecure()) {
            showStatus(getString(R.string.status_screen_lock_required));
            return;
        }
        Intent intent = manager.createConfirmDeviceCredentialIntent("alparts", getString(R.string.unlock_prompt));
        if (intent == null) return;
        authenticating = true;
        startActivityForResult(intent, 10);
    }

    private void connectionSetup() {
        View layout = nativeScreen();
        EditText address = layout.findViewById(R.id.server_address);
        Button connect = layout.findViewById(R.id.setup_action);
        TextView error = layout.findViewById(R.id.setup_error);
        if (origin != null) {
            address.setText(origin);
            address.setEnabled(false);
        }
        connect.setOnClickListener(view -> connectToServer(address, connect, error));
        address.setOnEditorActionListener((view, action, event) -> {
            if (action != EditorInfo.IME_ACTION_GO) return false;
            connect.performClick();
            return true;
        });
        if (origin != null) connect.performClick();
        resetIdle();
    }

    private void connectToServer(EditText address, Button connect, TextView error) {
        if (!unlocked || !connect.isEnabled()) return;
        String candidate;
        try { candidate = ServerAddress.normalize(address.getText().toString()); }
        catch (RuntimeException ignored) {
            error.setText(R.string.connection_invalid);
            error.setVisibility(View.VISIBLE);
            address.requestFocus();
            return;
        }
        if (!BuildConfig.DEBUG && !java.util.Arrays.asList(getResources().getStringArray(R.array.pinned_hosts))
                .contains(Uri.parse(candidate).getHost())) {
            error.setText(R.string.connection_invalid);
            error.setVisibility(View.VISIBLE);
            return;
        }
        error.setVisibility(View.GONE);
        address.setEnabled(false);
        connect.setEnabled(false);
        connect.setAlpha(0.6f);
        connect.setText(R.string.connecting);
        InputMethodManager keyboard = (InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
        keyboard.hideSoftInputFromWindow(address.getWindowToken(), 0);
        int generation = ++connectionGeneration;
        connectionCheck = connections.submit(() -> {
            ServerConnection.Result result = ServerConnection.check(candidate);
            handler.post(() -> {
                if (!unlocked || generation != connectionGeneration || isDestroyed()) return;
                connectionCheck = null;
                if (result == ServerConnection.Result.READY) {
                    if (getPreferences(MODE_PRIVATE).edit().putString("server", candidate).commit()) {
                        origin = candidate;
                        openWebClient();
                        return;
                    }
                    error.setText(R.string.connection_save_failed);
                } else {
                    // Diagnostics stay in logs, never in the connection form.
                    android.util.Log.w("AlpartsConnection", "Connection probe failed: " + result.name());
                    error.setText(connectionError(result));
                }
                error.setVisibility(View.VISIBLE);
                // Allow repair of an address saved by an older app before its
                // first successful connection. Existing data stays scoped to
                // its original origin; changing this field never deletes it.
                address.setEnabled(true);
                connect.setEnabled(true);
                connect.setAlpha(1f);
                connect.setText(R.string.connect);
            });
        });
    }

    private int connectionError(ServerConnection.Result result) {
        switch (result) {
            case SERVER_UNAVAILABLE: return R.string.connection_server_unavailable;
            case NOT_ALPARTS: return R.string.connection_not_alparts;
            case NOT_ALLOWED: return R.string.connection_not_allowed;
            case UNSAFE: return R.string.connection_unsafe;
            default: return R.string.connection_unavailable;
        }
    }

    private void openClient() {
        if (unlocked) connectionSetup();
    }

    @android.annotation.SuppressLint("SetJavaScriptEnabled") // Only APK code runs; exact-origin, main-frame bridge and CSP are enforced below.
    private void openWebClient() {
        if (!unlocked) return;
        if (origin == null) { connectionSetup(); return; }
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            showStatus(getString(R.string.status_webview_update)); return;
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
        // Participants' streams arrive asynchronously, after the join button's user gesture.
        settings.setMediaPlaybackRequiresUserGesture(false);
        CookieManager.getInstance().setAcceptCookie(true);
        CookieManager.getInstance().setAcceptThirdPartyCookies(web, false);
        WebView client = web;
        web.setWebChromeClient(new WebChromeClient() {
            @Override public void onPermissionRequest(PermissionRequest request) {
                requestMicrophone(client, request);
            }
            @Override public void onPermissionRequestCanceled(PermissionRequest request) {
                if (microphone.isPending(request)) clearMicrophoneRequest(false);
            }
            @Override public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if (!unlocked || fileSelection != null || saveReply != null || microphone.hasPending()) return false;
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
                        "Content-Security-Policy", "default-src 'none'; script-src " + origin + "/assets/ " + origin + "/android-bridge.js; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self' " + origin.replace("https:", "wss:") + "; frame-src 'none'; worker-src " + origin + "/assets/; base-uri 'none'; form-action 'none'",
                        "Permissions-Policy", "camera=(), display-capture=(), geolocation=(), microphone=(self), speaker-selection=(self)",
                        "Referrer-Policy", "no-referrer"), input);
                } catch (Exception ignored) { return blocked(); }
            }
        });
        FrameLayout container = new FrameLayout(this);
        container.setFilterTouchesWhenObscured(true);
        web.setFilterTouchesWhenObscured(true);
        container.setFitsSystemWindows(true);
        container.setBackgroundColor(getColor(R.color.alparts_background));
        web.setBackgroundColor(getColor(R.color.alparts_background));
        container.addView(web, new FrameLayout.LayoutParams(-1, -1));
        setContentView(container);
        web.loadUrl(origin + "/");
        resetIdle();
    }

    private boolean microphoneGranted() {
        return checkSelfPermission(Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED;
    }

    private boolean canUseMicrophone(WebView client) {
        KeyguardManager keyguard = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        PowerManager power = (PowerManager) getSystemService(POWER_SERVICE);
        return resumed && unlocked && !isFinishing() && !isDestroyed() && client != null && client == web
            && fileSelection == null && saveReply == null && !keyguard.isKeyguardLocked() && power.isInteractive()
            && ServerAddress.sameOrigin(origin, client.getUrl());
    }

    private void requestMicrophone(WebView client, PermissionRequest request) {
        MicrophonePermission.Decision decision = microphone.begin(request, origin,
            request.getOrigin().toString(), request.getResources(), canUseMicrophone(client), microphoneGranted());
        if (decision == MicrophonePermission.Decision.DENY) { request.deny(); return; }
        if (decision == MicrophonePermission.Decision.GRANT) {
            request.grant(new String[]{PermissionRequest.RESOURCE_AUDIO_CAPTURE});
            return;
        }
        dismissMicrophoneDialog();
        microphoneWeb = client;
        microphoneDeniedPermanently = false;
        microphoneRequestCanceled = false;
        if (shouldShowRequestPermissionRationale(Manifest.permission.RECORD_AUDIO)) {
            microphoneDialog = new AlertDialog.Builder(this)
                .setMessage(getString(R.string.microphone_rationale))
                .setPositiveButton(getString(R.string.action_continue), (dialog, which) -> {
                    microphoneDialog = null;
                    launchMicrophonePermission();
                })
                .setNegativeButton(getString(R.string.action_cancel), (dialog, which) -> clearMicrophoneRequest(true))
                .setOnCancelListener(dialog -> clearMicrophoneRequest(true)).show();
            protectDialog(microphoneDialog);
        } else launchMicrophonePermission();
    }

    private void launchMicrophonePermission() {
        if (!canUseMicrophone(microphoneWeb)) { clearMicrophoneRequest(true); return; }
        if (!microphone.startRuntimeRequest()) return;
        resetIdle();
        try { requestPermissions(new String[]{Manifest.permission.RECORD_AUDIO}, MICROPHONE_REQUEST); }
        catch (RuntimeException ignored) {
            microphone.runtimeResult(false);
            finishMicrophonePermission();
        }
    }

    @Override public void onRequestPermissionsResult(int request, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(request, permissions, results);
        if (request != MICROPHONE_REQUEST) return;
        boolean validResult = permissions.length == 1 && results.length == 1
            && Manifest.permission.RECORD_AUDIO.equals(permissions[0]);
        boolean granted = validResult && results[0] == PackageManager.PERMISSION_GRANTED && microphoneGranted();
        microphoneRequestCanceled = !validResult;
        microphoneDeniedPermanently = validResult && !granted
            && !shouldShowRequestPermissionRationale(Manifest.permission.RECORD_AUDIO);
        microphone.runtimeResult(granted);
        // Android can deliver this result before onResume. Keep the web request alive
        // through the permission dialog, and grant only once the app is active again.
        finishMicrophonePermission();
    }

    private void finishMicrophonePermission() {
        boolean ready = canUseMicrophone(microphoneWeb);
        MicrophonePermission.Resolution<PermissionRequest> resolution = microphone.resolve(
            resumed, ready && microphoneGranted(), origin);
        if (resolution == null) return;
        microphoneWeb = null;
        if (resolution.granted()) {
            resolution.request().grant(new String[]{PermissionRequest.RESOURCE_AUDIO_CAPTURE});
            resetIdle();
        } else {
            resolution.request().deny();
            if (!ready || microphoneRequestCanceled) return;
            if (microphoneDeniedPermanently) {
                microphoneDialog = new AlertDialog.Builder(this)
                    .setMessage(getString(R.string.microphone_blocked))
                    .setPositiveButton(getString(R.string.action_open_settings), (dialog, which) -> {
                        microphoneDialog = null;
                        try { startActivity(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                            Uri.parse("package:" + getPackageName()))); }
                        catch (RuntimeException ignored) {
                            Toast.makeText(this, getString(R.string.microphone_settings_hint), Toast.LENGTH_LONG).show();
                        }
                    })
                    .setNegativeButton(getString(R.string.action_not_now), (dialog, which) -> microphoneDialog = null)
                    .setOnCancelListener(dialog -> microphoneDialog = null).show();
                protectDialog(microphoneDialog);
            } else {
                Toast.makeText(this, getString(R.string.microphone_denied), Toast.LENGTH_LONG).show();
            }
        }
    }

    private void dismissMicrophoneDialog() {
        if (microphoneDialog != null) { microphoneDialog.dismiss(); microphoneDialog = null; }
    }

    private void clearMicrophoneRequest(boolean deny) {
        PermissionRequest pending = microphone.clear();
        microphoneWeb = null;
        dismissMicrophoneDialog();
        if (deny && pending != null) pending.deny();
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
                    if (saveReply != null || saveStream != null || microphone.hasPending()) throw new IllegalStateException();
                    expectedBytes = args.getLong("expectedBytes");
                    if (expectedBytes < 0 || expectedBytes > 100L * 1024 * 1024) throw new IllegalArgumentException();
                    // Match the desktop rules: NFKC, then replace separators, controls and
                    // format/bidi characters so the save dialog shows the real name.
                    String name = java.text.Normalizer.normalize(args.getString("name"), java.text.Normalizer.Form.NFKC)
                        .replaceAll("[\\\\/:*?\"<>|\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}]", "_")
                        .replaceAll("[. ]+$", "").trim();
                    if (name.isEmpty() || name.length() > 240) throw new IllegalArgumentException();
                    saveReply = reply; saveRequest = id;
                    if (args.optBoolean("dangerous") || name.toLowerCase(java.util.Locale.ROOT).matches(".*\\.(apk|exe|msi|bat|cmd|ps1|sh|html?|svg|js|jar)$")) {
                        protectDialog(new android.app.AlertDialog.Builder(this)
                            .setMessage(getString(R.string.dangerous_file_warning))
                            .setPositiveButton(getString(R.string.action_save), (dialog, which) -> launchSave(name))
                            .setNegativeButton(getString(R.string.action_cancel), (dialog, which) -> cancelSaveDialog())
                            .setOnCancelListener(dialog -> cancelSaveDialog()).show());
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
        } catch (Exception ignored) { respond(reply, id, null, getString(R.string.error_operation_failed)); }
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
            else showStatus(getString(R.string.status_locked));
        } else if (request == 20 && saveReply != null) {
            try {
                if (result == RESULT_OK && data != null && data.getData() != null) {
                    saveUri = data.getData();
                    saveStream = getContentResolver().openOutputStream(saveUri, "wt");
                    if (saveStream == null) throw new IllegalStateException();
                    saveToken = UUID.randomUUID().toString(); writtenBytes = 0;
                }
                respond(saveReply, saveRequest, saveToken, null);
            } catch (Exception ignored) { cancelSave(); respond(saveReply, saveRequest, null, getString(R.string.error_save_failed)); }
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
    private void protectDialog(AlertDialog dialog) {
        if (dialog.getWindow() == null) return;
        dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        dialog.getWindow().getDecorView().setFilterTouchesWhenObscured(true);
        if (android.os.Build.VERSION.SDK_INT >= 31) dialog.getWindow().setHideOverlayWindows(true);
    }

    @Override public boolean dispatchTouchEvent(MotionEvent event) {
        int obscured = MotionEvent.FLAG_WINDOW_IS_OBSCURED;
        if (android.os.Build.VERSION.SDK_INT >= 29) obscured |= MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED;
        if ((event.getFlags() & obscured) != 0) return false;
        resetIdle();
        return super.dispatchTouchEvent(event);
    }
    private void lock() {
        unlocked = false;
        clearMicrophoneRequest(true);
        connectionGeneration++;
        if (connectionCheck != null) { connectionCheck.cancel(true); connectionCheck = null; }
        handler.removeCallbacks(idleLock);
        cancelSave();
        if (fileSelection != null) { fileSelection.onReceiveValue(null); fileSelection = null; }
        if (saveReply != null) { respond(saveReply, saveRequest, null, getString(R.string.status_locked)); saveReply = null; }
        if (web != null) { web.stopLoading(); web.destroy(); web = null; }
        showStatus(getString(R.string.status_locked));
    }
    @Override protected void onStop() {
        super.onStop();
        // A permission dialog only pauses the activity. A real stop still cancels
        // microphone access and locks, even if an OS permission result is pending.
        clearMicrophoneRequest(true);
        if (saveReply != null || fileSelection != null) { if (web != null) { web.setVisibility(View.INVISIBLE); web.onPause(); } return; }
        if (unlocked) lock();
    }
    @Override protected void onResume() {
        super.onResume();
        resumed = true;
        finishMicrophonePermission();
    }
    @Override protected void onPause() {
        resumed = false;
        super.onPause();
    }
    @Override protected void onDestroy() {
        clearMicrophoneRequest(true);
        connectionGeneration++;
        connections.shutdownNow();
        handler.removeCallbacks(idleLock);
        cancelSave();
        if (web != null) web.destroy();
        super.onDestroy();
    }
}
