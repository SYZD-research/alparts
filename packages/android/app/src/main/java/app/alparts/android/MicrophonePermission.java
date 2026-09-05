package app.alparts.android;

/** Keeps a web request attached to its own runtime result, including across pause/resume. */
final class MicrophonePermission<T> {
    static final String AUDIO_CAPTURE = "android.webkit.resource.AUDIO_CAPTURE";
    enum Decision { DENY, GRANT, REQUEST }
    record Resolution<T>(T request, boolean granted) {}

    private T pending;
    private String pendingOrigin;
    private boolean runtimeInFlight;
    private Boolean result;

    Decision begin(T request, String trustedOrigin, String requestOrigin, String[] resources,
            boolean foreground, boolean microphoneGranted) {
        if (request == null || !foreground || pending != null || runtimeInFlight
                || !sameOrigin(trustedOrigin, requestOrigin)
                || resources == null || resources.length != 1 || !AUDIO_CAPTURE.equals(resources[0])) {
            return Decision.DENY;
        }
        if (microphoneGranted) return Decision.GRANT;
        pending = request;
        pendingOrigin = requestOrigin;
        return Decision.REQUEST;
    }

    boolean startRuntimeRequest() {
        if (pending == null || runtimeInFlight) return false;
        runtimeInFlight = true;
        return true;
    }

    void runtimeResult(boolean granted) {
        if (!runtimeInFlight) return;
        runtimeInFlight = false;
        if (pending != null) result = granted;
    }

    Resolution<T> resolve(boolean foreground, boolean microphoneGranted, String trustedOrigin) {
        if (!foreground || pending == null || result == null) return null;
        boolean grant = result && microphoneGranted && sameOrigin(trustedOrigin, pendingOrigin);
        return new Resolution<>(clear(), grant);
    }

    boolean isPending(T request) { return pending == request; }
    boolean hasPending() { return pending != null; }

    T clear() {
        T request = pending;
        pending = null;
        pendingOrigin = null;
        result = null;
        // A canceled web request cannot pass its outstanding OS result to a new request.
        // Keep this barrier until that runtime callback arrives.
        return request;
    }

    private static boolean sameOrigin(String trusted, String requested) {
        try { return ServerAddress.normalize(trusted).equals(ServerAddress.normalize(requested)); }
        catch (RuntimeException ignored) { return false; }
    }
}
