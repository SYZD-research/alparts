package app.alparts.android;

import java.net.URI;

/** A deployment is an HTTPS origin, never an arbitrary document or credential URL. */
public final class ServerAddress {
    private ServerAddress() {}
    public static String normalize(String value) {
        if (value == null || value.length() > 2048) throw new IllegalArgumentException("INSECURE_SERVER_URL");
        URI uri = URI.create(value.trim());
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || !(uri.getRawPath().isEmpty() || uri.getRawPath().equals("/"))
                || uri.getPort() == 0 || uri.getPort() > 65535) {
            throw new IllegalArgumentException("INSECURE_SERVER_URL");
        }
        // Chromium omits the default port in both request URLs and bridge origins.
        int port = uri.getPort();
        return "https://" + uri.getHost().toLowerCase(java.util.Locale.ROOT)
            + (port == -1 || port == 443 ? "" : ":" + port);
    }
    public static boolean sameOrigin(String origin, String address) {
        try {
            URI uri = URI.create(address);
            return normalize(origin).equals(normalize(uri.getScheme() + "://" + uri.getRawAuthority()));
        } catch (RuntimeException ignored) { return false; }
    }
}
