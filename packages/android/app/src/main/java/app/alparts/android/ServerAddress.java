package app.alparts.android;

import java.net.URI;

/** A deployment is an HTTPS origin, never an arbitrary document or credential URL. */
public final class ServerAddress {
    private ServerAddress() {}
    public static String normalize(String value) {
        URI uri = URI.create(value.trim());
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null
                || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || !(uri.getRawPath().isEmpty() || uri.getRawPath().equals("/"))
                || uri.getPort() == 0 || uri.getPort() > 65535) {
            throw new IllegalArgumentException("INSECURE_SERVER_URL");
        }
        return "https://" + uri.getRawAuthority().toLowerCase(java.util.Locale.ROOT);
    }
    public static boolean sameOrigin(String origin, String address) {
        try {
            URI uri = URI.create(address);
            return origin.equals(normalize(uri.getScheme() + "://" + uri.getRawAuthority()));
        } catch (RuntimeException ignored) { return false; }
    }
}
