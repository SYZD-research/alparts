package app.alparts.android;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import javax.net.ssl.SSLException;

/** An unauthenticated probe of the same endpoint used when the bundled client starts. */
final class ServerConnection {
    enum Result { READY, UNAVAILABLE, SERVER_UNAVAILABLE, NOT_ALPARTS, NOT_ALLOWED, UNSAFE }

    interface ConnectionFactory {
        HttpURLConnection open(String address) throws IOException;
    }

    static Result check(String origin) {
        return check(origin, address -> (HttpURLConnection) URI.create(address).toURL().openConnection());
    }

    static Result check(String origin, ConnectionFactory factory) {
        String normalized = ServerAddress.normalize(origin);
        HttpURLConnection connection = null;
        try {
            connection = factory.open(normalized + "/api/auth/me");
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(10_000);
            connection.setReadTimeout(10_000);
            connection.setInstanceFollowRedirects(false);
            connection.setUseCaches(false);
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Origin", normalized);
            int status = connection.getResponseCode();
            if (status >= 500 || status == 429) return Result.SERVER_UNAVAILABLE;
            if (status == 403) return Result.NOT_ALLOWED;
            // No cookies or account credentials are sent. A live Alparts auth
            // endpoint must ask for login, rather than return a website or redirect.
            String type = connection.getContentType();
            if (status != 401 || type == null
                    || !"application/json".equalsIgnoreCase(type.split(";", 2)[0].trim())) {
                return Result.NOT_ALPARTS;
            }
            // Same-origin fetches can read GET /me even when this deployment is
            // absent from CORS_ORIGINS; its subsequent login POST would be rejected.
            if (!normalized.equals(connection.getHeaderField("Access-Control-Allow-Origin"))) {
                return Result.NOT_ALLOWED;
            }
            return Result.READY;
        } catch (SSLException ignored) {
            return Result.UNSAFE;
        } catch (IOException ignored) {
            return Result.UNAVAILABLE;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private ServerConnection() {}
}
