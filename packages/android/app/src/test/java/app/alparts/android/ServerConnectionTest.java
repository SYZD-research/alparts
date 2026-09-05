package app.alparts.android;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLHandshakeException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class ServerConnectionTest {
    private ServerSocket server;
    private Thread worker;
    private volatile int status = 401;
    private volatile String contentType = "application/json; charset=utf-8";
    private volatile String allowedOrigin = "https://chat.example";
    private volatile IOException serverError;
    private final AtomicInteger redirects = new AtomicInteger();
    private volatile String method, origin, cookie, authorization, accept;

    @Before public void startServer() throws Exception {
        server = new ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"));
        worker = new Thread(() -> {
            while (!server.isClosed()) {
                try (Socket socket = server.accept()) {
                    socket.setSoTimeout(2_000);
                    BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                    String request = input.readLine();
                    method = request.split(" ")[0];
                    if (request.contains(" /redirect ")) redirects.incrementAndGet();
                    origin = cookie = authorization = accept = null;
                    String line;
                    while ((line = input.readLine()) != null && !line.isEmpty()) {
                        int separator = line.indexOf(':');
                        String name = line.substring(0, separator);
                        String value = line.substring(separator + 1).trim();
                        if (name.equalsIgnoreCase("Origin")) origin = value;
                        if (name.equalsIgnoreCase("Cookie")) cookie = value;
                        if (name.equalsIgnoreCase("Authorization")) authorization = value;
                        if (name.equalsIgnoreCase("Accept")) accept = value;
                    }
                    String response = "HTTP/1.1 " + status + " Test\r\nContent-Type: " + contentType + "\r\n"
                        + (allowedOrigin == null ? "" : "Access-Control-Allow-Origin: " + allowedOrigin + "\r\n")
                        + (status == 302 ? "Location: /redirect\r\n" : "")
                        + "Content-Length: 24\r\nConnection: close\r\n\r\n{\"error\":\"UNAUTHORIZED\"}";
                    socket.getOutputStream().write(response.getBytes(StandardCharsets.UTF_8));
                } catch (IOException error) {
                    if (!server.isClosed()) serverError = error;
                }
            }
        });
        worker.start();
    }

    @After public void stopServer() throws Exception {
        server.close();
        worker.join(3_000);
        assertFalse(worker.isAlive());
        assertNull(serverError);
    }

    private ServerConnection.Result check() {
        return ServerConnection.check("https://CHAT.example:443/", address -> {
            assertEquals("https://chat.example/api/auth/me", address);
            return (HttpURLConnection) URI.create("http://127.0.0.1:" + server.getLocalPort() + "/api/auth/me")
                .toURL().openConnection();
        });
    }

    @Test public void acceptsLiveLoginEndpointWithoutSendingAccountCredentials() {
        assertEquals(ServerConnection.Result.READY, check());
        assertEquals("GET", method);
        assertEquals("https://chat.example", origin);
        assertEquals("application/json", accept);
        assertNull(cookie);
        assertNull(authorization);
    }

    @Test public void detectsStoppedServerAndOverloadBeforeOpeningLogin() {
        for (int code : new int[]{500, 502, 503, 504, 429}) {
            status = code;
            assertEquals(ServerConnection.Result.SERVER_UNAVAILABLE, check());
        }
    }

    @Test public void rejectsWebsitesAndRedirectsWithoutFollowingThem() {
        status = 200;
        contentType = "text/html";
        assertEquals(ServerConnection.Result.NOT_ALPARTS, check());
        status = 401;
        assertEquals(ServerConnection.Result.NOT_ALPARTS, check());
        status = 404;
        contentType = "application/json";
        assertEquals(ServerConnection.Result.NOT_ALPARTS, check());
        status = 302;
        assertEquals(ServerConnection.Result.NOT_ALPARTS, check());
        assertEquals(0, redirects.get());
    }

    @Test public void detectsDeploymentThatWouldRejectLoginOrigin() {
        for (String value : new String[]{null, "*", "https://other.example"}) {
            allowedOrigin = value;
            assertEquals(ServerConnection.Result.NOT_ALLOWED, check());
        }
        status = 403;
        assertEquals(ServerConnection.Result.NOT_ALLOWED, check());
    }

    @Test public void failsClosedOnNetworkAndCertificateErrors() {
        assertEquals(ServerConnection.Result.UNAVAILABLE,
            ServerConnection.check("https://chat.example", address -> { throw new ConnectException(); }));
        assertEquals(ServerConnection.Result.UNSAFE,
            ServerConnection.check("https://chat.example", address -> { throw new SSLHandshakeException("untrusted"); }));
        assertThrows(IllegalArgumentException.class, () ->
            ServerConnection.check("http://chat.example", address -> { throw new AssertionError("Must not connect"); }));
    }
}
