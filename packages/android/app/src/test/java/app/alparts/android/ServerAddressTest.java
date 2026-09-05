package app.alparts.android;
import org.junit.Test;
import static org.junit.Assert.*;

public class ServerAddressTest {
    @Test public void acceptsOnlyDeploymentOrigins() {
        assertEquals("https://chat.example:8443", ServerAddress.normalize(" https://CHAT.example:8443/ "));
        for (String invalid : new String[]{"http://chat.example", "https://user:pass@chat.example", "https://chat.example/api", "https://chat.example?x", "https://chat.example#x", "file:///tmp/x", "https://chat.example:0"}) {
            assertThrows(IllegalArgumentException.class, () -> ServerAddress.normalize(invalid));
        }
        assertFalse(ServerAddress.sameOrigin("https://chat.example", "https://chat.example.attacker.test/api"));
        assertFalse(ServerAddress.sameOrigin("https://chat.example", "https://chat.example@attacker.test/api"));
        assertTrue(ServerAddress.sameOrigin("https://chat.example", "https://chat.example/api/me"));
    }

    @Test public void matchesChromiumDefaultPortAndCaseNormalization() {
        assertEquals("https://chat.example", ServerAddress.normalize("HTTPS://CHAT.example:443/"));
        assertTrue(ServerAddress.sameOrigin("https://chat.example:443", "https://chat.example/api/auth/login"));
        assertTrue(ServerAddress.sameOrigin("https://chat.example", "https://CHAT.example:443/api/auth/me"));
        assertEquals("https://[::1]", ServerAddress.normalize("https://[::1]:443"));
        assertFalse(ServerAddress.sameOrigin("https://chat.example", "https://chat.example:8443/api/auth/me"));
        assertFalse(ServerAddress.sameOrigin("https://chat.example", "http://chat.example:443/api/auth/me"));
        assertFalse(ServerAddress.sameOrigin("https://chat.example", "https://user@chat.example/api/auth/me"));
        assertThrows(IllegalArgumentException.class, () -> ServerAddress.normalize(null));
        assertThrows(IllegalArgumentException.class, () -> ServerAddress.normalize("https://" + "a".repeat(2048)));
    }
}
