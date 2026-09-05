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
}
