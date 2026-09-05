package app.alparts.android;

import org.junit.Test;
import static org.junit.Assert.*;

public class MicrophonePermissionTest {
    private static final String ORIGIN = "https://chat.example";
    private static final String[] AUDIO = { MicrophonePermission.AUDIO_CAPTURE };

    @Test public void grantsOnlyAudioFromTheExactTrustedOriginInTheForeground() {
        MicrophonePermission<Object> permission = new MicrophonePermission<>();
        assertEquals(MicrophonePermission.Decision.GRANT,
            permission.begin(new Object(), ORIGIN, "https://CHAT.example:443/", AUDIO, true, true));
        for (String address : new String[]{"https://chat.example.attacker.test", "https://chat.example:8443",
                "http://chat.example", "https://user@chat.example", "https://chat.example/page", "null", null}) {
            assertEquals(MicrophonePermission.Decision.DENY,
                permission.begin(new Object(), ORIGIN, address, AUDIO, true, true));
        }
        for (String[] resources : new String[][]{null, {}, {"android.webkit.resource.VIDEO_CAPTURE"},
                {MicrophonePermission.AUDIO_CAPTURE, "android.webkit.resource.VIDEO_CAPTURE"},
                {MicrophonePermission.AUDIO_CAPTURE, "future-resource"}}) {
            assertEquals(MicrophonePermission.Decision.DENY,
                permission.begin(new Object(), ORIGIN, ORIGIN, resources, true, true));
        }
        assertEquals(MicrophonePermission.Decision.DENY,
            permission.begin(new Object(), ORIGIN, ORIGIN, AUDIO, false, true));
    }

    @Test public void waitsForAndroidGrantAndResumeBeforeCompletingTheOriginalWebRequest() {
        MicrophonePermission<Object> permission = new MicrophonePermission<>();
        Object request = new Object();
        assertEquals(MicrophonePermission.Decision.REQUEST,
            permission.begin(request, ORIGIN, ORIGIN, AUDIO, true, false));
        assertTrue(permission.startRuntimeRequest());
        assertNull(permission.resolve(true, false, ORIGIN));
        permission.runtimeResult(true);
        assertNull(permission.resolve(false, true, ORIGIN));
        assertTrue(permission.isPending(request));
        MicrophonePermission.Resolution<Object> resolution = permission.resolve(true, true, ORIGIN);
        assertSame(request, resolution.request());
        assertTrue(resolution.granted());
        assertFalse(permission.hasPending());
        assertNull(permission.resolve(true, true, ORIGIN));
    }

    @Test public void denialAllowsAUserInitiatedRetry() {
        MicrophonePermission<Object> permission = new MicrophonePermission<>();
        Object first = new Object();
        permission.begin(first, ORIGIN, ORIGIN, AUDIO, true, false);
        permission.startRuntimeRequest();
        permission.runtimeResult(false);
        MicrophonePermission.Resolution<Object> denial = permission.resolve(true, false, ORIGIN);
        assertSame(first, denial.request());
        assertFalse(denial.granted());
        Object retry = new Object();
        assertEquals(MicrophonePermission.Decision.REQUEST,
            permission.begin(retry, ORIGIN, ORIGIN, AUDIO, true, false));
        assertTrue(permission.startRuntimeRequest());
        permission.runtimeResult(true);
        assertTrue(permission.resolve(true, true, ORIGIN).granted());
    }

    @Test public void canceledOrLockedRequestsCannotGrantLaterOrReplaceAnotherRequest() {
        MicrophonePermission<Object> permission = new MicrophonePermission<>();
        Object canceled = new Object();
        permission.begin(canceled, ORIGIN, ORIGIN, AUDIO, true, false);
        permission.startRuntimeRequest();
        assertSame(canceled, permission.clear());
        assertEquals(MicrophonePermission.Decision.DENY,
            permission.begin(new Object(), ORIGIN, ORIGIN, AUDIO, true, true));
        permission.runtimeResult(true);
        assertNull(permission.resolve(true, true, ORIGIN));
        assertEquals(MicrophonePermission.Decision.REQUEST,
            permission.begin(new Object(), ORIGIN, ORIGIN, AUDIO, true, false));
        // An unsolicited/duplicate runtime callback must not settle the new request.
        permission.runtimeResult(true);
        assertNull(permission.resolve(true, true, ORIGIN));
    }

    @Test public void rechecksNativePermissionAndOriginWhenTheActivityResumes() {
        for (boolean stillGranted : new boolean[]{false, true}) {
            MicrophonePermission<Object> permission = new MicrophonePermission<>();
            permission.begin(new Object(), ORIGIN, ORIGIN, AUDIO, true, false);
            permission.startRuntimeRequest();
            permission.runtimeResult(true);
            assertFalse(permission.resolve(true, stillGranted,
                stillGranted ? "https://other.example" : ORIGIN).granted());
        }
    }

    @Test public void concurrentWebRequestsDoNotReplaceThePendingRequest() {
        MicrophonePermission<Object> permission = new MicrophonePermission<>();
        Object first = new Object();
        permission.begin(first, ORIGIN, ORIGIN, AUDIO, true, false);
        assertEquals(MicrophonePermission.Decision.DENY,
            permission.begin(new Object(), ORIGIN, ORIGIN, AUDIO, true, false));
        assertTrue(permission.isPending(first));
        assertSame(first, permission.clear());
        assertFalse(permission.startRuntimeRequest());
    }
}
