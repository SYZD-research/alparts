# Android client

English | [日本語](ANDROID.ja.md)

The Android client shares the bundled React UI, cryptography, encrypted drafts/outbox,
history projector and attachment format with the desktop/Web client. This is a
development client, not completion of the Phase 2 security acceptance criteria.
iOS is outside this Linux implementation.

## Build

Requirements: JDK 21 **including javac**, Android SDK platform 35, build-tools 35.0.0,
platform-tools, Node/pnpm from the root package manifest. Set `JAVA_HOME` and
`ANDROID_HOME` to those installations, then run:

```sh
pnpm install --frozen-lockfile
pnpm android:build
```

The APK is `packages/android/app/build/outputs/apk/debug/app-debug.apk`.
Install with `adb install -r` using that path. The debug application ID is
`app.alparts.android.debug`; it is distinct from release `app.alparts.android`.
The first launch requires a configured device screen lock and an HTTPS deployment
origin. The backend must serve `/api` and `/socket.io` at that origin and include
it in `CORS_ORIGINS`. No cleartext or certificate-error bypass is provided.

The connection and lock screens use the shared client's dark palette and the
existing alpaca logo. The form scrolls when space is limited, keeps a bounded
card width on tablets, and respects the system bars and keyboard.

Before opening the bundled login screen, the app probes `/api/auth/me` without
account credentials. The expected response is `401` with a JSON content type
and an `Access-Control-Allow-Origin` matching the configured origin. This also
detects deployments missing from `CORS_ORIGINS`, whose login POST would otherwise
be rejected. Redirects are not followed, and a failed probe does not save a new
address. Failed connections can be retried or the address corrected; existing
keys and drafts remain associated with their original deployment.

### Troubleshooting login

The HTML is bundled in the APK, so older versions could show a normal login form
even while the deployment returned `502` because its backend or frontend proxy
was stopped. Check the deployment's `/api/auth/me` response and restart its
existing services before investigating account credentials. An unauthenticated
`401` is expected; it must not show a session-expired message on a new install.

HTTPS origins are now normalized the same way as WebView: `:443` is omitted and
scheme/hostname case is ignored. Previously an explicitly entered default port
could make the app reject its own requests and bridge messages. Non-default
ports remain distinct. Network failures, unavailable services and rejected
origins have separate plain-language messages; credentials are not logged.

`packages/android/gradlew -p packages/android assembleRelease` builds an unsigned
release APK. Android's package manager verifies APK signatures when installing
updates and requires the same signing identity. Release signing credentials must
be provided by the release operator; debug signing is not a production identity.

Gradle wrapper version and distribution checksum are pinned. Dependency checksums
are in `gradle/verification-metadata.xml`; review that file when updating dependencies.
`runtimeInventory` exports the resolved Android runtime components for the combined SBOM.

## Native boundary

- Only APK assets supply HTML/JavaScript. API responses are data; navigation cannot
  load a remote document into the privileged WebView. External links use the browser.
- The message bridge checks the exact origin **and main-frame flag**. There is no
  unrestricted `addJavascriptInterface` bridge. Frames, remote scripts and workers
  are prohibited by the local response CSP.
- AES-GCM wrapping uses a non-exportable Android Keystore key with the deployment
  origin and value name authenticated as associated data. Android backup and
  device transfer exclude app storage. Device keys still inherit the prototype's
  group-protocol limitations; this does not implement MLS or key transparency.
- OS credential confirmation gates WebView creation. Backgrounding and idle expiry
  destroy the WebView to discard in-memory plaintext. The system file picker is a
  bounded exception: the hidden/paused view remains until selection or idle lock.
- Screenshots and task-switcher previews are disabled using `FLAG_SECURE`. This
  does not prevent external photography or extraction from a compromised device.
- Attachments use the OS document chooser and bounded, sequential writes. A partial
  destination is deleted on cancellation where the document provider allows it.
- Voice capture requests are limited to audio from the configured origin while
  the app is unlocked and active. The first request asks for Android microphone
  permission; a denial can be retried and repeated denial offers app settings.
  OS results are held until resume and cannot grant a canceled or locked request.
  Incoming call audio can play without a separate media-element tap.

## Language

The app is available in English and Japanese. The native screens (connection,
unlock, and the microphone and file dialogs) follow the device's language:
Japanese when the device is set to Japanese, English otherwise. The bundled
screens start in the same language and can be switched with the 🌐 button in the
sidebar or on the sign-in screen; that choice is saved in the app.

## Touch navigation

On narrow screens, swipe right across the conversation to open workspaces and
channels. Select a text channel, swipe the list left, or tap the conversation
edge to return. The bottom navigation bar has been removed. The users icon
immediately left of search toggles members; Escape also closes the list.
Alt+Right and Alt+Left provide keyboard navigation between channels and chat.

Swipe a message left and release after 64 CSS pixels to reply. For your own
message, releasing after 136 pixels edits instead. The current action is shown
while dragging; returning below the threshold cancels it. Vertical movement,
multiple touches, canceled gestures and interactive controls do not trigger an
action. Reply/edit focuses the composer. Drafts and scroll positions survive
opening the channel drawer; hidden conversations do not advance read positions.

## Outstanding device validation and features

Run on physical devices before distribution: Keystore invalidation, reboot/lock,
background kill and outbox recovery, cookie expiry/revocation, file selection/save
cancel, huge attachments, malicious origins/subframes and accessibility/font scaling.
Automated Java unit tests cover origin validation and the connection probe,
including unavailable servers, rejected origins, redirects and certificate
errors. Android Lint and compilation do not substitute for these runtime checks.

On 2026-09-05, debug/release APK compilation, origin unit tests and Android Lint
passed. Connection-probe regression tests and the client authentication/error
tests also passed. The debug APK's platform signature was checked with `apksigner verify`.
The bridge's 5 MiB attachment chunk was also tested for lossless splitting into
bounded native messages. An Android 15 emulator with WebView 124 was used to
check device-credential unlock, the connection screen, unavailable-network
recovery, and navigation to the bundled login screen through the deployment's
HTTPS endpoint (including an explicitly entered `:443`). These checks do not
establish successful sign-in with a real account or complete the physical-device
acceptance checks above. The final APK was also checked at a phone-sized
1080 × 1920 viewport: login opens without a spurious session-expired message.
An invalid test account received the expected credentials error from the live
server. The emulator used a host CONNECT proxy to reach the private deployment;
certificate verification remained enabled.

On 2026-09-06, an Android 15 emulator showed the microphone permission prompt from
the bundled WebView. Denial, retry/rationale, repeated-denial settings guidance,
and granting a live, enabled audio track were checked using a temporary
instrumentation harness. The harness did not enable WebView debugging or change
the application's security settings. Moving Home during capture ended the
recording app operation, destroyed the WebView and required device authentication
on return. Check two-way audio with another participant, screen-off behavior and
file selection during a call on physical devices before distribution.

The integrated debug build, 13 Android JVM tests, 136 client tests, Android Lint
and lint for the changed client components passed. Chromium touch-input checks
covered reply/edit thresholds, cancellation, nested navigation, vertical scroll,
draft preservation, hidden-chat read positions, member toggling and modal
backdrops. Layout was checked at 320/390 CSS pixels and desktop width. Temporary
fixtures and instrumentation were kept outside the shipped application.

Push/background sync, sharing *into* alparts from the OS share sheet and an
in-app deployment switch are not implemented. Use the same
server for this app installation. Clearing app data loses device-local keys and
unsent drafts; recover access through another device before doing so.

Platform references: [bundled WebView content](https://developer.android.com/develop/ui/views/layout/webapps/load-local-content),
[WebView security boundary](https://developer.android.com/develop/ui/views/layout/webapps/webview).
