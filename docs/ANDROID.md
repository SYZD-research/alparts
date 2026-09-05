# Android client

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

## Outstanding device validation and features

Run on physical devices before distribution: Keystore invalidation, reboot/lock,
background kill and outbox recovery, cookie expiry/revocation, file selection/save
cancel, huge attachments, malicious origins/subframes and accessibility/font scaling.
Automated Java unit tests cover origin validation; Android Lint and compilation do
not substitute for these runtime checks. No emulator acceleration is present in
the implementation environment.

On 2026-09-05, debug/release APK compilation, origin unit tests and Android Lint
passed. The debug APK's platform signature was checked with `apksigner verify`.
The bridge's 5 MiB attachment chunk was also tested for lossless splitting into
bounded native messages. These are build/unit checks, not a device E2E result.

Push/background sync, sharing *into* alparts from the OS share sheet, native voice
permission flow and an in-app deployment switch are not implemented. Use the same
server for this app installation. Clearing app data loses device-local keys and
unsent drafts; recover access through another device before doing so.

Platform references: [bundled WebView content](https://developer.android.com/develop/ui/views/layout/webapps/load-local-content),
[WebView security boundary](https://developer.android.com/develop/ui/views/layout/webapps/webview).
