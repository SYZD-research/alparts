# Desktop client

English | [日本語](DESKTOP.ja.md)

Last verified: 2026-09-04.

The Electron client in `packages/desktop` packages the same Phase 1 client for Windows, macOS, and Linux. The application UI is bundled into the installer. Only API and real-time requests are sent to the deployment selected by the user or operator; JavaScript from that deployment is not loaded into the privileged desktop shell.

## Supported packages

| Platform | Architectures | Output |
| --- | --- | --- |
| Windows | x64, ARM64 | assisted NSIS installer |
| macOS 13 or later | x64, ARM64 | DMG and ZIP |
| Linux | x64, ARM64 | AppImage and Debian package |

Native packages are built on their matching operating system by `.github/workflows/desktop.yml`. The unpacked Linux x64 package is also suitable for a local smoke test.

## Development

Start the normal development deployment first. In another terminal, build the bundled UI and open Electron:

```bash
./dev.sh
pnpm dev:desktop
```

On first launch, enter `http://localhost:5173`. The development proxy forwards API and real-time requests to the local server while the desktop app continues to use its bundled UI. Plain HTTP is accepted only for loopback development; every non-loopback deployment must use HTTPS. For a managed installation, set an exact origin before starting the application:

```bash
ALPARTS_SERVER_URL=https://chat.example.com pnpm dev:desktop
```

`ALPARTS_DESKTOP_DEV_URL` is a development-only, loopback-only override for a separately running Vite UI. Packaged builds ignore it.

## Build and package

```bash
pnpm desktop:pack
pnpm desktop:dist:windows
pnpm desktop:dist:macos
pnpm desktop:dist:linux
```

`desktop:pack` creates an unpacked package for the current platform. Distribution artifacts are written to `packages/desktop/release`.

The repository can create unsigned development artifacts. A public release must be built on a controlled native runner with the organization’s Windows Authenticode or Apple Developer ID credentials. Signed update delivery, downgrade prevention, notarization policy, and release-key custody remain Phase 2 release gates; an unsigned developer artifact is not a production release.

## Security boundary

- Renderer processes have Chromium sandboxing, context isolation, and no Node.js, shell, webview, or raw filesystem access.
- The preload exposes only bounded settings, lock, protected-secret, and streamed-save operations, plus a notice of the display language. Every call is restricted to the main top-level bundled frame.
- Production pages keep the configured deployment’s origin for secure cookies and Socket.IO, while the response body for UI routes comes from the packaged renderer assets.
- API and real-time routes are data-only: they cannot be loaded as a script, style, frame, or top-level page, and redirects cannot bypass the protocol boundary.
- CSP blocks remote scripts, frames, objects, workers, and cross-origin network requests. External web links are opened by the operating system.
- Electron fuses disable `ELECTRON_RUN_AS_NODE`, Node options, CLI inspection, file-protocol privileges, and loading application code outside ASAR. Cookie encryption is enabled.
- A deployment change clears that origin’s cookies/storage and its protected desktop vault namespace before loading the new deployment.
- Device private keys and local-state keys are wrapped by Electron `safeStorage`: DPAPI on Windows, Keychain on macOS, and a Secret Service implementation on Linux. The app refuses to start when only unprotected Linux fallback storage is available.
- OS lock, suspend, the configured idle interval, or **Lock now** clears decrypted client state and requires the account password before reopening it. The main process keeps the lock state across renderer reloads.
- Attachments are decrypted in 5 MiB chunks into an opaque native save handle. Partial files are removed on failure or cancellation. Every saved file receives Windows zone information or macOS quarantine metadata, whatever its type, as browsers do; Linux files are saved without execute permission. Risky types additionally need a confirmation in the UI.

The desktop client does not expose diagnostic details in normal UI messages. Development logs and tests hold implementation-level failure information.

## Language

The app is available in English and Japanese. It starts in the operating system's language (English unless that is Japanese), and the language can be changed on the server setup screen or with the 🌐 button in the sidebar. The application menu and native dialogs, such as the save dialog, follow the language chosen in the app.

## Verification

```bash
pnpm --filter @alparts/desktop typecheck
pnpm --filter @alparts/desktop test
pnpm --filter @alparts/client test
pnpm desktop:pack
packages/desktop/node_modules/.bin/electron-fuses read \
  --app packages/desktop/release/linux-unpacked/alparts
```

Desktop unit tests cover URL/origin restrictions, bundle path traversal, vault persistence/rotation/deletion, settings validation, attachment streaming, size bounds, cancellation cleanup, marking of every saved file, and switching the display language. Native installer execution, signing, and OS key-store behavior must additionally be checked on each target operating system.
