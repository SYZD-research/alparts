<p align="center">
  <img src="icon/png/alparts.png" width="120" alt="Alparts logo">
</p>

# Alparts

English | [日本語](README.ja.md)

**Your team's conversations, on your own server.**

> [!IMPORTANT]
> Alparts is still in development. Features and behavior may change without notice.

Alparts is a self-hosted communication app that brings channel chat, direct messages, file sharing and voice calls together in one place. Create a space for each team or project, and decide for yourself who takes part and who can see what.

Message text and attachments support end-to-end encryption: they are encrypted on the device before they are sent. The same workspace can be used from a web browser, the desktop app for Windows, macOS and Linux, and the Android app.

[Features](#features) · [Getting started locally](#getting-started-locally) · [Running a server](#running-a-server) · [Documentation](docs/INDEX.md)

## Features

### Organize conversations by topic

Create categories and channels inside a workspace to separate conversations by project, subject or team. Channels can be public within the workspace or private to the members you choose. You can also talk with members of the same workspace in one-to-one or group direct messages.

### Chat for everyday work

- Markdown, mentions, replies, threads, editing and deleting messages, and reactions.
- Pinned posts, saved messages and links to individual messages.
- Unread markers, favorites, muting, hiding, and notification settings per channel.
- Search by text, author or channel name. Search covers the history already loaded on that device and never sends search terms to the server.
- Drafts and unsent messages are stored encrypted on the device. Text can be queued while offline and is sent again when the connection returns.

### Keep questions and topics in forums

In a forum channel, replies are grouped under each titled post. The post list can be sorted by latest reply or newest post and filtered by tags that administrators create. Posts can be pinned, marked as resolved, and locked against new replies by administrators, and new replies are highlighted. Post titles, text and replies are encrypted on the device just like ordinary messages. Tag names, like channel names, are visible to the server, so do not put anything private in them.

Who may create posts and who may reply can be set separately with roles and per-channel permissions.

### Share files and talk by voice

Attachments are shared with both their contents and file names encrypted. Each file can be up to 100 MiB, with up to four attachments per message, and uploads can be paused and resumed. Sending attachments requires an online connection.

Voice channels support calls with up to eight people. They include mute, voice activity detection, push-to-talk, microphone selection, and indicators for who is speaking and connection quality. Where supported, the output speaker can be changed too.

### Manage members and permissions

Invite members with invitation codes that expire or can be used only once. Create and assign roles, and set view and post permissions per category and channel, with a review of the effect before a change and an explanation of why each permission applies. The management screen also lets you revoke invitations and review the activity log.

### Check devices and carry history over

Approve new devices, compare verification codes, remove devices you no longer use, and end sign-ins. The web version supports signing in with a passkey and confirming important actions with one.

Once history restore is set up, you can carry saved history over to another device with a supported passkey or a recovery code you have stored. The desktop and Android apps also store keys with the device's own protection and can lock the app.

### Available in English and Japanese

The interface is available in English and Japanese. By default it follows the language of your browser or operating system (English unless that language is Japanese), and you can change it at any time from the sign-in screen or the 🌐 button in the sidebar. The choice is saved on that device.

## Clients

| Client | Platforms and notes | Guide |
| --- | --- | --- |
| Web | Runs in a browser. On narrow screens, swipe to move between channels and the conversation | [Run locally](#getting-started-locally) |
| Desktop | Windows, macOS 13 or later, and Linux, with package configurations for x64 and ARM64 on each | [Desktop guide](docs/DESKTOP.md) |
| Android | Development builds for Android 9 or later. Needs a screen lock on the device and an HTTPS server | [Android guide](docs/ANDROID.md) |

Registering passkeys, signing in with them and confirming actions with them is done in the web version. Setting up history restore for the first time requires a passkey that supports PRF. To restore history in the desktop or Android app, use a recovery code you have stored.

## Getting started locally

### Requirements

- A Bash environment on Linux or macOS
- Node.js **24.8.0 or later** and pnpm **11.21.0**
- Docker, running, with the Docker Compose plugin
- OpenSSL, and permission to run Docker with `sudo`

### Start

Run this from the repository root.

```bash
./dev.sh
```

The first run generates development credentials and saves them to `.env` (only the storage administrator credentials go to `.local/storage-admin.env`, so that they never reach the app). It then starts PostgreSQL and S3-compatible storage (SeaweedFS), installs dependencies, migrates the database and initializes the audit checkpoint, and finally starts the web client and the API. Docker is driven with `sudo docker compose`.

| Service | URL |
| --- | --- |
| Web | <http://localhost:5173> |
| API | <http://localhost:3000> |

### Create your first workspace

1. Open **Create account** in the web client.
2. Enter the value of `REGISTRATION_INVITE_SECRET` from `.env` as the **Invitation code**, then set a display name, email address and password. This code can create only the first account on the server.
   Without SMTP settings, no email is actually sent: the verification code appears in the terminal running `./dev.sh`, under a `[dev] mail to ...` line. To skip the code entirely, add `EMAIL_VERIFICATION=disabled` to `.env`; to send real mail, set the `SMTP_*` values described in [.env.example](.env.example).
3. After signing in, create a workspace with the **+** button on the left. A first text channel, `general`, is created automatically.
4. In the workspace management screen, open **Manage invitations** and create invitation codes for members. People who receive a code can use it to create an account and join.

Invitations are not emailed automatically. Share the codes you create through a secure channel. To join another workspace with an existing account, enter the code under **Accept invitation** in the management screen.

To use the same account in another browser or app, either approve the new device from **Signed-in devices** on a device you already use, after comparing verification codes, or add it with history restore if you have set that up. History restore itself is set up from **Restore history** on the same screen. Keep your recovery code somewhere safe, away from your devices.

### Use the desktop and Android apps

Start the desktop app in another terminal while `./dev.sh` is running.

```bash
pnpm dev:desktop
```

On the first screen, enter `http://localhost:5173` as the server. The app's screens are bundled with it, and it connects to the local development server. On Linux, the operating system's keyring service is required.

For Android, set up JDK 21, the Android SDK and the rest as described in the [Android guide](docs/ANDROID.md), then build a development APK with:

```bash
pnpm android:build
```

The output is `packages/android/app/build/outputs/apk/debug/app-debug.apk`. From Android, connect to an HTTPS server that the device can reach. The HTTP address used for local development does not work; to use your PC's development server from a device, start it with `./dev.sh --tailscale` (see [Connecting over Tailscale](docs/ANDROID.md#connecting-to-a-development-server-over-tailscale)).

### Stop and restart

Press `Ctrl+C` in the terminal that is running the web client and API to stop them. To stop PostgreSQL and storage as well, run:

```bash
./dev.sh down
```

Run `./dev.sh` again to restart. Stopping does not delete the data volumes. Keep the generated `.env` and `.local/audit-checkpoint.json` as well.

In development environments created before 2026-09-30, `./dev.sh` stops and reports that the audit record migration has not been done. Read the [audit head migration procedure](docs/OPERATIONS.md), then run the following command once. After the migration, the environment starts normally.

```bash
./dev.sh audit-head-init
```

## Running a server

An Alparts server consists of **one application process, PostgreSQL 16, and S3-compatible object storage (SeaweedFS is recommended)**. The server also serves the web client. A [Dockerfile](Dockerfile) and [Compose configuration](compose.production.yml) are provided for containers, along with a [systemd unit](deploy/alparts.service) for Linux.

`docker-compose.yml` starts PostgreSQL and S3-compatible storage (SeaweedFS) for local development. `compose.production.yml` defines the application and the migration step; you provide the database, storage and HTTPS reverse proxy separately.

- **Connections and credentials** — Serve the public web client and API over HTTPS, and set `CORS_ORIGINS` to the origins actually used. Credentials can be passed from protected files with `*_FILE`. See the [example environment](.env.example) for the settings.
- **Voice calls** — By default, no external relay service is used for calls. For connections between different networks, set operator-managed STUN/TURN servers in `VOICE_ICE_SERVERS_JSON`. Use short-lived TURN credentials that are safe to hand to participants.
- **Updates and backups** — When updating, stop the app, take a backup and check that it restores, and then migrate the database. Encrypted backups, a systemd timer for daily runs, and a tool for checking restores in an isolated environment are included.
- **Monitoring and audit** — Endpoints for start-up, liveness and readiness checks, authenticated metrics, and integrity verification of the activity log are built in. An audit checkpoint is required even in development.
- **Distributing the apps** — Packaging the desktop app and building Android releases requires certificate pinning for the server. See the [distribution and operations settings guide](docs/security/AUDIT_ALPARTS_REMEDIATION.md#接続先のビルド設定) (Japanese) for build-time settings and what to watch for when updating.

For step-by-step setup, see the [deployment guide](docs/policies/DEPLOYMENT.md); for day-to-day administration, the [operations guide](docs/OPERATIONS.md); and for protecting data, [backup and restore](docs/BACKUP.md).

## Encryption and current scope

Message text, attachment contents and file names are encrypted on the device. The server can still see information such as senders, participants, posting times and traffic volume. Encryption alone cannot protect you if a device, or the web app delivered to it, is compromised.

Device approval and key updates when participants or devices change are implemented. A device that is offline does not hold up sending. A newly added device can read and send messages once another device in the conversation comes online. It cannot read messages sent before that, although messages your other devices could read may be restored from your saved history. Keys for reading past messages are kept on your devices, so anyone who obtains a device's data may also be able to read past messages. Remove devices you have lost or no longer use.

History restore must be set up and saved in advance. If you lose every usable device, your restore passkey and your recovery code, not even the server administrator can recover the message text. The design and migration steps are described in [Protecting accounts, devices and history](docs/security/ACCOUNT_AND_GROUP_SECURITY.md) and [Setting up passkeys and recovery codes](docs/security/AUDIT_ALPARTS_REMEDIATION.md#パスキーと復旧コード) (Japanese).

Only single-server deployments are supported for now. Redundancy across several application processes, automatic failover, an iOS app, video calls and screen sharing, bots and webhooks, and single sign-on with OIDC are not supported yet. Background sync and push notifications on Android, passkeys in the native apps, and built-in automatic updates also remain to be done.

An independent external security review has not been completed. Do not use Alparts to share secrets whose leak would be serious, such as undisclosed vulnerabilities or credentials. For details, see the [known limitations](docs/policies/LIMITATIONS.md) and the [risk register](docs/RISK_REGISTER.md).

## Development

### Code layout

| Path | Contents |
| --- | --- |
| [packages/client](packages/client) | Shared screens, encryption and on-device state, built with React, TypeScript and Vite |
| [packages/server](packages/server) | Node.js and Express API, Socket.IO, authentication, permissions and audit, and database management with Drizzle |
| [packages/shared](packages/shared) | Types, constants and protocol definitions shared by the client and server |
| [packages/desktop](packages/desktop) | Electron app, operating system key storage, locking and file saving |
| [packages/android](packages/android) | Android app, bundled screens, device key storage, locking, and file picking and saving |
| [scripts](scripts) / [deploy](deploy) | Tools for verifying backups, restores and distribution, and systemd configuration |
| [docs](docs) | Design, operations, security and verification records |

### Basic checks

```bash
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm test
pnpm test:backup-security
pnpm test:release
pnpm build
pnpm security:secrets
pnpm audit --prod --audit-level moderate
git diff --check
```

Integration tests that use the database and storage run separately from `pnpm test`. Following the [CI configuration](.github/workflows/ci.yml), prepare disposable PostgreSQL and S3-compatible storage and the environment variables. Storage can be started with `scripts/ci/start-object-storage.sh`.

```bash
pnpm --filter @alparts/server test:integration
pnpm --filter @alparts/server test:account-security
```

Never run the integration tests against an environment that holds real data. Build and test Android with `pnpm android:build`. Development practices and pre-release checks are collected in the [contributing guide](docs/policies/CONTRIBUTING.md).

### Translations

All interface text goes through the translator in [packages/client/src/i18n](packages/client/src/i18n). The Japanese text is the message key, and the English catalog (`en.ts`) is typed against those keys, so a missing translation fails the type check. A client test also fails if Japanese text is added without going through `t()`. The desktop menu, Android resources and registration emails have their own small English and Japanese string sets.

## Documentation

- [Documentation index](docs/INDEX.md) — Entry point to design, operations and verification documents
- [Desktop](docs/DESKTOP.md) / [Android](docs/ANDROID.md) — Running and building each client
- [API and real-time protocol](docs/api/README.md) — Interfaces for developers
- [Security remediation record](docs/security/AUDIT_ALPARTS_REMEDIATION.md) (Japanese) — What was fixed and the settings needed when deploying
- [Security policy](docs/policies/SECURITY.md) — How to report vulnerabilities

## License

Copyright (C) 2026 SYZD Research

This program is free software. You can redistribute and modify it under the terms of the [GNU Affero General Public License version 3](LICENSE) (AGPL-3.0-only).

This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**, without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See [LICENSE](LICENSE) for details.

If you offer a modified version to users over a network (for example, by running it as a server), and not only when you distribute it, you must offer those users the corresponding source code under the same license. Third-party components are covered by their own licenses.
