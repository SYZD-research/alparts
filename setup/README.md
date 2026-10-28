# Production setup

English | [日本語](README.ja.md)

A program that installs and runs Alparts in production on one server. Answer a few questions and it does all of the following:

- Builds the app image from the repository's [Dockerfile](../Dockerfile)
- Starts PostgreSQL 16 and SeaweedFS (S3-compatible object storage), with separate credentials and least-privilege roles for each use
- Protects the connections between the app and the database and storage with TLS from an internal certificate authority it creates
- Serves the app over HTTPS with Caddy, which obtains and renews Let's Encrypt certificates
- Migrates the database and initializes the activity record (the audit checkpoint)
- Relays voice calls through the server (SFU)
- Checks the connection to the mail (SMTP) server that sends the sign-up emails
- Makes an encrypted backup every day (a systemd timer)
- Writes the certificate-key pins file that release builds of the desktop and Android apps need
- Shows the invitation code that creates the first account

It is written in TypeScript and uses nothing but Node.js itself. It lives in this directory, apart from the app (`packages/`).

## Requirements

- A Linux server (x86_64 or ARM64), with 2 GB of memory and 10 GB of free disk or more
- [Docker Engine](https://docs.docker.com/engine/install/) with the Docker Compose plugin 2.20 or later. Rootless mode and user namespace remapping (userns-remap) are not supported
- Node.js 22.18 or later (24 recommended). On Ubuntu, for example: `sudo snap install node --classic --channel=24`
- git
- A domain name, with a DNS A record pointing at this server's IPv4 address
- Incoming connections from the internet allowed (cloud security groups, firewalls) on:
  - 80/tcp, 443/tcp and 443/udp (the web, and getting certificates)
  - 40000/udp and 40000/tcp (when calls are relayed through the server)
- Recommended: the mail (SMTP) server's host name, port, sender address and sign-in details
- Recommended: an age public key for backups. Create it on a safe machine other than this server with age 1.3 or later, `age-keygen -pq -o backup-key.txt`, and use the `age1pq1…` public key it shows. The secret key file never goes on the server

## Installing

```bash
sudo git clone https://github.com/SYZD-research/alparts.git /opt/alparts
cd /opt/alparts
sudo ./setup/alparts-setup
```

Run without `sudo`, it uses your own Node.js and asks for the administrator password when needed (the way to go with a Node.js from nvm and the like).

There are four questions, and the answers are shown for review before anything is installed:

1. **Public address** — the domain name people connect to. The setup checks that DNS points to this server and that port 80 is reachable
2. **Sign-up email** — the SMTP settings, which are tried with a real connection and sign-in. Without email, sign-up can work without confirmation, but anyone holding an invitation code can then find out whether an address already has an account by trying to sign up with it
3. **Voice calls** — whether calls are relayed through this server (recommended), and if so, the public IPv4 address people connect to (by default the domain's A record)
4. **Backups** — the public key and the time of day for daily backups

The first build of the app image takes 10 to 20 minutes. If the setup stops partway, run it again to continue. At the end it shows the address and the invitation code for the first account:

1. Open the address and choose "Create account"
2. Enter the code as the "Invitation code". It creates the first account on this server only (`sudo ./setup/alparts-setup invite-code` shows it again)
3. After signing in, create a workspace with "+" on the left, then invite members from "Manage invitations" in the workspace settings

### Installing from an answers file

Given the answers in a JSON file, the setup installs without asking anything:

```json
{
  "domain": "chat.example.com",
  "email": {
    "mode": "smtp",
    "host": "smtp.example.com",
    "port": 587,
    "security": "starttls",
    "from": "no-reply@example.com",
    "user": "no-reply@example.com",
    "passwordFile": "/root/smtp-password"
  },
  "voice": { "relay": true, "publicAddress": "203.0.113.10" },
  "backup": { "recipient": "age1pq1…", "time": "04:00" }
}
```

```bash
sudo ./setup/alparts-setup install --answers answers.json
```

| Field | Meaning |
| --- | --- |
| `domain` | Required. The domain name to serve |
| `email.mode` | Required. `smtp`, or `disabled` for no email confirmation |
| `email.security` | `starttls` (the default, port 587) or `tls` (port 465) |
| `email.user` | Leave out for no sign-in. With a user, give `password`, or `passwordFile`: a file holding only the password |
| `voice.relay` | Whether calls go through the server (default `true`) |
| `voice.publicAddress` | Left out, the domain's A record is used |
| `backup` | Left out, no backups are set up |
| `acmeEmail` | Optional. A contact address registered with the certificate authority |
| `certificates` | `public` (the default, Let's Encrypt). `local` is for trials without public DNS; browsers warn about its certificate |

When the mail server cannot be reached the setup stops; with `--yes` it warns and continues.

## Commands

| Command | Does |
| --- | --- |
| `sudo ./setup/alparts-setup` | Installs (same as `install`) |
| `… configure` | Changes the answers given at installation (address, email, calls, backups) and applies them |
| `… status` | Shows the services, the certificate's expiry, calls, email and backups |
| `… start` / `stop` / `restart` | Starts, stops and restarts. Stopping keeps the data |
| `… update` | Updates to the repository's current contents, fetched with `git pull` for example |
| `… backup` | Makes a backup now |
| `… backup-setup` | Sets up daily backups (`--disable` stops them) |
| `… pins` | Writes the pins file for the desktop and Android apps (`--rotate` switches the key) |
| `… invite-code` | Shows the invitation code for the first account |
| `… logs [app\|proxy\|postgres\|object-storage]` | Shows what the services report |

Every command takes `--lang ja|en` (the language of the messages; the system's language by default) and `--help`.

## How it is put together

```text
                 Internet
   80/443 (HTTPS) │                  │ 40000 UDP/TCP (call relay)
           ┌──────▼──────┐           │
           │ proxy        │ Caddy     │
           └──────┬──────┘           │
          edge network (a fixed address range)
           ┌──────▼──────────────────▼──────┐
           │ app (Alparts server and relay) │
           └──────┬────────────────┬────────┘
          backend network (no route out, TLS inside)
           ┌──────▼──────┐  ┌──────▼─────────┐
           │ postgres     │  │ object-storage  │
           └─────────────┘  └────────────────┘
```

The app and the migration step are defined by the repository's [compose.production.yml](../compose.production.yml) as it is. The setup puts a generated `compose.json` on top that adds the database, the storage, the HTTPS proxy, the call relay and the backup tools. The Compose project is named `alparts-production`.

| Path | Holds |
| --- | --- |
| `/etc/alparts-production/setup.json` | The answers and the state of the installation |
| `/etc/alparts-production/secrets/` | The credentials (only root can open the directory; each file is mode 0400, those the app reads belong to the app's user and those the backups read to the backup user; only the internal certificate authority's certificate, which is public, is 0444) |
| `/etc/alparts-production/compose.env`, `compose.json` | Generated files for Compose |
| `/etc/alparts-production/proxy/Caddyfile` | The HTTPS proxy's settings |
| `/etc/alparts-production/postgres/pg_hba.conf` | PostgreSQL's connection rules |
| `/etc/alparts-production/transport-pins.json` | The pins file for the desktop and Android apps |
| `/var/lib/alparts-production/backups/` | The encrypted backups |
| `/var/lib/alparts-production/backup-work/` | Where a backup puts the data before encrypting it (empty once it finishes) |
| `/var/log/alparts-production/` | A detailed record of each run (the newest 60) |
| Docker volumes `alparts-production_*` | The database, files, certificates and the activity record's anchor |

The generated files are written again on every run. Do not edit them; use `configure`. To use Compose directly:

```bash
sudo docker compose --project-name alparts-production --project-directory /opt/alparts \
  --env-file /etc/alparts-production/compose.env \
  -f /opt/alparts/compose.production.yml -f /etc/alparts-production/compose.json ps
```

## Security design

- **Credentials** — Generated at random on the first run and never overwritten. Losing the password pepper or the audit key makes the existing data unusable: keep an encrypted copy of `/etc/alparts-production` somewhere other than the server
- **PostgreSQL** — Separate roles: `alparts_owner` applies migrations and owns the schema, `alparts_app` (the app) only reads and writes rows, and `alparts_backup` only reads. The superuser is reachable only through the local socket inside the container and has no password login. Role passwords are set as SCRAM verifiers, so the plain passwords never reach the server
- **TLS** — An internal certificate authority issues the certificates of PostgreSQL and SeaweedFS, and the app verifies them. PostgreSQL refuses connections without TLS
- **Networks** — The database and the storage are on an internal network with no route out, and publish no host ports
- **Storage permissions** — Separate identities: an administrator that creates buckets (never given to the app), the app with its two buckets, and a backup identity that only reads the app's bucket
- **HTTPS proxy** — Health checks and metrics are not served publicly. Request bodies are received whole before they are passed on. The proxy, at a fixed address, is the only source the app trusts for client addresses
- **Activity record** — The audit checkpoint is created once, by the first installation. If it goes missing it may have been tampered with, so the setup does not recreate it and asks for the checks in the [operations guide](../docs/OPERATIONS.md)
- **App container** — As compose.production.yml defines it: a read-only root, no capabilities, `no-new-privileges`, a non-root user, memory and CPU limits. Node.js's permission model (`--permission`) is left off: current Node.js releases (checked with 22.22 and 24.22) turn off `fsync` under it, so the audit checkpoint cannot be written and the app stops accepting writes after the first one. The other flags, such as `--disallow-code-generation-from-strings`, stay (risk register R-059)
- **Backups** — Encrypted to an age public key. The secret key that restores them is never on the server. The backup container runs as a user other than root (`postgres` of the PostgreSQL image, uid 70) with the read-only database role and storage key

## Updating

```bash
cd /opt/alparts
sudo git pull
sudo ./setup/alparts-setup update
```

The setup builds the new version's image, stops the app, makes a backup (when backups are set up), migrates the database and starts the new version. If the new version does not start and no migration ran, the previous version is started again automatically. After a migration the previous version no longer fits the database: use the backup made before the update and the [operations guide](../docs/OPERATIONS.md). The current and the previous image are kept.

## Backups and restores

Every day at the set time (04:00 by default, up to 10 minutes later) the app stops for a few minutes while [scripts/backup.sh](../scripts/backup.sh) puts a PostgreSQL dump and the files into one encrypted file. Backups older than 30 days are removed, keeping at least 7. `systemctl list-timers alparts-production-backup.timer` shows the next run and `journalctl -u alparts-production-backup` the results.

Copy `/var/lib/alparts-production/backups/` elsewhere regularly, in case the whole server is lost. Check that a backup really restores in an isolated environment with [scripts/restore-verify.sh](../scripts/restore-verify.sh) (see [backup and restore](../docs/BACKUP.md)). The audit's external anchor (the `alparts-audit` bucket) is not part of ordinary backups and restores.

## Desktop and Android apps

Release builds of the desktop and Android apps carry the server's certificate key as a pin and refuse certificates for any other key. The setup creates the certificate key itself and hands it to Caddy, which then keeps it across renewals.

```bash
sudo ./setup/alparts-setup pins
ALPARTS_TRANSPORT_PINS_FILE=/etc/alparts-production/transport-pins.json pnpm desktop:dist
cd packages/android && ./gradlew -PalpartsTransportPinsFile=/etc/alparts-production/transport-pins.json assembleRelease
```

The pins file lists two keys: the current one and a spare. `pins --rotate` switches to the spare and makes a new spare. Apps built with the file from before the switch keep connecting, since they know the spare; build them again with the new file afterwards. If the server is ever compromised, treat the spare as exposed too.

## Not covered

- One server only. Alparts itself does not support redundant servers or failover
- The independent audit witness and metrics are not set up. See the [deployment guide](../docs/policies/DEPLOYMENT.md) and the [operations guide](../docs/OPERATIONS.md) if you need them
- The mail server check stops at connecting and signing in; no email is sent
- The call relay announces an IPv4 address only
- Copying backups elsewhere and checking restores are not automated

## Troubleshooting

- `sudo ./setup/alparts-setup status` shows the state of each service; `logs app` and the like show what they report
- After a failure, the "Details" file shown holds the commands run and their output (credentials are never written to it)
- If no certificate is issued, check the DNS A record and that ports 80 and 443 accept incoming connections. It is issued automatically once they do
- If a port is in use by another program, stop that program (another web server, for example) and run the setup again

## Uninstalling

This stops and removes the containers; the data (volumes) remains:

```bash
sudo docker compose --project-name alparts-production --project-directory /opt/alparts \
  --env-file /etc/alparts-production/compose.env \
  -f /opt/alparts/compose.production.yml -f /etc/alparts-production/compose.json down
sudo systemctl disable --now alparts-production-backup.timer
sudo rm /etc/systemd/system/alparts-production-backup.service /etc/systemd/system/alparts-production-backup.timer
```

Only to erase the data as well, add `--volumes` to the `down` above and remove `/etc/alparts-production` and `/var/lib/alparts-production`. This cannot be undone: first make sure you have the backups and the copy of the credentials you need.

## Development

```bash
pnpm --filter @alparts/setup typecheck
pnpm --filter @alparts/setup test
```

The unit tests run on Node.js's own test runner and do not use Docker.

The database roles and grants have an integration test on a disposable PostgreSQL 16 server (CI runs it in the integration job). It applies the server's migrations, then tries what each role must and must not be able to do. Build the server and run it where `psql` and `pg_dump` are available. It creates a database and roles with unique names and drops them at the end, but never point it at a production server.

```bash
pnpm --filter @alparts/server build
export SETUP_TEST_DATABASE_URL='…'  # a superuser connection URL of a disposable PostgreSQL 16 server
pnpm --filter @alparts/setup test:integration
```

The flows that use Docker (install, update and its rollback, backup, resuming after an interruption) have no automated test. After changing them, install on a disposable Linux server with Docker and Node.js, from an answers file with local certificates (`"certificates": "local"`), and run each command. Check a restore from a backup in empty, disposable targets with [scripts/restore-verify.sh](../scripts/restore-verify.sh).
