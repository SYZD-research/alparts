import { createHash, createHmac, pbkdf2Sync, randomBytes, X509Certificate } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { APP_USER, ensureDirectory, ROOT, writeFileAtomic, writeFileIfChanged, type Owner } from './files.ts';
import type { Settings } from './settings.ts';
import { createCertificateAuthority, daysUntilExpiry, generatePrivateKeyPem, issueServerCertificate } from './x509.ts';

// Every credential lives in its own file under the secrets directory (mode
// 0700). Files the app image reads belong to its user; the rest to root. All
// are mode 0400. Generated values are created once and never replaced: the
// password pepper and the audit key in particular must outlive the install.

const hex = (bytes: number) => () => randomBytes(bytes).toString('hex');

/** Generated credentials: file name, who reads it, and how a new one is made. */
export const GENERATED_SECRETS = {
  postgres_superuser_password: { owner: ROOT, generate: hex(32) },
  postgres_owner_password: { owner: ROOT, generate: hex(32) },
  postgres_app_password: { owner: ROOT, generate: hex(32) },
  postgres_backup_password: { owner: ROOT, generate: hex(32) },
  storage_admin_access_key: { owner: ROOT, generate: hex(16) },
  storage_admin_secret_key: { owner: ROOT, generate: hex(32) },
  storage_app_access_key: { owner: APP_USER, generate: hex(16) },
  storage_app_secret_key: { owner: APP_USER, generate: hex(32) },
  storage_backup_access_key: { owner: ROOT, generate: hex(16) },
  storage_backup_secret_key: { owner: ROOT, generate: hex(32) },
  jwt_secret: { owner: APP_USER, generate: hex(48) },
  password_pepper: { owner: APP_USER, generate: hex(48) },
  audit_integrity_key: { owner: APP_USER, generate: hex(48) },
  // Typed or pasted once, into the first account's registration form.
  registration_invite_secret: { owner: APP_USER, generate: () => randomBytes(32).toString('base64url') },
  proxy_tls_current_key: { owner: ROOT, generate: generatePrivateKeyPem },
  proxy_tls_spare_key: { owner: ROOT, generate: generatePrivateKeyPem },
} as const satisfies Record<string, { owner: Owner; generate: () => string }>;

export type GeneratedSecret = keyof typeof GENERATED_SECRETS;

/** Files written from settings and the generated values on every run. */
export const DERIVED_SECRETS = {
  database_url: APP_USER,
  migration_database_url: APP_USER,
  storage_identities: ROOT,
  backup_pg_service: ROOT,
  backup_age_recipient: ROOT,
  smtp_password: APP_USER,
  empty: APP_USER,
  internal_ca_certificate: APP_USER,
  internal_ca_key: ROOT,
  postgres_tls_certificate: ROOT,
  postgres_tls_key: ROOT,
  storage_tls_certificate: ROOT,
  storage_tls_key: ROOT,
} as const satisfies Record<string, Owner>;

export type DerivedSecret = keyof typeof DERIVED_SECRETS;
export type SecretName = GeneratedSecret | DerivedSecret;

export const DATABASE = {
  name: 'alparts',
  owner: 'alparts_owner',
  app: 'alparts_app',
  backup: 'alparts_backup',
  host: 'postgres',
  port: 5432,
} as const;

export const STORAGE = {
  host: 'object-storage',
  port: 8333,
  bucket: 'alparts',
  auditBucket: 'alparts-audit',
} as const;

const CA_VALID_DAYS = 7300;
const SERVER_CERT_VALID_DAYS = 3650;
const RENEW_WITHIN_DAYS = 365;

export class SecretStore {
  readonly dir: string;

  constructor(dir: string) {
    this.dir = dir;
  }

  path(name: SecretName): string {
    return join(this.dir, name);
  }

  has(name: SecretName): boolean {
    return existsSync(this.path(name));
  }

  read(name: SecretName): string {
    return readFileSync(this.path(name), 'utf8').trim();
  }

  /** Creates the generated values that do not exist yet, and returns their names. */
  ensureGenerated(): GeneratedSecret[] {
    ensureDirectory(this.dir, 0o700);
    const created: GeneratedSecret[] = [];
    for (const [name, spec] of Object.entries(GENERATED_SECRETS) as Array<[GeneratedSecret, (typeof GENERATED_SECRETS)[GeneratedSecret]]>) {
      if (this.has(name)) continue;
      writeFileAtomic(this.path(name), `${spec.generate().trim()}\n`, 0o400, spec.owner);
      created.push(name);
    }
    return created;
  }

  /**
   * The certificate key the apps pin moves to the spare, and a new spare is
   * made: the one deliberate replacement of a generated value.
   */
  rotateProxyKey(): void {
    const spare = this.read('proxy_tls_spare_key');
    writeFileAtomic(this.path('proxy_tls_current_key'), `${spare}\n`, 0o400, GENERATED_SECRETS.proxy_tls_current_key.owner);
    writeFileAtomic(this.path('proxy_tls_spare_key'), `${generatePrivateKeyPem().trim()}\n`, 0o400, GENERATED_SECRETS.proxy_tls_spare_key.owner);
  }

  /** The SMTP password is entered by the operator, never generated. */
  writeSmtpPassword(password: string): void {
    this.writeDerived('smtp_password', password);
  }

  private changed = new Set<SecretName>();

  private writeDerived(name: DerivedSecret, content: string): void {
    if (writeFileIfChanged(this.path(name), content, 0o400, DERIVED_SECRETS[name])) this.changed.add(name);
  }

  /** The names written since the last call: services that mount them need a restart. */
  takeChanged(): SecretName[] {
    const names = [...this.changed];
    this.changed.clear();
    return names;
  }

  /**
   * Writes the files built from settings and generated values. The internal
   * authority is created once; server certificates are issued again when they
   * near expiry or no longer chain to it.
   */
  writeDerivedFiles(settings: Settings): void {
    const password = (name: GeneratedSecret) => this.read(name);
    this.writeDerived('database_url', databaseUrl(DATABASE.app, password('postgres_app_password')));
    this.writeDerived('migration_database_url', databaseUrl(DATABASE.owner, password('postgres_owner_password')));
    this.writeDerived('storage_identities', storageIdentities({
      admin: [password('storage_admin_access_key'), password('storage_admin_secret_key')],
      app: [password('storage_app_access_key'), password('storage_app_secret_key')],
      backup: [password('storage_backup_access_key'), password('storage_backup_secret_key')],
    }));
    this.writeDerived('backup_pg_service', backupServiceFile(password('postgres_backup_password')));
    this.writeDerived('backup_age_recipient', settings.backup ? `${settings.backup.recipient}\n` : '');
    this.writeDerived('empty', '');
    if (settings.email.mode !== 'smtp' || settings.email.user === null || !this.has('smtp_password')) {
      this.writeDerived('smtp_password', '');
    }
    this.ensureCertificates();
  }

  private ensureCertificates(): void {
    if (!this.has('internal_ca_certificate') || !this.has('internal_ca_key')) {
      const authority = createCertificateAuthority('Alparts internal CA', CA_VALID_DAYS);
      this.writeDerived('internal_ca_key', authority.privateKeyPem);
      this.writeDerived('internal_ca_certificate', authority.certificatePem);
    }
    const authority = {
      certificatePem: readFileSync(this.path('internal_ca_certificate'), 'utf8'),
      privateKeyPem: readFileSync(this.path('internal_ca_key'), 'utf8'),
    };
    const caCertificate = new X509Certificate(authority.certificatePem);
    for (const [host, certificateName, keyName] of [
      [DATABASE.host, 'postgres_tls_certificate', 'postgres_tls_key'],
      [STORAGE.host, 'storage_tls_certificate', 'storage_tls_key'],
    ] as const) {
      if (this.has(certificateName) && this.has(keyName)) {
        const pem = readFileSync(this.path(certificateName), 'utf8');
        const current = new X509Certificate(pem);
        if (current.checkIssued(caCertificate) && current.verify(caCertificate.publicKey)
          && current.checkHost(host) === host && daysUntilExpiry(pem) > RENEW_WITHIN_DAYS) continue;
      }
      const issued = issueServerCertificate(authority, { commonName: host, dnsNames: [host], validDays: SERVER_CERT_VALID_DAYS });
      this.writeDerived(keyName, issued.privateKeyPem);
      this.writeDerived(certificateName, issued.certificatePem);
    }
  }
}

/** TLS and the server identity come from DB_SSL and the trusted authority, never from URL parameters. */
export function databaseUrl(user: string, password: string): string {
  return `postgresql://${user}:${encodeURIComponent(password)}@${DATABASE.host}:${DATABASE.port}/${DATABASE.name}\n`;
}

export function storageIdentities(keys: { admin: [string, string]; app: [string, string]; backup: [string, string] }): string {
  const credentials = ([accessKey, secretKey]: [string, string]) => [{ accessKey, secretKey }];
  const bucketActions = (bucket: string, actions: string[]) => actions.map((action) => `${action}:${bucket}`);
  return `${JSON.stringify({
    identities: [
      // Creates buckets and repairs the store; never given to the app.
      { name: 'admin', credentials: credentials(keys.admin), actions: ['Admin', 'Read', 'List', 'Tagging', 'Write'] },
      {
        name: 'alparts-app',
        credentials: credentials(keys.app),
        actions: [...bucketActions(STORAGE.bucket, ['Read', 'Write', 'List']), ...bucketActions(STORAGE.auditBucket, ['Read', 'Write', 'List'])],
      },
      // Reads the application bucket only; the audit head is kept out of restores.
      { name: 'alparts-backup', credentials: credentials(keys.backup), actions: bucketActions(STORAGE.bucket, ['Read', 'List']) },
    ],
  }, null, 2)}\n`;
}

/** The libpq service file scripts/backup.sh connects with; the password never reaches argv or the environment. */
export function backupServiceFile(password: string): string {
  return [
    '[alparts_backup]',
    `host=${DATABASE.host}`,
    `port=${DATABASE.port}`,
    `dbname=${DATABASE.name}`,
    `user=${DATABASE.backup}`,
    `password=${password}`,
    'sslmode=verify-full',
    'sslrootcert=/run/secrets/internal_ca_certificate',
    '',
  ].join('\n');
}

/**
 * A SCRAM-SHA-256 verifier in PostgreSQL's stored format (RFC 5802/7677).
 * Setting a role's password to it keeps the plain password away from the
 * server, its logs and its statistics. The generated passwords are ASCII, which
 * SASLprep leaves unchanged.
 */
export function scramSha256Verifier(password: string, salt = randomBytes(16), iterations = 4096): string {
  const salted = pbkdf2Sync(password, salt, iterations, 32, 'sha256');
  const clientKey = createHmac('sha256', salted).update('Client Key').digest();
  const storedKey = createHash('sha256').update(clientKey).digest();
  const serverKey = createHmac('sha256', salted).update('Server Key').digest();
  return `SCRAM-SHA-256$${iterations}:${salt.toString('base64')}$${storedKey.toString('base64')}:${serverKey.toString('base64')}`;
}
