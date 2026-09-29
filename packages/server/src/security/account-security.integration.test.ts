import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import {
  randomBytes,
  randomUUID,
  generateKeyPairSync,
  createHash,
  sign,
  type KeyObject,
} from 'node:crypto';
import { after, before, describe, it } from 'node:test';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  canonicalActionBody,
  serializeDeviceChallengeProof,
  serializeDeviceDecision,
  serializeGroupKeyPackage,
  serializeMlsEpoch,
  serializeChannelKeyWrap,
  serializeChannelKeyAcknowledgement,
  serializeMessageEnvelope,
  serializeMessageAad,
  type MlsEpoch,
  type GroupKeyPackage,
} from '@alparts/shared';

const enabled = process.env.RUN_ACCOUNT_SECURITY_INTEGRATION === '1';
const password = 'Account-Security-Test-Password!';
const origin = 'http://localhost:5173';
const bytes = (value: string) => Buffer.from(value, 'base64url');
const hash = (value: string | Uint8Array) => createHash('sha256').update(value).digest();
const signature = (key: KeyObject, value: string) =>
  sign('sha256', Buffer.from(value), {
    key,
    dsaEncoding: 'ieee-p1363',
  }).toString('base64');
function deviceKeys() {
  const encryption = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const signing = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: signing.privateKey,
    identityKey: JSON.stringify({
      version: 1,
      encryptionKey: {
        ...encryption.publicKey.export({ format: 'jwk' }),
        alg: 'RSA-OAEP-256',
        key_ops: ['encrypt'],
        ext: true,
      },
      signingKey: {
        ...signing.publicKey.export({ format: 'jwk' }),
        alg: 'ES256',
        key_ops: ['verify'],
        ext: true,
      },
    }),
  };
}
// Minimal test-only CBOR encoder to create standards-compliant software
// authenticator responses. Production verification uses SimpleWebAuthn.
function cbor(value: unknown): Buffer {
  const head = (major: number, n: number) =>
    n < 24
      ? Buffer.from([(major << 5) | n])
      : n < 256
        ? Buffer.from([(major << 5) | 24, n])
        : Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') {
    const b = Buffer.from(value);
    return Buffer.concat([head(3, b.length), b]);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (value instanceof Map)
    return Buffer.concat([
      head(5, value.size),
      ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)]),
    ]);
  throw new Error('Unsupported test CBOR');
}
function authenticator(userId: string) {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const id = randomBytes(32);
  let counter = 0;
  const clientData = (type: string, challenge: string, expectedOrigin = origin) =>
    Buffer.from(
      JSON.stringify({
        type,
        challenge,
        origin: expectedOrigin,
        crossOrigin: false,
      }),
    );
  return {
    id: id.toString('base64url'),
    registration(challenge: string) {
      const publicKey = cbor(
        new Map<number, unknown>([
          [1, 2],
          [3, -7],
          [-1, 1],
          [-2, bytes(jwk.x!)],
          [-3, bytes(jwk.y!)],
        ]),
      );
      const authData = Buffer.concat([
        hash('localhost'),
        Buffer.from([0x45, 0, 0, 0, 0]),
        Buffer.alloc(16),
        Buffer.from([0, id.length]),
        id,
        publicKey,
      ]);
      return {
        id: id.toString('base64url'),
        rawId: id.toString('base64url'),
        type: 'public-key',
        clientExtensionResults: {},
        response: {
          clientDataJSON: clientData('webauthn.create', challenge).toString('base64url'),
          attestationObject: cbor(
            new Map<string, unknown>([
              ['fmt', 'none'],
              ['attStmt', new Map()],
              ['authData', authData],
            ]),
          ).toString('base64url'),
          transports: ['internal'],
        },
      };
    },
    assertion(challenge: string, options: { origin?: string; uv?: boolean; rp?: string } = {}) {
      const count = Buffer.alloc(4);
      count.writeUInt32BE(++counter);
      const authData = Buffer.concat([
        hash(options.rp ?? 'localhost'),
        Buffer.from([options.uv === false ? 1 : 5]),
        count,
      ]);
      const data = clientData('webauthn.get', challenge, options.origin ?? origin);
      return {
        id: id.toString('base64url'),
        rawId: id.toString('base64url'),
        type: 'public-key',
        clientExtensionResults: {},
        response: {
          clientDataJSON: data.toString('base64url'),
          authenticatorData: authData.toString('base64url'),
          signature: sign(
            'sha256',
            Buffer.concat([authData, hash(data)]),
            pair.privateKey,
          ).toString('base64url'),
          userHandle: Buffer.from(userId).toString('base64url'),
        },
      };
    },
  };
}

describe('account security end to end', { skip: !enabled }, () => {
  let base: string;
  let server: import('node:http').Server;
  let runtime: import('./runtime-lease.js').RuntimeLease;
  let closeDb: () => Promise<void>;
  let admin: any;
  let databaseName: string;
  let auditDirectory: string;
  let cookie: string;
  let secondCookie: string;
  let userId: string;
  let channelId: string;
  let first: any;
  let second: any;
  const firstKeys = deviceKeys();
  const secondKeys = deviceKeys();
  let key: Uint8Array;
  let version: number;
  let commitment: string;
  let passkey: ReturnType<typeof authenticator>;
  let recoveryPair: { privateKey: KeyObject; publicKey: KeyObject };
  let generation: string;
  let encryptedHistory: string;
  const legacyUser = randomUUID();
  const legacyDevice = randomUUID();
  const legacyRevokedDevice = randomUUID();
  const legacyWorkspace = randomUUID();
  const legacyRole = randomUUID();
  const registrationInvitation = randomBytes(32).toString('base64url');
  const legacyChannel = randomUUID();
  async function request(
    path: string,
    body?: unknown,
    auth = cookie,
    method = body === undefined ? 'GET' : 'POST',
    token?: string,
  ) {
    return fetch(base + path, {
      method,
      headers: {
        Origin: origin,
        ...(auth ? { Cookie: auth } : {}),
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(token ? { 'X-Alparts-Step-Up': token } : {}),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  }
  async function rawStatus(target: string, method: string, body?: unknown, token?: string) {
    const url = new URL(base);
    const encoded = body === undefined ? '' : JSON.stringify(body);
    return new Promise<number>((resolve, reject) => {
      const req = httpRequest(
        {
          hostname: url.hostname,
          port: url.port,
          path: target,
          method,
          headers: {
            Cookie: cookie,
            Origin: origin,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(encoded),
            ...(token ? { 'X-Alparts-Step-Up': token } : {}),
          },
        },
        (res) => {
          res.resume();
          res.once('end', () => resolve(res.statusCode!));
        },
      );
      req.on('error', reject);
      req.end(encoded);
    });
  }
  async function json(response: Response, expected = 200): Promise<any> {
    const data = await response.json();
    assert.equal(response.status, expected, JSON.stringify(data));
    return data;
  }
  async function stepUp(path: string, body: unknown, method = 'POST', auth = cookie) {
    const purpose = `${method} ${path} ${hash(canonicalActionBody(body)).toString('base64url')}`;
    const options = await json(await request('/api/auth/step-up/options', { purpose }, auth));
    const proof = options.passwordAllowed
      ? { password }
      : { response: passkey.assertion(options.options.challenge) };
    return (
      await json(
        await request('/api/auth/step-up/verify', { id: options.id, purpose, ...proof }, auth),
      )
    ).token as string;
  }
  async function sensitive(path: string, body?: unknown, method = 'POST', auth = cookie) {
    return request(path, body, auth, method, await stepUp(path, body, method, auth));
  }
  async function head() {
    return (await json(await request(`/api/directory/${userId}?after=0`))).head;
  }
  async function registerDevice(auth: string, keys: ReturnType<typeof deviceKeys>, name: string) {
    const challenge = (await json(await request('/api/devices/challenge', {}, auth))).challenge;
    return json(
      await request(
        '/api/devices',
        {
          name,
          identityKey: keys.identityKey,
          challenge,
          proof: signature(keys.privateKey, serializeDeviceChallengeProof(userId, challenge)),
          currentPassword: password,
        },
        auth,
      ),
      201,
    );
  }
  async function encryptedMessage() {
    const envelope = {
      channelId,
      authorId: userId,
      deviceId: first.id,
      keyVersion: version,
      idempotencyKey: randomUUID(),
      refMessageId: null,
      broadcastMention: false,
      type: 'message' as const,
    };
    const nonce = randomBytes(12);
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key as Uint8Array<ArrayBuffer>,
      'AES-GCM',
      false,
      ['encrypt'],
    );
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        additionalData: new TextEncoder().encode(serializeMessageAad(envelope)),
      },
      cryptoKey,
      new TextEncoder().encode('recoverable message'),
    );
    const body = {
      ...envelope,
      encryptedContent: Buffer.from(encrypted).toString('base64'),
      contentNonce: nonce.toString('base64'),
    };
    const {
      authorId: _author,
      channelId: _channel,
      type: _type,
      refMessageId: _reference,
      ...input
    } = body;
    return {
      ...input,
      signature: signature(firstKeys.privateKey, serializeMessageEnvelope(body)),
    };
  }
  before(async () => {
    assert.match(
      process.env.DATABASE_URL ?? '',
      /alparts_(?:security_)?test/,
      'Use an isolated test database',
    );
    const pg = await import('pg');
    admin = new pg.default.Client({
      connectionString: process.env.DATABASE_URL,
    });
    await admin.connect();
    databaseName = `alparts_security_test_${randomUUID().replaceAll('-', '')}`;
    await admin.query(`CREATE DATABASE ${databaseName}`);
    const url = new URL(process.env.DATABASE_URL!);
    url.pathname = `/${databaseName}`;
    process.env.DATABASE_URL = url.toString();
    const migrationClient = new pg.default.Client({
      connectionString: url.toString(),
    });
    await migrationClient.connect();
    try {
      const { drizzle } = await import('drizzle-orm/node-postgres');
      const { migrate } = await import('drizzle-orm/node-postgres/migrator');
      const { resolveMigrationsFolder } = await import('../db/migration-bundle.js');
      const migrationsFolder = resolveMigrationsFolder();
      const oldBundle = await mkdtemp(join(tmpdir(), 'alparts-pre-security-migrations-'));
      try {
        await cp(migrationsFolder, oldBundle, { recursive: true });
        const journalPath = join(oldBundle, 'meta', '_journal.json');
        const journal = JSON.parse(await readFile(journalPath, 'utf8'));
        journal.entries = journal.entries.slice(0, 14);
        await writeFile(journalPath, JSON.stringify(journal));
        await migrate(drizzle(migrationClient), {
          migrationsFolder: oldBundle,
        });
        await migrationClient.query(
          'INSERT INTO users (id,email,password_hash,display_name) VALUES ($1,$2,$3,$4)',
          [legacyUser, 'legacy@example.test', 'disabled-test-fixture', '移行前'],
        );
        await migrationClient.query(
          'INSERT INTO devices (id,user_id,name,identity_key,revoked_at) VALUES ($1,$3,$4,$5,NULL), ($2,$3,$4,$5,now())',
          [legacyDevice, legacyRevokedDevice, legacyUser, '移行前の端末', firstKeys.identityKey],
        );
        await migrationClient.query('INSERT INTO workspaces (id,name,owner_id) VALUES ($1,$2,$3)', [
          legacyWorkspace,
          '移行前',
          legacyUser,
        ]);
        await migrationClient.query('INSERT INTO roles (id,workspace_id,name) VALUES ($1,$2,$3)', [
          legacyRole,
          legacyWorkspace,
          'Member',
        ]);
        await migrationClient.query(
          "INSERT INTO workspace_invitations (workspace_id,role_id,token_hash,created_by,expires_at) VALUES ($1,$2,$3,$4,now() + interval '1 hour')",
          [
            legacyWorkspace,
            legacyRole,
            hash('alparts-workspace-invitation-v1\0' + registrationInvitation).toString('hex'),
            legacyUser,
          ],
        );
        await migrationClient.query(
          'INSERT INTO channels (id,workspace_id,name) VALUES ($1,$2,$3)',
          [legacyChannel, legacyWorkspace, '履歴'],
        );
        await migrationClient.query(
          "INSERT INTO channel_key_epochs (channel_id,version,status,key_commitment,distributor_device_id,activated_at) VALUES ($1,1,'active',$2,$3,now()), ($1,2,'pending',$2,$3,NULL)",
          [legacyChannel, 'a'.repeat(43), legacyDevice],
        );
      } finally {
        await rm(oldBundle, { recursive: true, force: true });
      }
      await migrate(drizzle(migrationClient), { migrationsFolder });
    } finally {
      await migrationClient.end();
    }
    process.env.MINIO_ACCESS_KEY = 'account-security-test-access';
    process.env.MINIO_SECRET_KEY = 'account-security-test-secret';
    process.env.AUDIT_INTEGRITY_KEY = 'account-security-test-audit-key-32-bytes';
process.env.PASSWORD_PEPPER ||= 'test-only-password-pepper-at-least-32-bytes';
    process.env.JWT_SECRET = 'account-security-test-session-key-32-bytes';
    process.env.REGISTRATION_INVITE_SECRET = 'account-security-test-bootstrap-32-bytes';
    auditDirectory = await mkdtemp(join(tmpdir(), 'alparts-account-security-'));
    process.env.AUDIT_CHECKPOINT_PATH = join(auditDirectory, 'checkpoint');
    process.env.AUDIT_CHECKPOINT_REQUIRED = 'true';
    const database = await import('../db/index.js');
    closeDb = database.closeDb;
    assert.equal(await database.checkDatabaseSchema(), 19);
    const audit = await import('../middleware/audit.js');
    await audit.provisionAuditCheckpoint();
    const app = await import('../app.js');
    runtime = await (await import('./runtime-lease.js')).acquireRuntimeLease();
    server = app.createApp().httpServer;
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address() as import('node:net').AddressInfo;
    base = `http://127.0.0.1:${address.port}`;
  });
  after(async () => {
    if (server?.listening)
      await new Promise<void>((resolve, reject) =>
        server.close((e) => (e ? reject(e) : resolve())),
      );
    if (closeDb) await closeDb();
    await runtime?.close();
    if (admin) {
      if (databaseName) await admin.query(`DROP DATABASE ${databaseName} WITH (FORCE)`);
      await admin.end();
    }
    if (auditDirectory) await rm(auditDirectory, { recursive: true, force: true });
  });
  it('migrates existing identities and history without silently accepting old pending epochs', async () => {
    const { db } = await import('../db/index.js');
    const { sql } = await import('drizzle-orm');
    const devices = await db.execute(
      sql`SELECT id, approved_at, revoked_at FROM devices WHERE user_id = ${legacyUser}`,
    );
    assert.equal(devices.rows.length, 2);
    assert.ok(devices.rows.every((row) => row.approved_at));
    const events = await db.execute(
      sql`SELECT * FROM device_directory_events WHERE user_id = ${legacyUser} ORDER BY sequence`,
    );
    const verifier = await import('../../../client/src/services/' + 'directory-verifier.ts');
    const verified = await verifier.verifyDirectoryEntries(
      verifier.emptyDirectory(legacyUser),
      events.rows.map((r) => ({
        userId: r.user_id,
        sequence: r.sequence,
        previousHash: r.previous_hash,
        hash: r.hash,
        event: r.event,
      })) as any,
      {
        userId: legacyUser,
        sequence: events.rows.at(-1)!.sequence,
        hash: events.rows.at(-1)!.hash,
      },
    );
    assert.equal(verified.devices[legacyDevice].approved, true);
    assert.equal(verified.devices[legacyRevokedDevice].revoked, true);
    const epochs = await db.execute(
      sql`SELECT version, status, protocol_version FROM channel_key_epochs WHERE channel_id = ${legacyChannel} ORDER BY version`,
    );
    assert.deepEqual(epochs.rows, [
      { version: 1, status: 'active', protocol_version: 2 },
      { version: 2, status: 'aborted', protocol_version: 2 },
    ]);
    const channel = await db.execute(
      sql`SELECT key_rotation_required FROM channels WHERE id = ${legacyChannel}`,
    );
    assert.equal(channel.rows[0].key_rotation_required, true);
    await assert.rejects(
      db.execute(
        sql`UPDATE device_directory_events SET hash = ${'f'.repeat(64)} WHERE user_id = ${legacyUser}`,
      ),
      (error: any) => /append-only/.test(error.cause?.message),
    );
    await assert.rejects(
      db.execute(sql`TRUNCATE device_directory_events CASCADE`),
      (error: any) => /append-only/.test(error.cause?.message),
    );
  });
  it('requires existing-device approval and records verifiable decisions', async () => {
    const email = `security-${randomUUID()}@example.test`;
    const registered = await json(
      await request(
        '/api/auth/register',
        {
          email,
          password,
          displayName: 'Security test',
          inviteToken: registrationInvitation,
        },
        '',
      ),
      201,
    );
    userId = registered.id;
    const login = await request('/api/auth/login', { email, password }, '');
    await json(login);
    cookie = login.headers.get('set-cookie')!.split(';')[0];
    const otherLogin = await request('/api/auth/login', { email, password }, '');
    await json(otherLogin);
    secondCookie = otherLogin.headers.get('set-cookie')!.split(';')[0];
    first = await registerDevice(cookie, firstKeys, 'First');
    assert.ok(first.approvedAt);
    const workspace = await json(
      await request('/api/workspaces', { name: 'Account security' }),
      201,
    );
    const channelResponse = await json(await request(`/api/workspaces/${workspace.id}/channels`));
    channelId = channelResponse.find((c: any) => c.type === 'text').id;
    second = await registerDevice(secondCookie, secondKeys, 'Second');
    assert.equal(second.approvedAt, null);
    const pendingPurpose = `DELETE /api/auth/sessions ${hash('null').toString('base64url')}`;
    await json(
      await request('/api/auth/step-up/options', { purpose: pendingPurpose }, secondCookie),
      403,
    );
    assert.equal(
      (
        await json(
          await request(`/api/channels/${channelId}/key-recipients`, undefined, secondCookie),
        )
      ).recipients.some((r: any) => r.deviceId === second.id),
      false,
    );
    const currentHead = await head();
    const decision = {
      kind: 'approve' as const,
      deviceId: second.id,
      identityKey: second.identityKey,
      actorDeviceId: first.id,
    };
    const body = {
      head: currentHead,
      signature: signature(firstKeys.privateKey, serializeDeviceDecision(currentHead, decision)),
    };
    assert.equal((await request(`/api/devices/${second.id}/approve`, body)).status, 428);
    assert.equal(
      (await request(`/API/Devices/${second.id}/APPROVE/`, body)).status,
      428,
      'case and trailing slash do not bypass step-up',
    );
    for (const [path, method, input] of [
      [`/api/devices/${second.id}/approve`, 'POST', body],
      ['/api/auth/passkeys/register/options', 'POST', {}],
      ['/api/auth/sessions', 'DELETE', undefined],
    ] as const) {
      assert.equal(await rawStatus(path, method, input), 428);
      assert.equal(
        await rawStatus(base + path, method, input),
        428,
        'absolute-form cannot skip the gate',
      );
    }
    const token = await stepUp(`/api/devices/${second.id}/approve`, body);
    assert.equal(
      await rawStatus(`${base}/api/devices/${second.id}/approve`, 'POST', body, token),
      428,
      'an origin-form grant cannot authorize an absolute-form target',
    );
    assert.equal(
      (
        await request(
          `/api/devices/${second.id}/approve`,
          { ...body, signature: 'changed' },
          cookie,
          'POST',
          token,
        )
      ).status,
      428,
      'grant binds exact body',
    );
    assert.equal(
      (await request(`/api/devices/${second.id}/approve`, body, secondCookie, 'POST', token))
        .status,
      428,
      'grant binds exact session',
    );
    assert.equal(
      (await request(`/api/devices/${first.id}/approve`, body, cookie, 'POST', token)).status,
      428,
      'grant binds exact target',
    );
    await json(await request(`/api/devices/${second.id}/approve`, body, cookie, 'POST', token));
    assert.equal(
      (await request(`/api/devices/${second.id}/approve`, body, cookie, 'POST', token)).status,
      428,
      'grant is single use',
    );
    const directory = await json(await request(`/api/directory/${userId}?after=0`));
    assert.deepEqual(
      directory.entries.map((e: any) => e.event.kind),
      ['bootstrap', 'register', 'approve'],
    );
    const verifier = await import('../../../client/src/services/' + 'directory-verifier.ts');
    let verified = await verifier.verifyDirectoryEntries(
      verifier.emptyDirectory(userId),
      directory.entries,
    );
    assert.equal(verified.devices[second.id].approved, true);
  });
  it('rejects invalid approval targets, retired recovery routes, and unbound metadata reads', async () => {
    assert.equal((await sensitive('/api/devices/not-a-uuid/approve', {})).status, 404);
    assert.equal((await request(`/api/channels/${channelId}/keys/start-fresh`, {})).status, 410);
    const { db } = await import('../db/index.js');
    const { sql } = await import('drizzle-orm');
    const account = (await db.execute(sql`select email from users where id = ${userId}`)).rows[0];
    assert.equal((await request('/api/auth/login', { email: account.email, password: 'incorrect-test-password' }, '')).status, 401);
    assert.equal((await request('/api/auth/login', { email: `absent-${randomUUID()}@example.test`, password }, '')).status, 401);
    const failures = (await db.execute(sql`select target_id, details from audit_logs where action = 'user.login.failed' order by created_at desc, id desc limit 2`)).rows;
    assert.equal(failures[1].target_id, userId);
    assert.equal(failures[0].target_id, null);
    for (const failure of failures) {
      assert.match((failure.details as any).accountTag, /^[a-f0-9]{64}$/);
      assert.ok(!JSON.stringify(failure.details).includes(String(account.email)));
    }
    const login = await request('/api/auth/login', { email: account.email, password }, '');
    await json(login);
    const unbound = login.headers.get('set-cookie')!.split(';')[0];
    assert.equal((await request('/api/recovery/metadata', undefined, unbound)).status, 403);
    assert.equal((await request(`/api/directory/${legacyUser}?channelId=${legacyChannel}`, undefined, unbound)).status, 403);
    const messageService = await import('../services/message.service.js');
    await assert.rejects(messageService.getChannelMessages(channelId, legacyUser), /CHANNEL_NOT_FOUND/);
    await messageService.getChannelMessages(channelId, userId);
  });
  it('rechecks the current password and receipt scope inside the sensitive transaction', async () => {
    const service = await import('../services/passkey.service.js');
    const { actionPurpose } = await import('./action-purpose.js');
    const { db } = await import('../db/index.js');
    const { sql } = await import('drizzle-orm');
    const path = `/api/channels/${channelId}/mls/epochs/fresh-start`;
    const body = { test: 'scope' };
    const purpose = actionPurpose('POST', path, body);
    const session = (
      await db.execute(
        sql`SELECT id FROM sessions WHERE user_id = ${userId} AND device_id = ${first.id}`,
      )
    ).rows[0];
    const proof = await service.consumeStepUp(
      session.id as string,
      purpose,
      await stepUp(path, body),
    );
    assert.ok(proof);
    await assert.rejects(
      db.transaction((tx) =>
        service.assertFreshStartStepUp(tx, { ...proof }, userId, first.id, purpose),
      ),
      /AUTHENTICATION_FAILED/,
    );
    await assert.rejects(
      db.transaction((tx) =>
        service.assertFreshStartStepUp(tx, proof, userId, first.id, purpose + '-different'),
      ),
      /AUTHENTICATION_FAILED/,
    );
    await db.transaction((tx) =>
      service.assertFreshStartStepUp(tx, proof, userId, first.id, purpose),
    );
    await assert.rejects(
      db.transaction((tx) => service.assertFreshStartStepUp(tx, proof, userId, first.id, purpose)),
      /AUTHENTICATION_FAILED/,
    );
    const stale = await service.consumeStepUp(
      session.id as string,
      purpose,
      await stepUp(path, body),
    );
    assert.ok(stale);
    const old = (await db.execute(sql`SELECT password_hash FROM users WHERE id = ${userId}`))
      .rows[0].password_hash;
    try {
      await db.execute(
        sql`UPDATE users SET password_hash = 'changed-test-fixture' WHERE id = ${userId}`,
      );
      await assert.rejects(
        db.transaction((tx) =>
          service.assertFreshStartStepUp(tx, stale, userId, first.id, purpose),
        ),
        /INVALID_CREDENTIALS|AUTHENTICATION_FAILED/,
      );
    } finally {
      await db.execute(sql`UPDATE users SET password_hash = ${old} WHERE id = ${userId}`);
    }
  });
  it('establishes a standard MLS group and requires every exact-delivery acknowledgement', async () => {
    const crypto = await import('../../../client/src/services/' + 'mls-crypto.ts');
    const state = await json(await request(`/api/channels/${channelId}/key-recipients`));
    version = state.nextVersion;
    const firstPackage = await crypto.generateEpochKeyPackage(first.id);
    const secondPackage = await crypto.generateEpochKeyPackage(second.id);
    const roster: GroupKeyPackage[] = [];
    for (const [device, keys, material, auth] of [
      [first, firstKeys, firstPackage, cookie],
      [second, secondKeys, secondPackage, secondCookie],
    ] as const) {
      const pkg = {
        deviceId: device.id,
        userId,
        identityKey: device.identityKey,
        packageId: randomUUID(),
        keyPackage: material.publicPackage,
      };
      const signed = {
        ...pkg,
        signature: signature(keys.privateKey, serializeGroupKeyPackage(channelId, version, pkg)),
      };
      roster.push(signed);
      await json(
        await request(
          `/api/channels/${channelId}/mls/packages`,
          {
            version,
            packageId: pkg.packageId,
            keyPackage: pkg.keyPackage,
            signature: signed.signature,
          },
          auth,
        ),
      );
    }
    const publisher = await import('../services/mls.service.js');
    assert.equal(
      await publisher.publishKeyPackage(channelId, userId, first.id, version, {
        packageId: roster[0].packageId,
        keyPackage: roster[0].keyPackage,
        signature: signature(
          firstKeys.privateKey,
          serializeGroupKeyPackage(channelId, version, roster[0]),
        ),
      }),
      false,
      're-signing the same package must not emit another roster change',
    );
    const groupId = JSON.stringify(['alparts', channelId, version, '0'.repeat(64)]);
    const material = await crypto.createEpochGroup(
      groupId,
      firstPackage,
      roster.map((p) => p.keyPackage),
    );
    key = material.raw;
    assert.deepEqual(
      await crypto.joinEpochGroup(
        groupId,
        secondPackage,
        roster.map((p) => p.keyPackage),
        material.welcome,
      ),
      key,
    );
    commitment = hash(key).toString('base64url');
    const unsigned = {
      channelId,
      version,
      previousVersion: 0,
      previousTranscript: '0'.repeat(64),
      keyCommitment: commitment,
      welcome: material.welcome,
      commit: material.commit,
      roster,
      directoryHeads: [await head()],
      distributorDeviceId: first.id,
    };
    const epoch: MlsEpoch = {
      ...unsigned,
      signature: signature(firstKeys.privateKey, serializeMlsEpoch(unsigned)),
    };
    const encryptedKey = Buffer.from(
      JSON.stringify({
        mls: 1,
        version,
        transcript: hash(serializeMlsEpoch(epoch)).toString('hex'),
      }),
    ).toString('base64');
    const keys = roster.map((p) => ({
      deviceId: p.deviceId,
      encryptedKey,
      signature: signature(
        firstKeys.privateKey,
        serializeChannelKeyWrap({
          channelId,
          keyVersion: version,
          keyCommitment: commitment,
          recipientDeviceId: p.deviceId,
          encryptedKey,
        }),
      ),
    }));
    const keyService = await import('../services/key.service.js');
    await assert.rejects(
      keyService.proposeMlsChannelEpoch(userId, first.id, epoch, keys, 'unverified'),
      /AUTHENTICATION_FAILED/,
      'MLS fresh-start cannot be called without a server-created step-up receipt',
    );
    await json(await request(`/api/channels/${channelId}/mls/epochs`, { epoch, keys }), 201);
    assert.notEqual(
      (await request(`/api/channels/${channelId}/messages`, await encryptedMessage())).status,
      201,
      'no writes before all recipients acknowledge',
    );
    for (const [device, signing, auth] of [
      [first, firstKeys, cookie],
      [second, secondKeys, secondCookie],
    ] as const) {
      const deliveries = await json(
        await request(`/api/channels/${channelId}/keys?scope=current`, undefined, auth),
      );
      const delivery = deliveries.find((d: any) => d.version === version);
      const acknowledgement = signature(
        signing.privateKey,
        serializeChannelKeyAcknowledgement({
          deliveryId: delivery.deliveryId,
          channelId,
          keyVersion: version,
          keyCommitment: commitment,
          recipientDeviceId: device.id,
          distributorDeviceId: first.id,
          encryptedKey,
        }),
      );
      const result = await json(
        await request(
          `/api/channels/${channelId}/keys/acknowledge`,
          { deliveryId: delivery.deliveryId, signature: acknowledgement },
          auth,
        ),
      );
      assert.equal(result.status, device.id === first.id ? 'pending' : 'active');
      if (device.id === first.id)
        assert.notEqual(
          (await request(`/api/channels/${channelId}/messages`, await encryptedMessage())).status,
          201,
        );
    }
    assert.equal(
      (await json(await request(`/api/channels/${channelId}/key-recipients`))).currentVersion,
      version,
    );
    await json(await request(`/api/channels/${channelId}/messages`, await encryptedMessage()), 201);
    const { db } = await import('../db/index.js');
    const { sql } = await import('drizzle-orm');
    await db.transaction(async (tx) => {
      await keyService.lockKeyProtocol(tx);
      const channel = await tx.query.channels.findFirst({
        where: (c, { eq }) => eq(c.id, channelId),
      });
      assert.ok(channel);
      assert.equal(await keyService.isEpochRosterCurrent(tx, channel, version), true);
      await tx.execute(sql`UPDATE devices SET approved_at = NULL WHERE id = ${second.id}`);
      assert.equal(
        await keyService.isEpochRosterCurrent(tx, channel, version),
        false,
        'activation excludes unapproved recipients',
      );
      await tx.execute(
        sql`UPDATE devices SET approved_at = now(), revoked_at = now() WHERE id = ${second.id}`,
      );
      assert.equal(
        await keyService.isEpochRosterCurrent(tx, channel, version),
        false,
        'activation excludes revoked recipients',
      );
      await tx.execute(sql`UPDATE devices SET revoked_at = NULL WHERE id = ${second.id}`);
      assert.equal(await keyService.isEpochRosterCurrent(tx, channel, version), true);
    });
    await db.execute(
      sql`UPDATE channel_key_epochs SET activated_at = now() - interval '25 hours', created_at = now() - interval '25 hours' WHERE channel_id = ${channelId} AND version = ${version}`,
    );
    assert.notEqual(
      (await request(`/api/channels/${channelId}/messages`, await encryptedMessage())).status,
      201,
      'expired epochs cannot be used through a raw API request',
    );
    await db.execute(
      sql`UPDATE channel_key_epochs SET activated_at = now(), created_at = now() WHERE channel_id = ${channelId} AND version = ${version}`,
    );
    assert.notEqual(
      (
        await request(`/api/channels/${channelId}/keys`, {
          version: version + 1,
          keyCommitment: commitment,
          keys,
        })
      ).status,
      201,
      'legacy group proposal is disabled',
    );
  });
  it('lets an offline recipient fetch and acknowledge a retired delivery without reactivating it', async () => {
    const { db } = await import('../db/index.js');
    const { sql } = await import('drizzle-orm');
    await db.execute(sql`UPDATE channel_key_epochs SET status = 'retired' WHERE channel_id = ${channelId} AND version = ${version}`);
    await db.execute(sql`UPDATE channel_key_epoch_recipients SET accepted_delivery_id = NULL, acknowledged_at = NULL, acknowledgement_signature = NULL WHERE channel_id = ${channelId} AND version = ${version} AND device_id = ${second.id}`);
    try {
      const deliveries = await json(await request(`/api/channels/${channelId}/keys?version=${version}`, undefined, secondCookie));
      assert.equal(deliveries.length, 1);
      const delivery = deliveries[0];
      assert.equal(delivery.epochStatus, 'retired');
      assert.equal(delivery.confirmedAt, null);
      const result = await json(await request(`/api/channels/${channelId}/keys/acknowledge`, {
        deliveryId: delivery.deliveryId,
        signature: signature(secondKeys.privateKey, serializeChannelKeyAcknowledgement({
          deliveryId: delivery.deliveryId, distributorDeviceId: delivery.distributorDeviceId,
          channelId, keyVersion: version, keyCommitment: commitment,
          recipientDeviceId: second.id, encryptedKey: delivery.encryptedKey,
        })),
      }, secondCookie));
      assert.equal(result.status, 'retired');
      assert.equal(result.activated, false);
      assert.equal((await db.execute(sql`SELECT status FROM channel_key_epochs WHERE channel_id = ${channelId} AND version = ${version}`)).rows[0].status, 'retired');
    } finally {
      await db.execute(sql`UPDATE channel_key_epochs SET status = 'active' WHERE channel_id = ${channelId} AND version = ${version}`);
    }
  });

  it('enrolls and authenticates a passkey; rejects wrong origin, RP, missing UV and replay', async () => {
    passkey = authenticator(userId);
    const options = await json(await sensitive('/api/auth/passkeys/register/options', {}));
    await json(
      await request('/api/auth/passkeys/register/verify', {
        id: options.id,
        name: 'Test authenticator',
        response: passkey.registration(options.options.challenge),
      }),
    );
    const ceremony = await json(await request('/api/auth/passkeys/login/options', {}, ''));
    const response = passkey.assertion(ceremony.options.challenge);
    const login = await request(
      '/api/auth/passkeys/login/verify',
      { id: ceremony.id, response },
      '',
    );
    await json(login);
    assert.ok(login.headers.get('set-cookie'));
    assert.equal(
      (await request('/api/auth/passkeys/login/verify', { id: ceremony.id, response }, '')).status,
      403,
    );
    // A passkey session stops counting as a fresh assertion for enrollment.
    const { db } = await import('../db/index.js');
    const { sql } = await import('drizzle-orm');
    const agedPasskeyCookie = login.headers.get('set-cookie')!.split(';')[0];
    await db.execute(sql`UPDATE sessions SET created_at = now() - interval '11 minutes'
      WHERE user_id = ${userId} AND authentication_method = 'passkey'`);
    const agedKeys = deviceKeys();
    const agedChallenge = (await json(await request('/api/devices/challenge', {}, agedPasskeyCookie))).challenge;
    const agedEnrollment = await request('/api/devices', {
      name: 'Aged passkey session',
      identityKey: agedKeys.identityKey,
      challenge: agedChallenge,
      proof: signature(agedKeys.privateKey, serializeDeviceChallengeProof(userId, agedChallenge)),
    }, agedPasskeyCookie);
    assert.equal(agedEnrollment.status, 403);
    assert.equal(((await agedEnrollment.json()) as { error: string }).error, 'DEVICE_STEP_UP_REQUIRED');
    for (const wrong of [
      { origin: 'https://evil.example' },
      { rp: 'evil.example' },
      { uv: false },
    ]) {
      const o = await json(await request('/api/auth/passkeys/login/options', {}, ''));
      assert.equal(
        (
          await request(
            '/api/auth/passkeys/login/verify',
            {
              id: o.id,
              response: passkey.assertion(o.options.challenge, wrong),
            },
            '',
          )
        ).status,
        403,
      );
    }
    const purpose = `DELETE /api/auth/sessions ${hash('null').toString('base64url')}`;
    const step = await json(await request('/api/auth/step-up/options', { purpose }));
    assert.equal(step.passwordAllowed, false);
    assert.equal(
      (
        await request('/api/auth/step-up/verify', {
          id: step.id,
          purpose,
          password,
        })
      ).status,
      403,
    );
  });
  it('rechecks a passkey credential inside the sensitive transaction', async () => {
    const service = await import('../services/passkey.service.js');
    const { actionPurpose } = await import('./action-purpose.js');
    const { db } = await import('../db/index.js');
    const { passkeys: table } = await import('../db/schema.js');
    const { sql, eq } = await import('drizzle-orm');
    const path = `/api/channels/${channelId}/mls/epochs/fresh-start`;
    const body = { test: 'passkey' };
    const purpose = actionPurpose('POST', path, body);
    const session = (
      await db.execute(
        sql`SELECT id FROM sessions WHERE user_id = ${userId} AND device_id = ${first.id}`,
      )
    ).rows[0];
    const proof = await service.consumeStepUp(
      session.id as string,
      purpose,
      await stepUp(path, body),
    );
    assert.ok(proof);
    await db.transaction((tx) =>
      service.assertFreshStartStepUp(tx, proof, userId, first.id, purpose),
    );
    const stale = await service.consumeStepUp(
      session.id as string,
      purpose,
      await stepUp(path, body),
    );
    assert.ok(stale);
    await assert.rejects(
      db.transaction(async (tx) => {
        await tx.delete(table).where(eq(table.userId, userId));
        await service.assertFreshStartStepUp(tx, stale, userId, first.id, purpose);
      }),
      /AUTHENTICATION_FAILED/,
    );
  });
  it('backs up opaque history and requires the recovery signing key to approve a replacement', async () => {
    generation = randomUUID();
    recoveryPair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const signingKey = JSON.stringify(recoveryPair.publicKey.export({ format: 'jwk' }));
    const currentHead = await head();
    const cipher = await import('../../../client/src/services/' + 'recovery-crypto.ts');
    const code = randomBytes(32);
    const archive = await cipher.aes(code);
    const encryptedSecret = await cipher.seal(
      archive,
      Buffer.from(JSON.stringify(recoveryPair.privateKey.export({ format: 'jwk' }))),
      cipher.aad(userId, `secret:${generation}:${signingKey}`),
    );
    const decision = {
      kind: 'recovery-config' as const,
      deviceId: generation,
      identityKey: signingKey,
      actorDeviceId: first.id,
    };
    await json(
      await sensitive('/api/recovery/configure', {
        generation,
        signingKey,
        encryptedSecret,
        accessTokenHash: (await cipher.recoveryAccess(code, userId, generation)).accessTokenHash,
        head: currentHead,
        signature: signature(firstKeys.privateKey, serializeDeviceDecision(currentHead, decision)),
      }),
    );
    // An existing pre-0015 archive retains its ciphertext, but a trusted device
    // must enroll retrieval proof before pending replacements can download it.
    const { db } = await import('../db/index.js');
    const { sql } = await import('drizzle-orm');
    await db.execute(
      sql`UPDATE history_recovery SET access_token_hash = NULL WHERE user_id = ${userId}`,
    );
    assert.equal((await json(await request('/api/recovery'))).encryptedSecret, encryptedSecret);
    const upgrade = {
      generation,
      accessTokenHash: (await cipher.recoveryAccess(code, userId, generation)).accessTokenHash,
    };
    assert.equal((await request('/api/recovery/access', upgrade)).status, 428);
    await json(await sensitive('/api/recovery/access', upgrade));
    assert.equal((await json(await request('/api/recovery'))).accessConfigured, true);
    assert.equal(
      (await sensitive('/api/recovery/access', upgrade)).status,
      403,
      'a retrieval capability cannot be silently replaced',
    );
    encryptedHistory = await cipher.seal(
      archive,
      key,
      cipher.aad(userId, `${generation}:${channelId}:${version}:${commitment}`),
    );
    const originalMessage = await encryptedMessage();
    await json(
      await request('/api/recovery/keys', {
        generation,
        channelId,
        version,
        keyCommitment: commitment,
        ciphertext: encryptedHistory,
      }),
    );
    assert.equal(
      (await json(await request('/api/recovery/keys'))).keys[0].ciphertext,
      encryptedHistory,
    );
    const login = await request('/api/auth/passkeys/login/options', {}, '');
    const options = await json(login);
    const loggedIn = await request(
      '/api/auth/passkeys/login/verify',
      {
        id: options.id,
        response: passkey.assertion(options.options.challenge),
      },
      '',
    );
    await json(loggedIn);
    const replacementCookie = loggedIn.headers.get('set-cookie')!.split(';')[0];
    assert.equal(
      (await request('/api/recovery', undefined, replacementCookie)).status,
      403,
      'unbound sessions cannot retrieve encrypted secrets',
    );
    assert.equal((await request('/api/recovery/keys', undefined, replacementCookie)).status, 403);
    const replacementKeys = deviceKeys();
    const replacement = await registerDevice(replacementCookie, replacementKeys, 'Replacement');
    assert.equal(replacement.approvedAt, null);
    assert.equal((await request('/api/recovery', undefined, replacementCookie)).status, 403);
    assert.equal((await request('/api/recovery/keys', undefined, replacementCookie)).status, 403);
    const metadata = await json(
      await request('/api/recovery/metadata', undefined, replacementCookie),
    );
    assert.equal(metadata.encryptedSecret, undefined);
    const access = await cipher.recoveryAccess(code, userId, generation);
    assert.equal(
      (
        await request(
          '/api/recovery/unlock',
          { generation, token: randomBytes(32).toString('base64url') },
          replacementCookie,
        )
      ).status,
      403,
    );
    assert.equal(
      (
        await request(
          '/api/recovery/unlock',
          { generation: randomUUID(), token: access.token },
          replacementCookie,
        )
      ).status,
      403,
    );
    const unlocked = await json(
      await request('/api/recovery/unlock', { generation, token: access.token }, replacementCookie),
    );
    assert.equal(unlocked.encryptedSecret, encryptedSecret);
    assert.equal(unlocked.accessTokenHash, undefined);
    assert.equal(
      (await request('/api/recovery/keys', undefined, replacementCookie)).status,
      403,
      'retrieval proof alone does not approve a device',
    );
    const recoveryHead = await head();
    const approval = {
      kind: 'recovery' as const,
      deviceId: replacement.id,
      identityKey: replacement.identityKey,
      actorDeviceId: generation,
    };
    assert.equal(
      (
        await request(
          '/api/recovery/restore-device',
          {
            generation,
            head: recoveryHead,
            signature: signature(
              replacementKeys.privateKey,
              serializeDeviceDecision(recoveryHead, approval),
            ),
          },
          replacementCookie,
        )
      ).status,
      403,
    );
    await json(
      await request(
        '/api/recovery/restore-device',
        {
          generation,
          head: recoveryHead,
          signature: signature(
            recoveryPair.privateKey,
            serializeDeviceDecision(recoveryHead, approval),
          ),
        },
        replacementCookie,
      ),
    );
    assert.ok(
      (await json(await request('/api/devices', undefined, replacementCookie))).find(
        (d: any) => d.id === replacement.id,
      ).approvedAt,
    );
    const stored = (await json(await request('/api/recovery/keys', undefined, replacementCookie)))
      .keys[0];
    assert.equal(stored.ciphertext, encryptedHistory);
    const candidates = await json(
      await request('/api/recovery/candidates', undefined, replacementCookie),
    );
    assert.ok(
      candidates.candidates.some(
        (entry: any) => entry.channelId === channelId && entry.version === version,
      ),
      'replacement can re-archive history owned by the account',
    );
    await json(
      await request(
        '/api/recovery/keys',
        {
          generation,
          channelId,
          version,
          keyCommitment: commitment,
          ciphertext: encryptedHistory,
        },
        replacementCookie,
      ),
    );
    const recovered = await cipher.open(
      await cipher.aes(code),
      stored.ciphertext,
      cipher.aad(userId, `${generation}:${channelId}:${version}:${commitment}`),
    );
    assert.deepEqual(recovered, key);
    const messageAad = serializeMessageAad({
      ...originalMessage,
      channelId,
      authorId: userId,
      type: 'message',
      refMessageId: null,
    });
    const plain = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: Buffer.from(originalMessage.contentNonce, 'base64'),
        additionalData: new TextEncoder().encode(messageAad),
      },
      await cipher.aes(recovered),
      Buffer.from(originalMessage.encryptedContent, 'base64'),
    );
    assert.equal(new TextDecoder().decode(plain), 'recoverable message');
    await assert.rejects(
      cipher.open(
        await cipher.aes(randomBytes(32)),
        stored.ciphertext,
        cipher.aad(userId, `${generation}:${channelId}:${version}:${commitment}`),
      ),
    );
    const restoredSecret = await cipher.open(
      archive,
      encryptedSecret,
      cipher.aad(userId, `secret:${generation}:${signingKey}`),
    );
    assert.equal(
      JSON.parse(new TextDecoder().decode(restoredSecret)).d,
      recoveryPair.privateKey.export({ format: 'jwk' }).d,
    );
    const revokeHead = await head();
    const revoke = {
      kind: 'revoke' as const,
      deviceId: second.id,
      identityKey: second.identityKey,
      actorDeviceId: first.id,
    };
    await json(
      await sensitive(
        `/api/devices/${second.id}`,
        {
          head: revokeHead,
          signature: signature(firstKeys.privateKey, serializeDeviceDecision(revokeHead, revoke)),
        },
        'DELETE',
      ),
    );
    assert.equal((await request('/api/devices', undefined, secondCookie)).status, 401);
    assert.notEqual(
      (await request(`/api/channels/${channelId}/messages`, await encryptedMessage())).status,
      201,
      'revocation blocks stale epoch writes',
    );
    const recipients = await json(await request(`/api/channels/${channelId}/key-recipients`));
    assert.equal(recipients.rotationRequired, true);
    assert.equal(
      recipients.recipients.some((r: any) => r.deviceId === second.id),
      false,
    );
    const disableHead = await head();
    const disable = {
      kind: 'recovery-disable' as const,
      deviceId: generation,
      identityKey: signingKey,
      actorDeviceId: first.id,
    };
    await json(
      await sensitive(
        '/api/recovery',
        {
          head: disableHead,
          signature: signature(firstKeys.privateKey, serializeDeviceDecision(disableHead, disable)),
        },
        'DELETE',
      ),
    );
    assert.equal(await json(await request('/api/recovery')), null);
    assert.deepEqual((await json(await request('/api/recovery/keys'))).keys, []);
    const directory = await json(await request(`/api/directory/${userId}?after=0`));
    const verifier = await import('../../../client/src/services/' + 'directory-verifier.ts');
    const verified = await verifier.verifyDirectoryEntries(
      verifier.emptyDirectory(userId),
      directory.entries,
    );
    assert.equal(verified.recovery, null);
    assert.equal(verified.devices[second.id].revoked, true);
  });
  it('binds passkey recovery metadata to an enrolled authenticator without exposing the encrypted signing secret', async () => {
    const generation = randomUUID();
    const signingKey = JSON.stringify(recoveryPair.publicKey.export({ format: 'jwk' }));
    const currentHead = await head();
    const wrap = { version: 1, credentialId: passkey.id, rpId: 'localhost',
      salt: randomBytes(32).toString('base64'), ciphertext: randomBytes(60).toString('base64') };
    // The server stores opaque client ciphertext; PRF encryption/decryption is
    // exercised separately with the browser client and real Web Crypto.
    const secret = { version: 2, codeSecret: randomBytes(256).toString('base64'), passkeyWrap: wrap };
    const body = {
      generation, signingKey, encryptedSecret: JSON.stringify(secret),
      accessTokenHash: randomBytes(32).toString('hex'), head: currentHead,
      signature: signature(firstKeys.privateKey, serializeDeviceDecision(currentHead, {
        kind: 'recovery-config', deviceId: generation, identityKey: signingKey, actorDeviceId: first.id,
      })),
    };
    assert.equal((await json(await request('/api/auth/passkeys/vault'))).rpId, 'localhost');
    for (const passkeyWrap of [{ ...wrap, credentialId: randomBytes(32).toString('base64url') },
      { ...wrap, rpId: 'unrelated.example.test' }]) {
      assert.equal((await sensitive('/api/recovery/configure', {
        ...body, encryptedSecret: JSON.stringify({ ...secret, passkeyWrap }),
      })).status, 403);
    }
    assert.equal((await sensitive('/api/recovery/configure', {
      ...body, encryptedSecret: '{' + 'invalid'.repeat(20),
    })).status, 403, 'malformed client data must not become an internal server error');
    await json(await sensitive('/api/recovery/configure', body));
    const metadata = await json(await request('/api/recovery/metadata'));
    assert.deepEqual(metadata.passkeyWrap, wrap);
    assert.equal(metadata.encryptedSecret, undefined);
    assert.equal(metadata.codeSecret, undefined);
    assert.equal(metadata.accessTokenHash, undefined);
    const disableHead = await head();
    await json(await sensitive('/api/recovery', {
      head: disableHead,
      signature: signature(firstKeys.privateKey, serializeDeviceDecision(disableHead, {
        kind: 'recovery-disable', deviceId: generation, identityKey: signingKey, actorDeviceId: first.id,
      })),
    }, 'DELETE'));
  });
  it('aborts a pending roster when a visible member registers their first device', async () => {
    const { db } = await import('../db/index.js');
    const { sql } = await import('drizzle-orm');
    const channel = await db.execute(
      sql`SELECT workspace_id FROM channels WHERE id = ${channelId}`,
    );
    const workspaceId = channel.rows[0].workspace_id as string;
    const roles = await json(await request(`/api/workspaces/${workspaceId}/roles`));
    const memberRole = roles.find((role: any) => role.name === 'Member');
    const invitation = await json(
      await sensitive(`/api/workspaces/${workspaceId}/invitations`, {
        roleId: memberRole.id,
        expiresInSeconds: 3600,
      }),
      201,
    );
    const email = `first-device-${randomUUID()}@example.test`;
    const account = await json(
      await request(
        '/api/auth/register',
        {
          email,
          password,
          displayName: 'First device',
          inviteToken: invitation.token,
        },
        '',
      ),
      201,
    );
    const login = await request('/api/auth/login', { email, password }, '');
    await json(login);
    const auth = login.headers.get('set-cookie')!.split(';')[0];
    const pendingVersion = (await json(await request(`/api/channels/${channelId}/key-recipients`)))
      .nextVersion;
    // Model a proposal made while this authorized account has no devices yet.
    // It necessarily has no recipient row for the account about to register.
    await db.execute(
      sql`INSERT INTO channel_key_epochs (channel_id, version, protocol_version, status, key_commitment, distributor_device_id) VALUES (${channelId}, ${pendingVersion}, 3, 'pending', ${commitment}, ${first.id})`,
    );
    await db.execute(
      sql`INSERT INTO channel_key_epoch_recipients (channel_id, version, device_id, user_id) VALUES (${channelId}, ${pendingVersion}, ${first.id}, ${userId})`,
    );
    const keys = deviceKeys();
    const challenge = (await json(await request('/api/devices/challenge', {}, auth))).challenge;
    const device = await json(
      await request(
        '/api/devices',
        {
          name: 'New member',
          identityKey: keys.identityKey,
          challenge,
          proof: signature(keys.privateKey, serializeDeviceChallengeProof(account.id, challenge)),
          currentPassword: password,
        },
        auth,
      ),
      201,
    );
    assert.ok(device.approvedAt);
    const pending = await db.execute(
      sql`SELECT status FROM channel_key_epochs WHERE channel_id = ${channelId} AND version = ${pendingVersion}`,
    );
    assert.equal(
      pending.rows[0].status,
      'aborted',
      'a pending proposal cannot omit a newly eligible first device',
    );
  });
  it('isolates retained and in-progress attachment usage by workspace', async () => {
    const { db } = await import('../db/index.js');
    const { sql } = await import('drizzle-orm');
    const { getCiphertextUsage } = await import('../services/file.service.js');
    const ownWorkspace = String((await db.execute(sql`select workspace_id from channels where id = ${channelId}`)).rows[0].workspace_id);
    await assert.rejects(db.transaction(async (tx) => {
      const before = await getCiphertextUsage(tx, ownWorkspace, channelId, userId);
      const otherBefore = await getCiphertextUsage(tx, legacyWorkspace, legacyChannel, userId);
      const messageId = randomUUID();
      await tx.execute(sql`insert into messages (id, channel_id, author_id, device_id, type, content, content_nonce, key_version, idempotency_key, signature, broadcast_mention)
        select ${messageId}, ${legacyChannel}, author_id, device_id, type, content, content_nonce, 1, ${randomUUID()}, signature, false
        from messages where channel_id = ${channelId} and author_id = ${userId} and type = 'message' limit 1`);
      await tx.execute(sql`insert into attachments (message_id, channel_id, signer_device_id, key_version, signature, filename_enc, mime_type, size_bytes, storage_key, wrapped_key, content_nonce)
        values (${messageId}, ${legacyChannel}, ${first.id}, 1, 'test', 'test', 'application/octet-stream', 1234, ${randomUUID()}, 'test', 'test')`);
      const uploadId = randomUUID();
      await tx.execute(sql`insert into attachment_uploads (id, message_id, uploader_id, storage_key, filename_enc, mime_type, expires_at)
        values (${uploadId}, ${messageId}, ${userId}, ${randomUUID()}, 'test', 'application/octet-stream', now() + interval '1 hour')`);
      await tx.execute(sql`insert into attachment_upload_chunks (upload_id, chunk_index, size_bytes, storage_key, etag)
        values (${uploadId}, 0, 456, ${randomUUID()}, 'test')`);
      assert.deepEqual(await getCiphertextUsage(tx, ownWorkspace, channelId, userId), before);
      assert.equal((await getCiphertextUsage(tx, legacyWorkspace, legacyChannel, userId)).userBytes, otherBefore.userBytes + 1690);
      throw new Error('ROLLBACK_FIXTURE');
    }), /ROLLBACK_FIXTURE/);
  });
  it('disables an account across CLI, password, passkey and already-connected sockets', { timeout: 15_000 }, async () => {
    const { db } = await import('../db/index.js');
    const auth = await import('../services/auth.service.js');
    const { promisify } = await import('node:util');
    const { execFile } = await import('node:child_process');
    const { fileURLToPath } = await import('node:url');
    const { io } = await import('socket.io-client');
    const user = await db.query.users.findFirst({ where: (u, { eq }) => eq(u.id, userId) });
    assert.ok(user);
    const socket = io(base, { transports: ['websocket'], extraHeaders: { Cookie: cookie, Origin: origin } });
    const run = (operation: string) => promisify(execFile)(process.execPath, ['--import', 'tsx',
      fileURLToPath(new URL('../scripts/set-account-state.ts', import.meta.url)), operation, userId], { timeout: 10_000 });
    try {
      await new Promise<void>((resolve, reject) => { socket.once('connect', resolve); socket.once('connect_error', reject); });
      const disconnected = new Promise<void>((resolve) => socket.once('disconnect', () => resolve()));
      await run('disable');
      await disconnected;
      assert.equal((await request('/api/auth/me')).status, 401);
      await assert.rejects(auth.login(user.email, password), /INVALID_CREDENTIALS/);
      await assert.rejects(auth.establishSession(user, undefined, 'passkey'), /INVALID_CREDENTIALS/);
      await run('enable');
      assert.equal((await request('/api/auth/me')).status, 401, 'enable must not resurrect old sessions');
      assert.ok((await auth.login(user.email, password)).token);
      assert.equal((await (await import('../middleware/audit.js')).verifyAuditChain()).valid, true);
    } finally { socket.disconnect(); }
  });

  it('refuses a second runtime and fences replacement until admitted work drains', async () => {
    const { acquireRuntimeLease } = await import('./runtime-lease.js');
    await assert.rejects(acquireRuntimeLease(), /RUNTIME_ALREADY_ACTIVE/);
    await runtime.check();
    let admitted!: () => void;
    let release!: () => void;
    const ready = new Promise<void>((resolve) => {
      admitted = resolve;
    });
    const drain = new Promise<void>((resolve) => {
      release = resolve;
    });
    const previous = runtime;
    const operation = previous.fence(async () => {
      admitted();
      await drain;
    });
    await ready;
    await admin.query(
      "select pg_terminate_backend(pid) from pg_stat_activity where datname = $1 and application_name = 'alparts-runtime-lease'",
      [databaseName],
    );
    await assert.rejects(previous.check(), /RUNTIME_LEASE_LOST/);
    const replacement = acquireRuntimeLease();
    try {
      let waiting = false;
      for (let attempt = 0; attempt < 100; attempt++) {
        const row = await admin.query(
          "select 1 from pg_locks where locktype = 'advisory' and objid = 1095520342 and not granted",
        );
        if (row.rows.length) {
          waiting = true;
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      assert.equal(waiting, true, 'replacement must wait through the old checkpoint boundary');
    } finally {
      release();
    }
    await operation;
    runtime = await replacement;
    await runtime.check();
    await assert.rejects(
      previous.fence(async () => undefined),
      /RUNTIME_LEASE_LOST/,
    );
    await previous.close();
  });
});
