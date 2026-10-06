// Real-service checks for assumptions omitted by the bounded Python models.
// Requires a disposable PostgreSQL administrator URL and a disposable S3-compatible bucket.
// Creates and drops its OWN uniquely named database. Does not alter the input database.
// Exit 1 means a claimed property has a counterexample; fixtures/setup errors exit 2.
import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { crc32, deflateSync } from 'node:zlib';

const server = fileURLToPath(new URL('../../packages/server/', import.meta.url));
const require = createRequire(join(server, 'package.json'));
const pg = require('pg');
const { eq } = require('drizzle-orm');
const { Permissions: P } = require('@alparts/shared');
assert.equal(process.env.RUN_FORMAL_CONFORMANCE, '1', 'Set RUN_FORMAL_CONFORMANCE=1 for this disposable integration audit');
assert.match(new URL(process.env.DATABASE_URL!).pathname, /^\/alparts_(?:security_)?test(?:_\w+)?$/);
assert.equal(process.env.NODE_ENV, 'test');
const admin = new pg.Client({ connectionString: process.env.DATABASE_URL });
const databaseName = `alparts_security_test_formal_${randomUUID().replaceAll('-', '')}`;
const directory = await mkdtemp(join(tmpdir(), 'alparts-formal-services-'));
const checks: Array<{ id: string; title: string; verdict: string; detail?: string }> = [];
let closeDb: (() => Promise<void>) | undefined;
let cleanupObjects: (() => Promise<void>) | undefined;
let closeRuntime: (() => Promise<void>) | undefined;

// Two valid PNG encodings of the same solid RGBA pixels: filter None and Sub.
// Sub stores the first pixel and zero deltas for every remaining pixel.
function samePixelsPng(filter: 0 | 1, red = 60): Buffer {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const chunk = (type: string, data: Buffer) => {
    const result = Buffer.alloc(data.length + 12);
    result.writeUInt32BE(data.length);
    result.write(type, 4);
    data.copy(result, 8);
    result.writeUInt32BE(crc32(data, crc32(Buffer.from(type))), data.length + 8);
    return result;
  };
  const header = Buffer.alloc(13);
  header.writeUInt32BE(256, 0); header.writeUInt32BE(256, 4); header[8] = 8; header[9] = 6;
  const raw = Buffer.alloc(256 * 1025);
  for (let y = 0; y < 256; y++) {
    const row = y * 1025;
    raw[row] = filter;
    for (let x = 0; x < (filter === 0 ? 256 : 1); x++) Buffer.from([red, 90, 120, 255]).copy(raw, row + 1 + x * 4);
  }
  return Buffer.concat([signature, chunk('IHDR', header), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}

async function check(id: string, title: string, body: () => Promise<void> | void) {
  try {
    await body();
    checks.push({ id, title, verdict: 'PASS' });
  } catch (error) {
    if (!(error instanceof assert.AssertionError)) throw error;
    checks.push({ id, title, verdict: 'FINDING', detail: error.message });
  }
  console.log(JSON.stringify(checks.at(-1)));
}

try {
  await admin.connect();
  await admin.query(`CREATE DATABASE ${databaseName}`);
  const url = new URL(process.env.DATABASE_URL!);
  url.pathname = '/' + databaseName;
  process.env.DATABASE_URL = url.toString();
  process.env.AUDIT_CHECKPOINT_PATH = join(directory, 'checkpoint.json');
  process.env.AUDIT_CHECKPOINT_REQUIRED = 'true';
  process.env.AUDIT_HEAD_OBJECT_KEY = `test-${randomUUID()}`;
  const migrated = spawnSync(process.execPath, ['--import', './node_modules/tsx/dist/loader.mjs', 'src/scripts/migrate-runtime.ts'], {
    cwd: server, env: process.env, encoding: 'utf8', timeout: 60_000,
  });
  if (migrated.status !== 0) throw new Error(`fixture migration failed: ${migrated.stderr}`);
  const database = await import('../../packages/server/src/db/index.ts');
  closeDb = database.closeDb;
  const { db } = database;
  const schema = await import('../../packages/server/src/db/schema.ts');
  const authz = await import('../../packages/server/src/services/authorization.service.ts');
  const channels = await import('../../packages/server/src/services/channel.service.ts');
  const profiles = await import('../../packages/server/src/services/profile.service.ts');
  const roles = await import('../../packages/server/src/services/role.service.ts');
  const audit = await import('../../packages/server/src/middleware/audit.ts');
  const { sanitizeAvatarPng } = await import('../../packages/server/src/security/profile-input.ts');
  const storage = await import('../../packages/server/src/services/object-storage.ts');
  cleanupObjects = async () => {
    for (const user of await db.query.users.findMany({ columns: { avatarObjectKey: true } })) {
      if (user.avatarObjectKey) await storage.removeStoredObjectBestEffort(user.avatarObjectKey);
    }
  };
  await audit.provisionAuditCheckpoint();

  async function fixture() {
    const owner = randomUUID(), superior = randomUUID(), manager = randomUUID(), subject = randomUUID();
    for (const id of [owner, superior, manager, subject]) {
      await db.insert(schema.users).values({ id, email: id + '@formal.invalid', passwordHash: 'disabled-test-fixture', displayName: 'Original' });
    }
    const workspaceId = randomUUID();
    await db.insert(schema.workspaces).values({ id: workspaceId, name: 'Formal audit', ownerId: owner });
    const ownerRole = randomUUID(), highRole = randomUUID(), lowRole = randomUUID(), memberRole = randomUUID();
    await db.insert(schema.roles).values([
      { id: ownerRole, workspaceId, name: 'Owner', position: 100, permissions: roles.ALL_PERMISSION_MASK },
      { id: highRole, workspaceId, name: 'Higher', position: 90, permissions: P.VIEW_CHANNELS | P.SEND_MESSAGES },
      { id: lowRole, workspaceId, name: 'Manager', position: 60, permissions: P.VIEW_CHANNELS | P.SEND_MESSAGES | P.MANAGE_CHANNELS | P.MANAGE_ROLES | P.MANAGE_MEMBERS },
      { id: memberRole, workspaceId, name: 'Lower', position: 10, permissions: P.VIEW_CHANNELS | P.SEND_MESSAGES },
    ]);
    for (const [userId, roleId] of [[owner, ownerRole], [superior, highRole], [manager, lowRole], [subject, memberRole]]) {
      const [member] = await db.insert(schema.workspaceMembers).values({ workspaceId, userId }).returning();
      await db.insert(schema.memberRoles).values({ memberId: member.id, roleId });
    }
    const channelId = randomUUID();
    await db.insert(schema.channels).values({ id: channelId, workspaceId, name: 'public', type: 'text', isPrivate: false });
    return { owner, superior, manager, subject, workspaceId, channelId, highRole, lowRole, memberRole };
  }

  await check('M2c-guard', 'The real hierarchy guard rejects loss for a superior and accepts loss for a lower member', async () => {
    const f = await fixture();
    const before = await authz.loadWorkspaceAuthorizationSnapshot(db, f.workspaceId);
    assert.ok(before);
    const mutation = (roleId: string) => ({ channelOverrideMutation: { roleId, allowMask: 0, denyMask: P.VIEW_CHANNELS } });
    assert.throws(() => authz.assertNoSuperiorAccessLoss(before, before, f.manager, mutation(f.highRole)), /MEMBER_HIERARCHY/);
    assert.doesNotThrow(() => authz.assertNoSuperiorAccessLoss(before, before, f.manager, mutation(f.memberRole)));
    assert.doesNotThrow(() => authz.assertNoSuperiorAccessLoss(before, before, f.owner, mutation(f.highRole)));
  });

  await check('M2c-private-remove', 'Removing a superior from an existing private channel is refused', async () => {
    const f = await fixture();
    await db.update(schema.channels).set({ isPrivate: true }).where(eq(schema.channels.id, f.channelId));
    await db.insert(schema.channelMembers).values([f.owner, f.superior, f.manager].map(userId => ({ channelId: f.channelId, userId })));
    await assert.rejects(channels.removeChannelMember(f.channelId, f.superior, f.manager), /MEMBER_HIERARCHY/);
  });

  await check('M2c-privacy', 'Changing privacy preserves the owner and superior access claimed by H2/H3', async () => {
    const f = await fixture();
    try { await channels.updateChannel(f.channelId, { isPrivate: true }, f.manager); }
    catch (error) {
      if (error instanceof Error && error.message === 'MEMBER_HIERARCHY') return;
      throw error;
    }
    const owner = await authz.getChannelAuthorization(f.owner, f.channelId);
    const superior = await authz.getChannelAuthorization(f.superior, f.channelId);
    assert.ok(authz.isVisibleChannelAuthorization(owner) && authz.isVisibleChannelAuthorization(superior),
      'Lower manager made a public channel private; both owner and superior lost visibility.');
  });

  await check('M2c-category-move', 'Moving categories preserves superior access claimed by H2', async () => {
    const f = await fixture();
    const categoryId = randomUUID();
    await db.insert(schema.categories).values({ id: categoryId, workspaceId: f.workspaceId, name: 'Restricted' });
    await db.insert(schema.categoryRolePermissionOverrides).values({ workspaceId: f.workspaceId, categoryId, roleId: f.highRole, allowMask: 0, denyMask: P.VIEW_CHANNELS });
    assert.ok(authz.isVisibleChannelAuthorization(await authz.getChannelAuthorization(f.superior, f.channelId)));
    try { await channels.updateChannel(f.channelId, { categoryId }, f.manager); }
    catch (error) {
      if (error instanceof Error && error.message === 'MEMBER_HIERARCHY') return;
      throw error;
    }
    assert.ok(authz.isVisibleChannelAuthorization(await authz.getChannelAuthorization(f.superior, f.channelId)),
      'Lower manager moved a channel to a category denying the superior VIEW_CHANNELS.');
  });

  await check('M2c-deletions', 'Channel/category deletion cannot remove superior permissions; owner operations still succeed', async () => {
    const f = await fixture();
    await assert.rejects(channels.deleteChannel(f.channelId, f.manager), /MEMBER_HIERARCHY/);
    assert.ok(await db.query.channels.findFirst({ where: eq(schema.channels.id, f.channelId) }));
    const categoryId = randomUUID();
    await db.insert(schema.categories).values({ id: categoryId, workspaceId: f.workspaceId, name: 'Granted' });
    await db.insert(schema.categoryRolePermissionOverrides).values({ workspaceId: f.workspaceId, categoryId,
      roleId: f.highRole, allowMask: P.ATTACH_FILES, denyMask: 0 });
    await channels.updateChannel(f.channelId, { categoryId }, f.owner);
    const before = await authz.getChannelAuthorization(f.superior, f.channelId);
    assert.ok(before!.permissions & P.ATTACH_FILES);
    await assert.rejects(channels.deleteCategory(f.workspaceId, categoryId, f.manager), /MEMBER_HIERARCHY/);
    await assert.rejects(channels.updateChannel(f.channelId, { categoryId: null }, f.manager), /MEMBER_HIERARCHY/);
    const after = await authz.getChannelAuthorization(f.superior, f.channelId);
    assert.equal(after!.permissions, before!.permissions, 'refused changes must roll back');
    await channels.updateChannel(f.channelId, { name: 'Renamed safely' }, f.manager);
    await channels.deleteCategory(f.workspaceId, categoryId, f.owner);
    await channels.deleteChannel(f.channelId, f.owner);
    assert.equal(await db.query.channels.findFirst({ where: eq(schema.channels.id, f.channelId) }), undefined);
  });

  await check('M1c-validation-width', 'Service mask validators reject integers with bits above the 32-bit model domain', () => {
    const accepted: string[] = [];
    for (const value of [2 ** 32, 2 ** 32 + P.VIEW_CHANNELS, 2 ** 40]) {
      for (const [name, validate] of [['role', roles.assertValidPermissionMask], ['override', authz.assertValidChannelOverrideMask]] as const) {
        try { validate(value); accepted.push(`${name}:${value}`); } catch { /* rejected */ }
      }
    }
    assert.deepEqual(accepted, [], 'Out-of-domain integers accepted by service helpers; HTTP schemas separately cap values at 0x7fffffff');
  });

  async function register(userId: string) {
    const shared = await import('../../packages/shared/src/index.ts');
    const deviceService = await import('../../packages/server/src/services/device.service.ts');
    const authService = await import('../../packages/server/src/services/auth.service.ts');
    const encryption = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const signing = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const encryptionKey = { ...encryption.publicKey.export({ format: 'jwk' }), alg: 'RSA-OAEP-256', ext: true, key_ops: ['encrypt'] };
    const signingKey = { ...signing.publicKey.export({ format: 'jwk' }), alg: 'ES256', ext: true, key_ops: ['verify'] };
    const identityKey = JSON.stringify({ version: 1, encryptionKey, signingKey });
    const signText = (text: string) => sign('sha256', Buffer.from(text), { key: signing.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
    const user = await db.query.users.findFirst({ where: eq(schema.users.id, userId) });
    assert.ok(user);
    const authentication = await authService.establishSession(user, undefined, 'passkey');
    const session = await db.query.sessions.findFirst({ where: eq(schema.sessions.tokenHash, createHash('sha256').update(authentication.token).digest('hex')) });
    assert.ok(session);
    const challenge = deviceService.issueDeviceChallenge(userId, session.id);
    const { device } = await deviceService.registerDevice(userId, session.id, 'Formal device', identityKey, challenge,
      signText(shared.serializeDeviceChallengeProof(userId, challenge)));
    return { ...device, signText, cookie: `alparts_session=${authentication.token}` };
  }

  await check('M3c-orphan-proposal', 'A non-manager without the active key must use the fresh-start path, as M3 and canRotate require', async () => {
    const f = await fixture();
    const shared = await import('../../packages/shared/src/index.ts');
    const keyService = await import('../../packages/server/src/services/key.service.ts');
    const mlsService = await import('../../packages/server/src/services/mls.service.ts');
    const { directoryHead } = await import('../../packages/server/src/services/directory.service.ts');
    const crypto = await import('../../packages/client/src/services/mls-crypto.ts');
    const old = await register(f.owner);
    const sender = await register(f.subject);
    // A migrated active epoch whose sole original holder later loses visibility.
    await db.insert(schema.channelKeyEpochs).values({ channelId: f.channelId, version: 1, protocolVersion: 2, status: 'active', keyCommitment: 'a'.repeat(43), distributorDeviceId: old.id, activatedAt: new Date() });
    await db.insert(schema.channelKeyEpochRecipients).values({ channelId: f.channelId, version: 1, deviceId: old.id, userId: f.owner });
    const [delivery] = await db.insert(schema.channelKeys).values({ channelId: f.channelId, version: 1, deviceId: old.id, encryptedKey: 'legacy-test-fixture', distributorDeviceId: old.id, signature: 'legacy-test-fixture' }).returning();
    await db.update(schema.channelKeyEpochRecipients).set({ acceptedDeliveryId: delivery.id, acknowledgementSignature: 'legacy-test-fixture', acknowledgedAt: new Date() }).where(eq(schema.channelKeyEpochRecipients.channelId, f.channelId));
    await channels.updateChannel(f.channelId, { isPrivate: true }, f.owner);
    await channels.addChannelMember(f.channelId, f.subject, f.owner);
    await channels.removeChannelMember(f.channelId, f.owner, f.owner);
    const state = await keyService.getKeyRecipients(f.channelId, f.subject, sender.id);
    assert.equal(state.historyRecoveryRequired, true);
    assert.equal(state.canRotate, false);
    assert.deepEqual(state.recipients.map(r => r.deviceId), [sender.id]);
    const material = await crypto.generateEpochKeyPackage(sender.id);
    const pkg = { deviceId: sender.id, userId: f.subject, identityKey: sender.identityKey, packageId: randomUUID(), keyPackage: material.publicPackage };
    const signedPackage = { ...pkg, signature: sender.signText(shared.serializeGroupKeyPackage(f.channelId, 2, pkg)) };
    await mlsService.publishKeyPackage(f.channelId, f.subject, sender.id, 2, signedPackage);
    const context = { channelId: f.channelId, version: 2, previousVersion: 1, previousTranscript: '0'.repeat(64) };
    const group = await crypto.createEpochGroup(JSON.stringify(['alparts', f.channelId, 2, context.previousTranscript]), material, [pkg.keyPackage]);
    const keyCommitment = createHash('sha256').update(group.raw).digest('base64url');
    const unsigned = { ...context, keyCommitment, roster: [signedPackage], directoryHeads: [await directoryHead(db, f.subject)], distributorDeviceId: sender.id, welcome: group.welcome, commit: group.commit };
    const epoch = { ...unsigned, signature: sender.signText(shared.serializeMlsEpoch(unsigned)) };
    const transcript = createHash('sha256').update(shared.serializeMlsEpoch(epoch)).digest('hex');
    const encryptedKey = Buffer.from(JSON.stringify({ mls: 1, version: 2, transcript })).toString('base64');
    const keys = [{ deviceId: sender.id, encryptedKey, signature: sender.signText(shared.serializeChannelKeyWrap({ channelId: f.channelId, keyVersion: 2, keyCommitment, recipientDeviceId: sender.id, encryptedKey })) }];
    const runtime = await (await import('../../packages/server/src/security/runtime-lease.ts')).acquireRuntimeLease();
    closeRuntime = () => runtime.close();
    const { httpServer } = (await import('../../packages/server/src/app.ts')).createApp();
    try {
      await new Promise<void>(resolve => httpServer.listen(0, '127.0.0.1', resolve));
      const address = httpServer.address() as import('node:net').AddressInfo;
      const response = await fetch(`http://127.0.0.1:${address.port}/api/channels/${f.channelId}/mls/epochs`, {
        method: 'POST', headers: { Cookie: sender.cookie, Origin: 'http://localhost:5173', 'Content-Type': 'application/json' },
        body: JSON.stringify({ epoch, keys }), signal: AbortSignal.timeout(10_000),
      });
      const body = await response.json();
      if (![201, 403].includes(response.status)) throw new Error(`unexpected HTTP fixture response ${response.status}: ${JSON.stringify(body)}`);
      assert.equal(response.status, 403,
        'canRotate=false, but POST /mls/epochs returned 201 for a non-holder/non-manager without fresh-start proof or manager notification');
    } finally {
      httpServer.closeAllConnections();
      await new Promise<void>(resolve => httpServer.close(() => resolve()));
    }
  });

  await check('M2c-http-hierarchy', 'Channel and category HTTP routes return 403 for superior-access loss and accept harmless edits', async () => {
    const f = await fixture();
    const { hashPassword } = await import('../../packages/server/src/security/password-work.ts');
    const { actionPurpose } = await import('../../packages/server/src/security/action-purpose.ts');
    const { isSensitiveRequest } = await import('../../packages/shared/src/index.ts');
    const password = randomUUID() + randomUUID();
    await db.update(schema.users).set({ passwordHash: await hashPassword(password, 12) }).where(eq(schema.users.id, f.manager));
    const manager = await register(f.manager);
    const categoryId = randomUUID();
    await db.insert(schema.categories).values({ id: categoryId, workspaceId: f.workspaceId, name: 'Granted' });
    await db.insert(schema.categoryRolePermissionOverrides).values({ workspaceId: f.workspaceId, categoryId,
      roleId: f.highRole, allowMask: P.ATTACH_FILES, denyMask: 0 });
    await channels.updateChannel(f.channelId, { categoryId }, f.owner);
    const { httpServer } = (await import('../../packages/server/src/app.ts')).createApp();
    try {
      await new Promise<void>(resolve => httpServer.listen(0, '127.0.0.1', resolve));
      const address = httpServer.address() as import('node:net').AddressInfo;
      for (const [method, path, body, expected] of [
        ['PUT', `/channels/${f.channelId}`, { isPrivate: true }, 403],
        ['PUT', `/channels/${f.channelId}`, { categoryId: null }, 403],
        ['DELETE', `/channels/${f.channelId}`, undefined, 403],
        ['DELETE', `/workspaces/${f.workspaceId}/categories/${categoryId}`, undefined, 403],
        ['PUT', `/channels/${f.channelId}`, { name: 'Safe rename' }, 200],
      ] as const) {
        const headers: Record<string, string> = { Cookie: manager.cookie, Origin: 'http://localhost:5173', 'Content-Type': 'application/json' };
        if (isSensitiveRequest(method, `/api${path}`, body)) {
          const purpose = actionPurpose(method, `/api${path}`, body);
          const options = await fetch(`http://127.0.0.1:${address.port}/api/auth/step-up/options`, {
            method: 'POST', headers, body: JSON.stringify({ purpose }), signal: AbortSignal.timeout(10_000),
          });
          const challenge = await options.json() as { id: string; error?: string };
          assert.equal(options.status, 200, challenge.error ?? 'Step-up options should be available');
          const verified = await fetch(`http://127.0.0.1:${address.port}/api/auth/step-up/verify`, {
            method: 'POST', headers, body: JSON.stringify({ id: challenge.id, purpose, password }), signal: AbortSignal.timeout(10_000),
          });
          assert.equal(verified.status, 200);
          headers['X-Alparts-Step-Up'] = (await verified.json() as { token: string }).token;
        }
        const response = await fetch(`http://127.0.0.1:${address.port}/api${path}`, {
          method, headers,
          body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(10_000),
        });
        const output = await response.json() as { error?: string };
        assert.equal(response.status, expected, `${method} ${path}: ${JSON.stringify(output)}`);
        if (expected === 403) assert.equal(output.error, 'MEMBER_HIERARCHY');
      }
    } finally {
      httpServer.closeAllConnections();
      await new Promise<void>(resolve => httpServer.close(() => resolve()));
    }
  });

  await check('M6c-noop', 'A sequential unchanged save does not permit a clearing request', async () => {
    const f = await fixture();
    await profiles.flagProfile(f.workspaceId, f.owner, f.subject);
    await profiles.updateProfile(f.subject, { displayName: 'Original' });
    await assert.rejects(profiles.requestProfileAppeal(f.workspaceId, f.subject), /PROFILE_APPEAL_NEEDS_CHANGE/);
  });

  // Delay only a real completed preflight SELECT. All writes, transaction locks,
  // audit commits and subsequent reads execute unchanged against PostgreSQL.
  async function holdPreflight(columns: string[], body: (read: Promise<void>, release: () => void) => Promise<void>) {
    const query = db.query.users;
    const original = query.findFirst;
    let held = false;
    let release!: () => void, observed!: () => void;
    const paused = new Promise<void>(resolve => { release = resolve; });
    const read = new Promise<void>(resolve => { observed = resolve; });
    query.findFirst = (async function(this: typeof query, options: any) {
      const row = await original.call(this, options);
      if (!held && columns.every(column => options?.columns?.[column])) {
        held = true;
        observed();
        await paused;
      }
      return row;
    }) as typeof original;
    try { await body(read, release); } finally { release(); query.findFirst = original; }
  }

  await check('M6c-concurrent-noop', 'An in-flight unchanged save cannot bypass the change-after-warning requirement A3', async () => {
    const f = await fixture();
    await holdPreflight(['displayName', 'bio'], async (read, release) => {
      const pending = profiles.updateProfile(f.subject, { displayName: 'Changed before warning' });
      try {
        await read;
        await profiles.updateProfile(f.subject, { displayName: 'Changed before warning' });
        await profiles.flagProfile(f.workspaceId, f.owner, f.subject);
        await assert.rejects(profiles.requestProfileAppeal(f.workspaceId, f.subject), /PROFILE_APPEAL_NEEDS_CHANGE/);
        await delay(5);
      } finally { release(); }
      await pending;
    });
    await assert.rejects(profiles.requestProfileAppeal(f.workspaceId, f.subject), /PROFILE_APPEAL_NEEDS_CHANGE/,
      'The second save wrote identical content after the warning and incorrectly advanced profileUpdatedAt');
  });

  for (const action of ['save', 'remove'] as const) {
    await check(`M6c-concurrent-avatar-${action}`, `Concurrent avatar ${action} must recheck the locked current picture`, async () => {
      const f = await fixture();
      if (action === 'remove') await profiles.setAvatar(f.subject, samePixelsPng(0));
      const operation = () => action === 'remove' ? profiles.removeAvatar(f.subject) : profiles.setAvatar(f.subject, samePixelsPng(1));
      await holdPreflight(['avatarObjectKey'], async (read, release) => {
        const pending = operation();
        try {
          await read;
          await operation();
          await profiles.flagProfile(f.workspaceId, f.owner, f.subject);
          await delay(5);
        } finally { release(); }
        await pending;
      });
      await assert.rejects(profiles.requestProfileAppeal(f.workspaceId, f.subject), /PROFILE_APPEAL_NEEDS_CHANGE/);
    });
  }

  await check('M6c-global-once', 'Concurrent requests in two workspaces still consume only one account allowance', async () => {
    const f = await fixture();
    const second = randomUUID();
    await db.insert(schema.workspaces).values({ id: second, name: 'Second', ownerId: f.owner });
    await db.insert(schema.workspaceMembers).values([f.owner, f.subject].map(userId => ({ workspaceId: second, userId })));
    await profiles.flagProfile(f.workspaceId, f.owner, f.subject);
    await profiles.flagProfile(second, f.owner, f.subject);
    await delay(5);
    await profiles.updateProfile(f.subject, { bio: 'Changed after both warnings' });
    const results = await Promise.allSettled([profiles.requestProfileAppeal(f.workspaceId, f.subject), profiles.requestProfileAppeal(second, f.subject)]);
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
    assert.match((results.find(result => result.status === 'rejected') as PromiseRejectedResult).reason.message, /PROFILE_APPEAL_USED/);
  });

  await check('M6c-png-canonical', 'Equal decoded pixels give equal sanitized bytes, as the sanitizer contract claims', () => {
    const none = sanitizeAvatarPng(samePixelsPng(0));
    const sub = sanitizeAvatarPng(samePixelsPng(1));
    assert.ok(none.equals(sub), 'PNG None/Sub filters describe identical pixels but survive sanitization as different bytes');
  });

  await check('M6c-same-pixels', 'Re-encoding the unchanged picture cannot enable a clearing request', async () => {
    const f = await fixture();
    await profiles.setAvatar(f.subject, samePixelsPng(0));
    await profiles.flagProfile(f.workspaceId, f.owner, f.subject);
    await profiles.setAvatar(f.subject, samePixelsPng(0));
    await assert.rejects(profiles.requestProfileAppeal(f.workspaceId, f.subject), /PROFILE_APPEAL_NEEDS_CHANGE/);
    await delay(5);
    await profiles.setAvatar(f.subject, samePixelsPng(1));
    await assert.rejects(profiles.requestProfileAppeal(f.workspaceId, f.subject), /PROFILE_APPEAL_NEEDS_CHANGE/,
      'Changing only the PNG row filter counted as changing the picture after the warning');
  });

  await check('M6c-legacy-avatar', 'Existing noncanonical PNGs compare by pixels; actual picture edits remain possible', async () => {
    const f = await fixture();
    await profiles.setAvatar(f.subject, samePixelsPng(0));
    const user = await db.query.users.findFirst({ where: eq(schema.users.id, f.subject) });
    await storage.putStoredObject(user!.avatarObjectKey!, samePixelsPng(1));
    await profiles.flagProfile(f.workspaceId, f.owner, f.subject);
    await profiles.setAvatar(f.subject, samePixelsPng(0));
    await assert.rejects(profiles.requestProfileAppeal(f.workspaceId, f.subject), /PROFILE_APPEAL_NEEDS_CHANGE/);
    await profiles.setAvatar(f.subject, samePixelsPng(0, 140));
    await profiles.requestProfileAppeal(f.workspaceId, f.subject);
  });

  await check('M6c-ambiguous-commit', 'A committed upload remains readable after the caller receives a transaction error', async () => {
    const f = await fixture();
    const original = db.transaction;
    let injected = false;
    db.transaction = (async function(this: typeof db, ...args: any[]) {
      const result = await (original as any).apply(this, args);
      if (!injected && result && typeof result === 'object' && 'checkpoint' in result) {
        injected = true;
        throw new Error('injected acknowledgement loss AFTER COMMIT');
      }
      return result;
    }) as typeof original;
    try {
      const result = await profiles.setAvatar(f.subject, samePixelsPng(0));
      assert.ok(injected, 'fault injection must actually fire');
      const image = await profiles.readAvatar(f.subject, f.subject, result.avatarUrl.split('/').at(-1)!);
      assert.ok(image);
      assert.ok(image.equals(sanitizeAvatarPng(samePixelsPng(0))));
    } finally { db.transaction = original; }
  });

  function freshVerification(initialize = false) {
    const source = `const a=await import(${JSON.stringify(new URL('../../packages/server/src/middleware/audit.ts', import.meta.url).href)}); const d=await import(${JSON.stringify(new URL('../../packages/server/src/db/index.ts', import.meta.url).href)}); try { ${initialize ? 'await a.provisionAuditHead();' : ''} console.log(JSON.stringify(await a.verifyAuditChain())); } catch (e) { if (e?.name !== 'AuditCheckpointIntegrityError') throw e; console.log(JSON.stringify({valid:false, error:e.message})); } finally { await d.closeDb(); }`;
    const restarted = spawnSync(process.execPath, ['--import', './node_modules/tsx/dist/loader.mjs', '--input-type=module', '-e', source], {
      cwd: server, env: process.env, encoding: 'utf8', timeout: 30_000,
    });
    if (restarted.status !== 0) throw new Error(`restart fixture failed: ${restarted.stderr}`);
    return JSON.parse(restarted.stdout.trim());
  }
  const { config } = await import('../../packages/server/src/config/index.ts');
  const { S3Client, DeleteObjectCommand } = require('@aws-sdk/client-s3');
  const objectClient = new S3Client({
    endpoint: storage.objectStorageEndpoint(config.s3.endpoint, config.s3.port, config.s3.useSSL),
    region: config.s3.region, forcePathStyle: true, maxAttempts: 1,
    credentials: { accessKeyId: config.s3.accessKey, secretAccessKey: config.s3.secretKey },
  });
  const objectAdmin = {
    removeObject: (bucket: string, key: string) => objectClient.send(new DeleteObjectCommand({ Bucket: bucket, Key: key })),
  };
  await check('M5c-concurrent-checks', 'Concurrent readiness/full verification and appends never report a false rollback', async () => {
    for (let batch = 0; batch < 3; batch++) {
      await Promise.all(Array.from({ length: 4 }, async (_, i) => {
        await audit.audit({ action: `formal.concurrent.${batch}.${i}`, targetType: 'system' });
      }).concat(Array.from({ length: 4 }, async () => {
        await audit.checkAuditCheckpoint();
        assert.equal((await audit.verifyAuditChain()).valid, true);
      })));
    }
  });
  await check('M5c-head-write-failure', 'A head write failure preserves the committed result, blocks subsequent writes, and recovers on restart', async () => {
    const previous = await storage.readStoredAuditHead();
    const source = `
      import http from 'node:http';
      import { syncBuiltinESMExports } from 'node:module';
      const original = http.request;
      let injected = false;
      http.request = function(...args) {
        const outgoing = original.apply(this, args);
        if (outgoing.method === 'PUT' && outgoing.path.split('?')[0] === ${JSON.stringify('/' + config.audit.headBucket + '/' + config.audit.headObjectKey)}) {
          injected = true;
          queueMicrotask(() => outgoing.destroy(new Error('INJECTED_AUDIT_HEAD_WRITE_FAILURE')));
        }
        return outgoing;
      };
      syncBuiltinESMExports();
      const a = await import(${JSON.stringify(new URL('../../packages/server/src/middleware/audit.ts', import.meta.url).href)});
      const d = await import(${JSON.stringify(new URL('../../packages/server/src/db/index.ts', import.meta.url).href)});
      try {
        const committed = await a.auditedTransaction(async () => 'committed-once', () => ({ action: 'formal.head.io.failure', targetType: 'system' }));
        let ran = false, denied = false;
        try { await a.auditedTransaction(async () => { ran = true; }, () => ({ action: 'formal.head.must.not.commit' })); }
        catch(e) { if (!(e instanceof a.AuditUnavailableError)) throw e; denied = true; }
        console.log(JSON.stringify({ committed, injected, ran, denied }));
      } finally { await d.closeDb(); }
    `;
    const child = spawnSync(process.execPath, ['--import', './node_modules/tsx/dist/loader.mjs', '--input-type=module', '-e', source], {
      cwd: server, env: process.env, encoding: 'utf8', timeout: 30_000,
    });
    if (child.status !== 0) throw new Error(`write-failure fixture failed: ${child.stderr}`);
    assert.deepEqual(JSON.parse(child.stdout.trim()), { committed: 'committed-once', injected: true, ran: false, denied: true });
    assert.equal(await storage.readStoredAuditHead(), previous);
    assert.equal(freshVerification().valid, true);
    assert.equal(JSON.parse((await storage.readStoredAuditHead())!).logId,
      JSON.parse(await readFile(process.env.AUDIT_CHECKPOINT_PATH!, 'utf8')).logId);
  });
  await check('M5c-restart-control', 'An unchanged durable audit chain verifies after a real process restart', () => {
    assert.equal(freshVerification().valid, true);
  });
  await check('M5c-head-missing', 'Startup refuses a missing durable head without silently provisioning it', async () => {
    const original = await storage.readStoredAuditHead();
    assert.ok(original);
    await objectAdmin.removeObject(config.audit.headBucket, config.audit.headObjectKey!);
    try {
      const result = freshVerification();
      assert.equal(result.valid, false);
      assert.match(result.error, /durable audit head is missing/);
      assert.equal(await storage.readStoredAuditHead(), null);
      assert.equal(freshVerification(true).valid, true, 'explicit stopped-server upgrade is available');
    } finally { await storage.writeStoredAuditHead(original); }
  });
  await check('M5c-head-legacy-upgrade', 'The explicit head initializer upgrades an authenticated v1 checkpoint without losing its anchor', async () => {
    const path = process.env.AUDIT_CHECKPOINT_PATH!;
    const original = await readFile(path, 'utf8');
    const originalHead = (await storage.readStoredAuditHead())!;
    const current = JSON.parse(original);
    const unsigned = { version: 1, logId: current.logId, logHash: current.logHash, updatedAt: current.updatedAt };
    const canonical = JSON.stringify(Object.fromEntries(Object.entries(unsigned).sort(([a], [b]) => a.localeCompare(b))));
    const signature = createHmac('sha256', config.audit.integrityKey).update('alparts-audit-checkpoint-v1\0').update(canonical).digest('hex');
    await objectAdmin.removeObject(config.audit.headBucket, config.audit.headObjectKey!);
    await writeFile(path, JSON.stringify({ ...unsigned, signature }), { mode: 0o600 });
    try {
      assert.equal(freshVerification(true).valid, true);
      const upgraded = JSON.parse(await readFile(path, 'utf8'));
      assert.equal(upgraded.version, 2);
      assert.equal(upgraded.logId, current.logId);
      assert.equal(JSON.parse((await storage.readStoredAuditHead())!).logId, current.logId);
    } finally {
      await writeFile(path, original, { mode: 0o600 });
      await storage.writeStoredAuditHead(originalHead);
    }
  });
  await check('M5c-head-signature', 'An invalid persistent head signature is rejected after restart', async () => {
    const original = (await storage.readStoredAuditHead())!;
    const head = JSON.parse(original);
    head.logHash = 'f'.repeat(64);
    await storage.writeStoredAuditHead(JSON.stringify(head));
    try {
      const result = freshVerification();
      assert.equal(result.valid, false);
      assert.match(result.error, /signature/);
    } finally { await storage.writeStoredAuditHead(original); }
  });
  await check('M5c-head-crash-window', 'Startup repairs a lagging head only forward on a verified database chain', async () => {
    const previous = (await storage.readStoredAuditHead())!;
    await audit.audit({ action: 'formal.head.crash.window', targetType: 'system' });
    await storage.writeStoredAuditHead(previous);
    assert.equal(freshVerification().valid, true);
    assert.equal(JSON.parse((await storage.readStoredAuditHead())!).logId,
      JSON.parse(await readFile(process.env.AUDIT_CHECKPOINT_PATH!, 'utf8')).logId);
  });

  let rollbackCheckpoint = '';
  await check('M5c-AU4a', 'Replaying an old checkpoint is rejected by the running implementation', async () => {
    const checkpoint = process.env.AUDIT_CHECKPOINT_PATH!;
    const previous = await readFile(checkpoint, 'utf8');
    rollbackCheckpoint = previous;
    await audit.audit({ action: 'formal.rollback.probe', targetType: 'system' });
    const current = await readFile(checkpoint, 'utf8');
    await writeFile(checkpoint, previous, { mode: 0o600 });
    try {
      await assert.rejects(audit.verifyAuditChain(), /rollback detected/);
    } finally {
      await writeFile(checkpoint, current, { mode: 0o600 });
    }
  });

  await check('M5c-AU4b', 'Replaying an old checkpoint and truncated chain is rejected after restart', async () => {
    const checkpoint = process.env.AUDIT_CHECKPOINT_PATH!;
    const previous = rollbackCheckpoint;
    const old = JSON.parse(previous);
    const tamper = new pg.Client({ connectionString: process.env.DATABASE_URL });
    await tamper.connect();
    try {
      // DBA attacker, as in M5: only the newly created disposable database.
      await tamper.query('set session_replication_role = replica');
      await tamper.query('delete from audit_logs where created_at > (select created_at from audit_logs where id=$1)', [old.logId]);
    } finally { await tamper.end(); }
    await writeFile(checkpoint, previous, { mode: 0o600 });
    const result = freshVerification();
    assert.equal(result.valid, false, 'A fresh process accepted the shortened chain and old checkpoint (known R-047 / AU4b)');
  });
  console.log(JSON.stringify({ summary: checks.reduce((counts, check) => ({ ...counts, [check.verdict]: (counts[check.verdict] ?? 0) + 1 }), {} as Record<string, number>) }));
  process.exitCode = checks.some(check => check.verdict === 'FINDING') ? 1 : 0;
} catch (error) {
  console.error(error);
  process.exitCode = 2;
} finally {
  await cleanupObjects?.();
  await closeRuntime?.();
  await closeDb?.();
  await admin.query(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
  await admin.end();
  await rm(directory, { recursive: true, force: true });
}
