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
  const { MAX_AVATAR_BYTES, sanitizeAvatarPng } = await import('../../packages/server/src/security/profile-input.ts');
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
    return { ...device, signText, sessionId: session.id, cookie: `alparts_session=${authentication.token}` };
  }

  await check('M3c-orphan-proposal', 'Only a group member orders a commit; a device outside the group replaces it only by confirmed fresh start, and only when no usable member is left (M3 KL-orphan, §5.3.4)', async () => {
    const f = await fixture();
    const shared = await import('../../packages/shared/src/index.ts');
    const keyService = await import('../../packages/server/src/services/key.service.ts');
    const groups = await import('../../packages/server/src/services/mls-group.service.ts');
    const { directoryHead } = await import('../../packages/server/src/services/directory.service.ts');
    const { hashPassword } = await import('../../packages/server/src/security/password-work.ts');
    const { actionPurpose } = await import('../../packages/server/src/security/action-purpose.ts');
    const mls = await import('../../packages/client/src/services/mls-crypto.ts');
    const setup = (ok: boolean, message: string) => { if (!ok) throw new Error(`fixture: ${message}`); };
    const password = randomUUID() + randomUUID();
    await db.update(schema.users).set({ passwordHash: await hashPassword(password, 12) }).where(eq(schema.users.id, f.subject));
    const old = await register(f.owner);
    const sender = await register(f.subject);
    // A private channel whose group's only member is the owner's device; the
    // subject (no MANAGE_CHANNELS) also sees it.
    await channels.updateChannel(f.channelId, { isPrivate: true }, f.owner);
    await channels.addChannelMember(f.channelId, f.subject, f.owner);
    const runtime = await (await import('../../packages/server/src/security/runtime-lease.ts')).acquireRuntimeLease();
    closeRuntime = () => runtime.close();
    const { httpServer } = (await import('../../packages/server/src/app.ts')).createApp();
    try {
      await new Promise<void>(resolve => httpServer.listen(0, '127.0.0.1', resolve));
      const address = httpServer.address() as import('node:net').AddressInfo;
      type Device = typeof sender;
      const call = async (device: Device, path: string, body: unknown, stepUp?: string) => {
        const response = await fetch(`http://127.0.0.1:${address.port}${path}`, {
          method: 'POST',
          headers: { Cookie: device.cookie, Origin: 'http://localhost:5173', 'Content-Type': 'application/json', ...(stepUp ? { 'X-Alparts-Step-Up': stepUp } : {}) },
          body: JSON.stringify(body), signal: AbortSignal.timeout(10_000),
        });
        return { status: response.status, body: await response.json().catch(() => null) as any };
      };
      /** Like the app: confirm the identity for exactly this request, then send it. */
      const confirmed = async (device: Device, path: string, body: unknown) => {
        const purpose = actionPurpose('POST', path, body);
        const options = await call(device, '/api/auth/step-up/options', { purpose });
        setup(options.status === 200, `step-up options ${options.status}`);
        const verified = await call(device, '/api/auth/step-up/verify', { id: options.body.id, purpose, password });
        setup(verified.status === 200, `step-up verify ${verified.status}`);
        return call(device, path, body, verified.body.token);
      };
      const groupPath = `/api/channels/${f.channelId}/mls/group`;
      const publish = async (device: Device, userId: string) => {
        const material = await mls.generateMemberPackage(device.id);
        const packageId = randomUUID();
        const body = {
          packageId, keyPackage: material.publicPackage,
          signature: device.signText(shared.serializeMlsMemberPackage(f.channelId, { deviceId: device.id, packageId, keyPackage: material.publicPackage })),
        };
        const response = await call(device, `${groupPath}/packages`, body);
        setup(response.status === 201, `package ${response.status} ${JSON.stringify(response.body)}`);
        return { material, entry: { deviceId: device.id, userId, identityKey: device.identityKey, ...body } };
      };
      const seal = async (device: Device, result: { newState: any; commit: string; welcome: string }, fields: any) => {
        const raw = await mls.exportChannelKey(result.newState, fields.groupId, fields.version);
        const users = [...new Set<string>(fields.members.map((member: any) => member.userId))].sort();
        const unsigned = {
          ...fields, keyCommitment: createHash('sha256').update(raw).digest('base64url'), commit: result.commit, welcome: result.welcome,
          directoryHeads: await Promise.all(users.map(userId => directoryHead(db, userId))), committerDeviceId: device.id,
        };
        return { ...unsigned, signature: device.signText(shared.serializeMlsGroupCommit(unsigned)) };
      };
      const signatureKey = (entry: { keyPackage: string }) => mls.readMemberPackage(entry.keyPackage).signatureKey;

      const own = await publish(old, f.owner);
      const genesisId = shared.mlsGroupId(f.channelId, 1);
      const genesis = await mls.createChannelGroup(genesisId, own.material, [], new Map([[old.id, signatureKey(own.entry)]]));
      const created = await seal(old, genesis, {
        channelId: f.channelId, version: 1, previousVersion: 0, previousTranscript: '0'.repeat(64), groupId: genesisId, epoch: 1,
        kind: 'create', added: [own.entry], removed: [], members: [{ deviceId: old.id, userId: f.owner, leafIndex: 0 }],
      });
      const genesisResponse = await call(old, `${groupPath}/commits`, { commit: created });
      setup(genesisResponse.status === 201, `genesis ${genesisResponse.status} ${JSON.stringify(genesisResponse.body)}`);
      const previousTranscript = createHash('sha256').update(shared.serializeMlsGroupCommit(created)).digest('hex');
      const waiting = await publish(sender, f.subject);
      // What the device outside the group can send: a new group of its own ...
      const restartId = shared.mlsGroupId(f.channelId, 2);
      const restart = await mls.createChannelGroup(restartId, waiting.material, [], new Map([[sender.id, signatureKey(waiting.entry)]]));
      const replacement = await seal(sender, restart, {
        channelId: f.channelId, version: 2, previousVersion: 1, previousTranscript, groupId: restartId, epoch: 1,
        kind: 'create', added: [waiting.entry], removed: [], members: [{ deviceId: sender.id, userId: f.subject, leafIndex: 0 }],
      });
      const freshStart = {
        commit: replacement,
        freshStartSignature: sender.signText(shared.serializeChannelKeyFreshStart({ channelId: f.channelId, keyVersion: 2, keyCommitment: replacement.keyCommitment, deviceId: sender.id })),
      };
      // ... or a valid commit of the existing group (made from the member's state) that it orders as its own.
      const tree = mls.treeAuthMap(genesis.newState);
      tree.set(sender.id, signatureKey(waiting.entry));
      const addition = await mls.commitChannelGroup(genesis.newState, { add: [waiting.entry.keyPackage], removeLeaves: [], authMap: tree });
      const foreign = await seal(sender, addition, {
        channelId: f.channelId, version: 2, previousVersion: 1, previousTranscript, groupId: genesisId, epoch: 2, kind: 'commit',
        added: [waiting.entry], removed: [],
        members: [{ deviceId: old.id, userId: f.owner, leafIndex: 0 }, { deviceId: sender.id, userId: f.subject, leafIndex: 1 }],
      });

      // While a usable member can add the device, even a confirmed fresh start is refused.
      let state = await keyService.getKeyRecipients(f.channelId, f.subject, sender.id);
      assert.deepEqual([state.historyRecoveryRequired, state.pendingAddDeviceIds], [false, [sender.id]]);
      let response = await confirmed(sender, `${groupPath}/fresh-start`, freshStart);
      assert.deepEqual([response.status, response.body?.code], [409, 'KEY_FRESH_START_NOT_REQUIRED'],
        'a non-manager replaced a group that a usable member could still extend');

      // The only member's user loses the channel: no usable member is left.
      await channels.removeChannelMember(f.channelId, f.owner, f.owner);
      state = await keyService.getKeyRecipients(f.channelId, f.subject, sender.id);
      assert.equal(state.historyRecoveryRequired, true);
      assert.equal(state.canRotate, false);
      assert.deepEqual(state.requiredRemoveDeviceIds, [old.id]);
      assert.deepEqual(state.recipients.map(r => r.deviceId), [sender.id]);
      response = await call(sender, `${groupPath}/commits`, { commit: replacement });
      assert.deepEqual([response.status, response.body?.code], [403, 'KEY_FRESH_START_REQUIRED'],
        'canRotate=false, but the ordinary commit route took a new group from a device outside the existing one');
      response = await call(sender, `${groupPath}/commits`, { commit: foreign });
      assert.deepEqual([response.status, response.body?.code], [409, 'MLS_CONFLICT'], 'a device outside the group ordered a commit of it');
      response = await call(sender, `${groupPath}/fresh-start`, freshStart);
      assert.equal(response.status, 428, 'fresh start went through without a confirmation');
      await assert.rejects(groups.admitGroupCommit(f.subject, sender.id, replacement, { signature: freshStart.freshStartSignature }),
        /AUTHENTICATION_FAILED/, 'fresh start went through without a server-created confirmation receipt');
      response = await confirmed(sender, `${groupPath}/fresh-start`, freshStart);
      assert.deepEqual([response.status, response.body], [201, { version: 2, epoch: 1 }], 'a confirmed fresh start of an orphaned group was refused');
      // The old group ended for its member at that version, and the restart is on record.
      const ended = await db.query.mlsGroupMembers.findFirst({ where: (m: any, o: any) => o.and(o.eq(m.channelId, f.channelId), o.eq(m.deviceId, old.id)) });
      assert.equal(ended?.removedVersion, 2);
      const records = await db.query.auditLogs.findMany({ where: (a: any, o: any) => o.and(o.eq(a.action, 'channel.key.group.fresh_start'), o.eq(a.targetId, f.channelId)) });
      assert.deepEqual(records.map((record: any) => [record.details.removed, record.details.added]), [[[old.id], [sender.id]]]);
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
  // === 2026-10-09: the defects the re-verification found (M3r, M4s, M5v, M6, M8) ===
  const ORIGIN = 'http://localhost:5173';
  const setup = (ok: boolean, message: string) => { if (!ok) throw new Error(`fixture: ${message}`); };
  /** The real app on a free port, with the runtime lease this process holds. */
  async function serve(body: (base: string, io: any) => Promise<void>) {
    if (!closeRuntime) {
      const runtime = await (await import('../../packages/server/src/security/runtime-lease.ts')).acquireRuntimeLease();
      closeRuntime = () => runtime.close();
    }
    const { httpServer, io } = (await import('../../packages/server/src/app.ts')).createApp();
    await new Promise<void>(resolve => httpServer.listen(0, '127.0.0.1', resolve));
    const address = httpServer.address() as import('node:net').AddressInfo;
    try {
      await body(`http://127.0.0.1:${address.port}`, io);
    } finally {
      io.disconnectSockets(true);
      httpServer.closeAllConnections();
      await new Promise<void>(resolve => io.close(() => resolve()));
    }
  }
  async function send(base: string, device: { cookie: string }, method: string, path: string, body?: unknown, stepUp?: string) {
    const response = await fetch(base + path, {
      method,
      headers: { Cookie: device.cookie, Origin: ORIGIN, 'Content-Type': 'application/json', ...(stepUp ? { 'X-Alparts-Step-Up': stepUp } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(10_000),
    });
    return { status: response.status, body: await response.json().catch(() => null) as any };
  }
  /** Like the app: when the server asks to confirm exactly this request, confirm it and send it again. */
  async function sendConfirmed(base: string, device: { cookie: string }, password: string, method: string, path: string, body?: unknown) {
    const first = await send(base, device, method, path, body);
    if (first.status !== 428 || first.body?.error !== 'STEP_UP_REQUIRED') return first;
    const purpose = first.body.purpose;
    const options = await send(base, device, 'POST', '/api/auth/step-up/options', { purpose });
    setup(options.status === 200, `step-up options ${options.status}`);
    const verified = await send(base, device, 'POST', '/api/auth/step-up/verify', { id: options.body.id, purpose, password });
    setup(verified.status === 200, `step-up verify ${verified.status}`);
    return send(base, device, method, path, body, verified.body.token);
  }
  async function withPassword(userId: string) {
    const { hashPassword } = await import('../../packages/server/src/security/password-work.ts');
    const password = randomUUID() + randomUUID();
    await db.update(schema.users).set({ passwordHash: await hashPassword(password, 12) }).where(eq(schema.users.id, userId));
    return password;
  }

  await check('M5c-case-uuid', 'A request naming a workspace or member in capital letters is refused, so no change escapes the audit view (M5v AV-case)', async () => {
    const f = await fixture();
    const auditLog = await import('../../packages/server/src/services/audit-log.service.ts');
    const password = await withPassword(f.manager);
    const manager = await register(f.manager);
    const flags = async () => (await db.select().from(schema.profileFlags).where(eq(schema.profileFlags.userId, f.subject))).length;
    const inChain = async () => (await db.select().from(schema.auditLogs).where(eq(schema.auditLogs.action, 'profile.flag')))
      .filter((row: any) => row.targetId?.toLowerCase() === f.subject).length;
    const inView = async () => (await auditLog.listWorkspaceAuditLogs(f.workspaceId, f.owner, { limit: 100 })).data
      .filter((row: any) => row.action === 'profile.flag' && row.targetId === f.subject).length;
    const letter = [...f.workspaceId].findIndex(c => /[a-f]/.test(c));
    setup(letter >= 0, 'a workspace id without letters');
    const encoded = f.workspaceId.slice(0, letter) + '%' + (f.workspaceId.charCodeAt(letter) - 32).toString(16).toUpperCase()
      + f.workspaceId.slice(letter + 1);
    await serve(async (base) => {
      // Before the fix these went through once confirmed and wrote the
      // workspace id as sent: the owner's audit view (text comparison) missed the row.
      for (const path of [
        `/api/workspaces/${f.workspaceId.toUpperCase()}/members/${f.subject}/profile-flag`,
        `/api/workspaces/${encoded}/members/${f.subject}/profile-flag`,
        `/api/workspaces/${f.workspaceId}/members/${f.subject.toUpperCase()}/profile-flag`,
      ]) {
        const response = await sendConfirmed(base, manager, password, 'PUT', path);
        assert.equal(response.status, 404, `${path} answered ${response.status} ${JSON.stringify(response.body)}`);
      }
      assert.deepEqual([await flags(), await inChain()], [0, 0], 'a request with an id in capital letters changed the warning');
      const response = await sendConfirmed(base, manager, password, 'PUT', `/api/workspaces/${f.workspaceId}/members/${f.subject}/profile-flag`);
      assert.equal(response.status, 200, `the canonical request answered ${response.status} ${JSON.stringify(response.body)}`);
      assert.deepEqual([await flags(), await inChain(), await inView()], [1, 1, 1], 'the warning is missing from the owner\'s audit view');
    });
  });

  await check('M5c-member-package-view', 'Who publishes packages in a private channel is shown only to audit viewers who can see the channel (M5v AV-class)', async () => {
    const f = await fixture();
    const shared = await import('../../packages/shared/src/index.ts');
    const groups = await import('../../packages/server/src/services/mls-group.service.ts');
    const auditLog = await import('../../packages/server/src/services/audit-log.service.ts');
    const mls = await import('../../packages/client/src/services/mls-crypto.ts');
    // An audit viewer of the workspace who is not in the private channel.
    const auditor = randomUUID(), auditRole = randomUUID();
    await db.insert(schema.users).values({ id: auditor, email: auditor + '@formal.invalid', passwordHash: 'disabled-test-fixture', displayName: 'Auditor' });
    await db.insert(schema.roles).values({ id: auditRole, workspaceId: f.workspaceId, name: 'Auditor', position: 50, permissions: P.VIEW_CHANNELS | P.VIEW_AUDIT_LOG });
    const [membership] = await db.insert(schema.workspaceMembers).values({ workspaceId: f.workspaceId, userId: auditor }).returning();
    await db.insert(schema.memberRoles).values({ memberId: membership.id, roleId: auditRole });
    await channels.updateChannel(f.channelId, { isPrivate: true }, f.owner);
    await channels.addChannelMember(f.channelId, f.subject, f.owner);
    const device = await register(f.subject);
    const material = await mls.generateMemberPackage(device.id);
    const packageId = randomUUID();
    await groups.publishMemberPackage(f.channelId, f.subject, device.id, {
      packageId, keyPackage: material.publicPackage,
      signature: device.signText(shared.serializeMlsMemberPackage(f.channelId, { deviceId: device.id, packageId, keyPackage: material.publicPackage })),
    });
    const rows = async (viewer: string) => (await auditLog.listWorkspaceAuditLogs(f.workspaceId, viewer, { limit: 100 })).data
      .filter((row: any) => row.targetId === f.channelId && row.action.startsWith('channel.mls.')).length;
    setup(await rows(f.owner) === 1, 'the owner does not see the package row');
    assert.equal(await rows(auditor), 0, 'an audit viewer outside the private channel saw which of its members publish packages');
    await channels.addChannelMember(f.channelId, auditor, f.owner);
    assert.equal(await rows(auditor), 1, 'a viewer of the channel does not see its package row');
  });

  await check('M5c-view-chain-fields', 'The audit view returns no chain hashes that would show rows written in between (M5v AV-links)', async () => {
    const f = await fixture();
    const auditLog = await import('../../packages/server/src/services/audit-log.service.ts');
    await channels.updateChannel(f.channelId, { name: 'renamed' }, f.owner);
    const rows = (await auditLog.listWorkspaceAuditLogs(f.workspaceId, f.owner, { limit: 100 })).data as Array<Record<string, unknown>>;
    setup(rows.length > 0, 'the view is empty');
    assert.deepEqual(rows.filter(row => 'prevHash' in row || 'hash' in row).map(row => row.action), [],
      'the view returns the chain hashes of its rows');
  });

  await check('M4c-stale-step-up', 'A confirmation taken before its session was revoked no longer lets that session change the password or sign out the others (M4s AS1, AS2)', async () => {
    const f = await fixture();
    const auth = await import('../../packages/server/src/services/auth.service.ts');
    const passkeys = await import('../../packages/server/src/services/passkey.service.ts');
    const { actionPurpose } = await import('../../packages/server/src/security/action-purpose.ts');
    const password = await withPassword(f.subject);
    const stolen = await register(f.subject);
    /** The route's two steps: the confirmation is taken (T1), the change made later (T2). */
    const confirm = async (purpose: string) => {
      const options = await passkeys.authenticationOptions(purpose, f.subject, stolen.sessionId);
      const { token } = await passkeys.finishStepUp(f.subject, stolen.sessionId, options.id, purpose, undefined, password);
      const proof = await passkeys.consumeStepUp(stolen.sessionId, purpose, token);
      setup(proof !== null, 'the confirmation was not taken');
      return proof!;
    };
    const recheck = (proof: Awaited<ReturnType<typeof confirm>>) =>
      (transaction: any) => passkeys.assertStepUpStillValid(transaction, proof, f.subject, stolen.sessionId);
    const hash = async () => (await db.query.users.findFirst({ where: eq(schema.users.id, f.subject) }))!.passwordHash;
    const alive = async (sessionId: string) => Boolean(await db.query.sessions.findFirst({ where: eq(schema.sessions.id, sessionId) }));
    // A confirmation that still holds goes through.
    const extra = await register(f.subject);
    assert.equal(await auth.revokeSession(f.subject, extra.sessionId, recheck(await confirm(actionPurpose('DELETE', `/api/auth/sessions/${extra.sessionId}`, undefined)))), true);
    // The session confirms both changes, then the owner revokes it from another session.
    const own = await register(f.subject);
    const replacement = randomUUID() + randomUUID();
    const changeProof = await confirm(actionPurpose('PUT', '/api/auth/password', { newPassword: replacement }));
    const signOutProof = await confirm(actionPurpose('DELETE', '/api/auth/sessions', undefined));
    assert.equal(await auth.revokeSession(f.subject, stolen.sessionId, async () => undefined), true);
    const before = await hash();
    await assert.rejects(auth.changePassword(f.subject, stolen.sessionId, replacement, recheck(changeProof)), /STEP_UP_STALE/,
      'a revoked session changed the password with a confirmation taken before the revocation');
    assert.equal(await hash(), before);
    await assert.rejects(auth.revokeAllSessions(f.subject, recheck(signOutProof)), /STEP_UP_STALE/,
      'a revoked session signed out the owner\'s other sessions');
    assert.equal(await alive(own.sessionId), true);
    // Without the check inside the transaction (before the fix) the change commits: the window is real.
    await auth.changePassword(f.subject, stolen.sessionId, randomUUID(), async () => undefined);
    setup(await hash() !== before, 'the change without the check did not commit');
  });

  await check('M4c-socket-recheck', 'A socket whose session is revoked while it connects is closed (M4s WS1)', async () => {
    const f = await fixture();
    const auth = await import('../../packages/server/src/services/auth.service.ts');
    const { io: connect } = require('socket.io-client');
    const device = await register(f.subject);
    await serve(async (base, io) => {
      const blocker = new pg.Client({ connectionString: process.env.DATABASE_URL });
      await blocker.connect();
      let socket: any;
      try {
        // The handshake reads the session, then the device: hold it in between.
        await blocker.query('begin');
        await blocker.query('lock table devices in access exclusive mode');
        socket = connect(base, { transports: ['websocket'], reconnection: false, extraHeaders: { Cookie: device.cookie, Origin: ORIGIN } });
        const ended = new Promise<string>(resolve => {
          socket.once('disconnect', (reason: string) => resolve(`disconnect: ${reason}`));
          socket.once('connect_error', (error: Error) => resolve(`connect_error: ${error.message}`));
        });
        const deadline = Date.now() + 10_000;
        while ((await blocker.query(`select count(*)::int as n from pg_locks where relation = 'devices'::regclass and not granted`)).rows[0].n === 0) {
          setup(Date.now() < deadline, 'the handshake never reached the device read');
          await delay(10);
        }
        // Revoked as the route does it: the session row, then the sockets in its room (none yet).
        assert.equal(await auth.revokeSession(f.subject, device.sessionId, async () => undefined), true);
        io.in(`session:${device.sessionId}`).disconnectSockets(true);
        await blocker.query('commit');
        const outcome = await Promise.race([ended, delay(5_000).then(() => 'still connected')]);
        assert.notEqual(outcome, 'still connected', 'a socket whose session was revoked during its handshake stayed connected');
        assert.equal((await io.in(`session:${device.sessionId}`).fetchSockets()).length, 0);
      } finally {
        socket?.disconnect();
        await blocker.query('rollback').catch(() => undefined);
        await blocker.end();
      }
    });
  });

  await check('M4c-step-up-budget', 'A stolen session that uses up its confirmations cannot keep the owner\'s other session from confirming and revoking it', async () => {
    const f = await fixture();
    const { actionPurpose } = await import('../../packages/server/src/security/action-purpose.ts');
    const password = await withPassword(f.subject);
    const stolen = await register(f.subject);
    const own = await register(f.subject);
    // Both are the user's approved devices (fixture: the second one is approved directly).
    await db.update(schema.devices).set({ approvedAt: new Date() }).where(eq(schema.devices.id, own.id));
    await serve(async (base) => {
      // The stolen session guesses the password until it is refused, then floods the requests for a challenge.
      const purpose = actionPurpose('DELETE', `/api/auth/sessions/${own.sessionId}`, undefined);
      let guesses = 0, requests = 0;
      for (; guesses < 11; guesses++) {
        const options = await send(base, stolen, 'POST', '/api/auth/step-up/options', { purpose });
        setup(options.status === 200, `the stolen session's challenge ${guesses} answered ${options.status}`);
        const guess = await send(base, stolen, 'POST', '/api/auth/step-up/verify', { id: options.body.id, purpose, password: `wrong-${guesses}` });
        if (guess.status === 429) break;
      }
      setup(guesses === 10, `the stolen session was refused after ${guesses} wrong passwords`);
      for (; requests < 240; requests++) {
        if ((await send(base, stolen, 'POST', '/api/auth/step-up/options', { purpose })).status === 429) break;
      }
      setup(requests < 240, 'the stolen session\'s challenge requests were never refused');
      // The owner confirms from its own session and revokes the stolen one.
      const path = `/api/auth/sessions/${stolen.sessionId}`;
      const asked = await send(base, own, 'DELETE', path);
      setup(asked.status === 428, `the revocation answered ${asked.status} before confirming`);
      const options = await send(base, own, 'POST', '/api/auth/step-up/options', { purpose: asked.body.purpose });
      assert.equal(options.status, 200, `the owner could not start a confirmation after the stolen session used up its own (${JSON.stringify(options.body)})`);
      const verified = await send(base, own, 'POST', '/api/auth/step-up/verify', { id: options.body.id, purpose: asked.body.purpose, password });
      assert.equal(verified.status, 200, 'the owner\'s correct password was refused after the stolen session\'s wrong guesses');
      const revoked = await send(base, own, 'DELETE', path, undefined, verified.body.token);
      assert.equal(revoked.status, 200, JSON.stringify(revoked.body));
      assert.equal(Boolean(await db.query.sessions.findFirst({ where: eq(schema.sessions.id, stolen.sessionId) })), false);
    });
  });

  await check('M3c-identical-retry', 'The same commit sent again gets the replay answer, whichever check finds its version taken (M3r K2)', async () => {
    const f = await fixture();
    const shared = await import('../../packages/shared/src/index.ts');
    const groups = await import('../../packages/server/src/services/mls-group.service.ts');
    const { directoryHead } = await import('../../packages/server/src/services/directory.service.ts');
    const mls = await import('../../packages/client/src/services/mls-crypto.ts');
    const device = await register(f.owner);
    // Statements outside transactions go through the pool; a transaction has a client of its own.
    const pool = (db as any).$client;
    const query = pool.query;
    try {
      for (const [window, table] of [['after its replay check', 'mls_epochs'], ['after its unlocked checks', 'mls_member_packages']]) {
        const channelId = randomUUID();
        await db.insert(schema.channels).values({ id: channelId, workspaceId: f.workspaceId, name: 'retry', type: 'text', isPrivate: false });
        const material = await mls.generateMemberPackage(device.id);
        const packageId = randomUUID();
        const published = {
          packageId, keyPackage: material.publicPackage,
          signature: device.signText(shared.serializeMlsMemberPackage(channelId, { deviceId: device.id, packageId, keyPackage: material.publicPackage })),
        };
        await groups.publishMemberPackage(channelId, f.owner, device.id, published);
        const entry = { deviceId: device.id, userId: f.owner, identityKey: device.identityKey, ...published };
        const groupId = shared.mlsGroupId(channelId, 1);
        const genesis = await mls.createChannelGroup(groupId, material, [], new Map([[device.id, mls.readMemberPackage(entry.keyPackage).signatureKey]]));
        const raw = await mls.exportChannelKey(genesis.newState, groupId, 1);
        const unsigned = {
          channelId, version: 1, previousVersion: 0, previousTranscript: '0'.repeat(64), groupId, epoch: 1, kind: 'create' as const,
          added: [entry], removed: [], members: [{ deviceId: device.id, userId: f.owner, leafIndex: 0 }],
          keyCommitment: createHash('sha256').update(raw).digest('base64url'), commit: genesis.commit, welcome: genesis.welcome,
          directoryHeads: [await directoryHead(db, f.owner)], committerDeviceId: device.id,
        };
        const commit = { ...unsigned, signature: device.signText(shared.serializeMlsGroupCommit(unsigned)) };
        // The resend (its first answer was lost) is held after one read until the first send is accepted.
        let armed = true, held!: () => void, release!: () => void;
        const reached = new Promise<void>(resolve => { held = resolve; });
        const released = new Promise<void>(resolve => { release = resolve; });
        pool.query = async function(this: unknown, config: any, values?: unknown[]) {
          const result = await query.call(this, config, values);
          const text = typeof config === 'string' ? config : config?.text ?? '';
          if (armed && text.includes(`from "${table}"`) && (values ?? []).includes(channelId)) {
            armed = false;
            held();
            await released;
          }
          return result;
        };
        const resend = groups.admitGroupCommit(f.owner, device.id, commit, null).then(result => result, (error: Error) => error);
        await Promise.race([reached, delay(10_000).then(() => setup(false, `the resend never read ${table}`))]);
        const first = await groups.admitGroupCommit(f.owner, device.id, commit, null);
        release();
        const second = await resend;
        pool.query = query;
        setup(first.replay === false, `${window}: the first send was not accepted`);
        assert.ok(!(second instanceof Error), `${window}: the resend of the accepted bytes was refused (${second instanceof Error ? second.message : ''})`);
        assert.equal((second as { replay: boolean }).replay, true, `${window}: the resend was accepted a second time`);
      }
    } finally { pool.query = query; }
  });

  await check('M6c-avatar-read-failure', 'An upload compared with a current picture that cannot be read does not count as a change; a missing one does (M6 A3)', async () => {
    for (const fault of ['unreadable', 'missing'] as const) {
      const f = await fixture();
      await profiles.setAvatar(f.subject, samePixelsPng(0));
      const user = await db.query.users.findFirst({ where: eq(schema.users.id, f.subject) });
      await profiles.flagProfile(f.workspaceId, f.owner, f.subject);
      // A read that fails takes the same branch as an object the store
      // answers with but that is not a picture of an allowed size.
      if (fault === 'unreadable') await storage.putStoredObject(user!.avatarObjectKey!, Buffer.alloc(MAX_AVATAR_BYTES + 1));
      else await objectAdmin.removeObject(config.s3.bucket, user!.avatarObjectKey!);
      await delay(5);
      const upload = await profiles.setAvatar(f.subject, samePixelsPng(0)).then(() => 'saved', () => 'refused');
      if (fault === 'unreadable') {
        await assert.rejects(profiles.requestProfileAppeal(f.workspaceId, f.subject), /PROFILE_APPEAL_NEEDS_CHANGE/,
          `a current picture that could not be read counted as a change after the warning (upload ${upload})`);
      } else {
        assert.equal(upload, 'saved', 'an upload replacing a missing picture was refused');
        await profiles.requestProfileAppeal(f.workspaceId, f.subject);
      }
    }
  });

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
