import assert from 'node:assert/strict';
import {
  constants,
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  generateKeyPairSync,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
  randomUUID,
  sign,
} from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { crc32, deflateSync } from 'node:zlib';
import { and, eq, inArray, sql } from 'drizzle-orm';
import pg from 'pg';
import {
  Permissions,
  canonicalActionBody, isSensitiveAction, serializeDeviceDecision, serializeGroupKeyPackage, serializeMlsEpoch, type MlsEpoch, type GroupKeyPackage,
  serializeAttachmentEnvelope,
  serializeChannelKeyAcknowledgement,
  serializeChannelKeyEpochAbort,
  serializeChannelKeyFreshStart,
  serializeChannelKeyWrap,
  serializeDeviceChallengeProof,
  serializeMessageAad,
  serializeMessageEnvelope,
  serializeVoiceSignalEnvelope,
  type SignedAttachmentEnvelope,
  type SignedMessageEnvelope,
  type SignedVoiceSignalEnvelope,
} from '@alparts/shared';

const enabled = process.env.RUN_INTEGRATION === '1';
const fixtureKeys = new Map<string, ReturnType<typeof deviceFixture>>();
const joinedMlsKeys = new Map<string, Map<string, Buffer>>();

describe('security boundaries (PostgreSQL + MinIO)', { skip: !enabled }, () => {
  let baseUrl = '';
  let httpServer: import('node:http').Server;
  let verifyAuditChain: typeof import('../middleware/audit.js').verifyAuditChain;
  let runtime: import('./runtime-lease.js').RuntimeLease;
  let closeDb: typeof import('../db/index.js').closeDb;
  let auditCheckpointDirectory = '';
  let auditCheckpointPath = '';
  const credentials = new Map<string, { password: string; userId: string }>();
  const sockets: Array<{ disconnect(): void }> = [];

  before(async () => {
    auditCheckpointDirectory = await mkdtemp(join(tmpdir(), 'alparts-integration-audit-'));
    auditCheckpointPath = join(auditCheckpointDirectory, 'checkpoint.json');
    process.env.AUDIT_CHECKPOINT_PATH = auditCheckpointPath;
    process.env.AUDIT_CHECKPOINT_REQUIRED = 'true';
    process.env.AUDIT_HEAD_OBJECT_KEY = `test-${randomUUID()}`;
    // The suite represents several independent clients but they all originate
    // from the loopback test runner. Trust only that loopback reverse proxy and
    // assign a stable documentation-range address per authenticated session so
    // one client's production rate budget cannot mask a later assertion.
    process.env.TRUSTED_PROXIES = '127.0.0.1';
    const auditModule = await import('../middleware/audit.js');
    const dbModule = await import('../db/index.js');
    closeDb = dbModule.closeDb;
    assert.equal(await dbModule.checkDatabaseSchema(), 21);
    verifyAuditChain = auditModule.verifyAuditChain;
    await auditModule.provisionAuditCheckpoint();
    const startupAudit = await verifyAuditChain();
    assert.equal(startupAudit.valid, true);
    const appModule = await import('../app.js');
    runtime = await (await import('./runtime-lease.js')).acquireRuntimeLease();
    const created = appModule.createApp();
    httpServer = created.httpServer;
    await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
    const address = httpServer.address();
    if (!address || typeof address === 'string') throw new Error('Server did not bind a TCP port');
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  after(async () => {
    for (const socket of sockets) socket.disconnect();
    await new Promise<void>((resolve, reject) => httpServer.close((error) => error ? reject(error) : resolve()));
    await closeDb();
    await runtime?.close();
    if (auditCheckpointDirectory) await rm(auditCheckpointDirectory, { recursive: true, force: true });
  });

  it('enforces authorization, E2EE envelopes, WebSocket rooms, and session revocation', async () => {
    const bootstrapToken = process.env.REGISTRATION_INVITE_SECRET!;
    const alice = await createAccount('alice@example.test', 'Correct-Horse-Battery-1!', 'Alice', bootstrapToken);

    const invalidInvite = await request('/api/auth/register', {
      method: 'POST',
      body: { email: 'blocked@example.test', password: 'Correct-Horse-Battery-4!', displayName: 'Blocked', inviteToken: 'invalid' },
    });
    assert.equal(invalidInvite.status, 403);

    const reusedBootstrap = await request('/api/auth/register', {
      method: 'POST',
      body: { email: 'bootstrap-reuse@example.test', password: 'Correct-Horse-Battery-5!', displayName: 'Blocked', inviteToken: bootstrapToken },
    });
    assert.equal(reusedBootstrap.status, 403);

    const aliceKeys = deviceFixture();
    const aliceDevice = await registerDevice(alice, aliceKeys, 'Alice test device');

    const workspaceResponse = await request('/api/workspaces', {
      method: 'POST', cookie: alice.cookie, body: { name: 'Security Test' },
    });
    assert.equal(workspaceResponse.status, 201);
    const workspace = await json<{ id: string }>(workspaceResponse);

    const bobInvitation = await createWorkspaceInvitation(workspace.id, alice.cookie, 'bob@example.test');
    const invitationsResponse = await request(`/api/workspaces/${workspace.id}/invitations`, { cookie: alice.cookie });
    assert.equal(invitationsResponse.status, 200);
    const invitationList = await json<Array<Record<string, unknown>>>(invitationsResponse);
    assert.equal(Object.hasOwn(invitationList[0], 'token'), false);
    assert.equal(Object.hasOwn(invitationList[0], 'tokenHash'), false);
    const bob = await createAccount('bob@example.test', 'Correct-Horse-Battery-2!', 'Bob', bobInvitation.token);
    const reusedInvitation = await request('/api/auth/register', {
      method: 'POST',
      body: { email: 'bob-reuse@example.test', password: 'Correct-Horse-Battery-6!', displayName: 'Blocked', inviteToken: bobInvitation.token },
    });
    assert.equal(reusedInvitation.status, 403);
    const unboundInvitation = await createWorkspaceInvitation(workspace.id, alice.cookie);
    const existingEmailRegistration = await request('/api/auth/register', {
      method: 'POST',
      body: { email: 'alice@example.test', password: 'Correct-Horse-Battery-8!', displayName: 'Probe', inviteToken: unboundInvitation.token },
    });
    assert.equal(existingEmailRegistration.status, invalidInvite.status);
    assert.equal((await json<{ error: string }>(existingEmailRegistration)).error, 'INVITE_REQUIRED');
    const unboundRegistration = await request('/api/auth/register', {
      method: 'POST',
      body: { email: 'unbound@example.test', password: 'Correct-Horse-Battery-9!', displayName: 'Unbound', inviteToken: unboundInvitation.token },
    });
    assert.equal(unboundRegistration.status, 201);
    const retryDeviceInvitation = await createWorkspaceInvitation(workspace.id, alice.cookie, 'device-retry@example.test');
    const retryDeviceAccount = await createAccount(
      'device-retry@example.test',
      'Correct-Horse-Battery-10!',
      'Device Retry',
      retryDeviceInvitation.token,
    );
    const retryDeviceKeys = deviceFixture();
    const firstDeviceRegistration = await request('/api/devices', {
      method: 'POST', cookie: retryDeviceAccount.cookie,
      body: await deviceRegistrationBody(retryDeviceAccount, retryDeviceKeys, 'Retry identity'),
    });
    assert.equal(firstDeviceRegistration.status, 201);
    const firstRetryDevice = await json<{ id: string }>(firstDeviceRegistration);
    const repeatedDeviceRegistration = await request('/api/devices', {
      method: 'POST', cookie: retryDeviceAccount.cookie,
      body: await deviceRegistrationBody(retryDeviceAccount, retryDeviceKeys, 'Retry identity renamed'),
    });
    assert.equal(repeatedDeviceRegistration.status, 200);
    assert.equal((await json<{ id: string }>(repeatedDeviceRegistration)).id, firstRetryDevice.id);

    // A workspace manager can legitimately create more than 64 provisional
    // epochs that include an ordinary member. Those rows must not consume an
    // account-global enrollment cap and prevent that member from recovering a
    // device. Seed the exact database state directly so this regression test
    // remains fast and independent of API rate limits.
    const enrollmentDatabaseModule = await import('../db/index.js');
    const enrollmentSchemaModule = await import('../db/schema.js');
    const enrollmentFixtureChannels = await enrollmentDatabaseModule.db
      .insert(enrollmentSchemaModule.channels)
      .values(Array.from({ length: 65 }, (_, index) => ({
        workspaceId: workspace.id,
        name: `enrollment-pending-${index}`,
        type: 'text',
        isPrivate: false,
      })))
      .returning({ id: enrollmentSchemaModule.channels.id });
    const enrollmentFixtureChannelIds = enrollmentFixtureChannels.map((channel) => channel.id);
    await enrollmentDatabaseModule.db.insert(enrollmentSchemaModule.channelKeyEpochs).values(
      enrollmentFixtureChannelIds.map((channelId) => ({
        channelId,
        version: 1,
        protocolVersion: 2,
        status: 'pending',
        keyCommitment: 'A'.repeat(43),
        distributorDeviceId: firstRetryDevice.id,
      })),
    );
    await enrollmentDatabaseModule.db.insert(enrollmentSchemaModule.channelKeyEpochRecipients).values(
      enrollmentFixtureChannelIds.map((channelId) => ({
        channelId,
        version: 1,
        deviceId: firstRetryDevice.id,
        userId: retryDeviceAccount.user.id,
        requiredForActivation: true,
      })),
    );
    await enrollmentDatabaseModule.db.insert(enrollmentSchemaModule.channelKeys).values(
      enrollmentFixtureChannelIds.map((channelId) => ({
        channelId,
        version: 1,
        encryptedKey: 'fixture',
        deviceId: firstRetryDevice.id,
        distributorDeviceId: firstRetryDevice.id,
        signature: 'fixture',
      })),
    );

    // Losing the only accepted device must not permanently wedge future
    // writes. Recovery creates a new epoch without pretending old ciphertext
    // is decryptable, and is separately visible in state and audit logs.
    const recoveryWorkspaceResponse = await request('/api/workspaces', {
      method: 'POST', cookie: retryDeviceAccount.cookie, body: { name: 'Sole holder recovery' },
    });
    assert.equal(recoveryWorkspaceResponse.status, 201);
    const recoveryWorkspace = await json<{ id: string }>(recoveryWorkspaceResponse);
    const recoveryChannels = await json<Array<{ id: string; type: string }>>(
      await request(`/api/workspaces/${recoveryWorkspace.id}/channels`, { cookie: retryDeviceAccount.cookie }),
    );
    const recoveryChannel = recoveryChannels.find((channel) => channel.type !== 'dm');
    assert.ok(recoveryChannel);
    const soleRecipients = await json<{ recipients: Array<{ deviceId: string; identityKey: string }> }>(
      await request(`/api/channels/${recoveryChannel.id}/key-recipients`, { cookie: retryDeviceAccount.cookie }),
    );
    assert.deepEqual(soleRecipients.recipients.map((recipient) => recipient.deviceId), [firstRetryDevice.id]);
    await distributeAndAcknowledgeChannelKey({
      channelId: recoveryChannel.id,
      version: 1,
      rawKey: randomBytes(32),
      senderCookie: retryDeviceAccount.cookie,
      senderKeys: retryDeviceKeys,
      recipients: soleRecipients.recipients,
      acknowledgements: [{
        deviceId: firstRetryDevice.id,
        cookie: retryDeviceAccount.cookie,
        keys: retryDeviceKeys,
      }],
    });

    // A newly enrolled manager may explicitly leave unavailable history
    // behind and start a fresh writable epoch. Every current endpoint gets a
    // signed wrap, while every endpoint gates activation, including the old endpoint.
    const freshStartLogin = await request('/api/auth/login', {
      method: 'POST',
      body: { email: 'device-retry@example.test', password: 'Correct-Horse-Battery-10!' },
    });
    assert.equal(freshStartLogin.status, 200);
    const freshStartCookie = freshStartLogin.headers.get('set-cookie')!.split(';', 1)[0];
    const freshStartKeys = deviceFixture();
    const freshStartDevice = await registerDevice(
      { ...retryDeviceAccount, cookie: freshStartCookie },
      freshStartKeys,
      'Fresh start identity',
    );
    const freshStartState = await json<{
      nextVersion: number;
      recipients: Array<{ deviceId: string; identityKey: string }>;
    }>(await request(`/api/channels/${recoveryChannel.id}/key-recipients`, { cookie: freshStartCookie }));
    assert.equal(freshStartState.nextVersion, 2);
    const freshStartKey = randomBytes(32);
    const { keyCommitment: freshStartCommitment, keys: freshStartWraps } = await proposeFixtureMls({
      channelId: recoveryChannel.id, version: freshStartState.nextVersion, rawKey: freshStartKey,
      senderCookie: freshStartCookie, senderKeys: freshStartKeys, recipients: freshStartState.recipients, fresh: true,
    });
    const proposedFreshState = await json<{
      pendingRequiredDeviceIds: string[];
    }>(await request(`/api/channels/${recoveryChannel.id}/key-recipients`, { cookie: freshStartCookie }));
    assert.deepEqual(new Set(proposedFreshState.pendingRequiredDeviceIds), new Set([firstRetryDevice.id, freshStartDevice.id]));
    const oldEndpointWrap = freshStartWraps.find((key) => key.deviceId === firstRetryDevice.id);
    assert.ok(oldEndpointWrap);
    const optionalAcknowledgement = await acknowledgeChannelKeyDelivery({
      channelId: recoveryChannel.id,
      version: 2,
      keyCommitment: freshStartCommitment,
      encryptedKey: oldEndpointWrap.encryptedKey,
      deviceId: firstRetryDevice.id,
      cookie: retryDeviceAccount.cookie,
      keys: retryDeviceKeys,
    });
    assert.equal(optionalAcknowledgement.status, 'pending');
    assert.equal(optionalAcknowledgement.activated, false);
    const freshStartDelivery = freshStartWraps.find((key) => key.deviceId === freshStartDevice.id);
    assert.ok(freshStartDelivery);
    const freshStartAcknowledgement = await acknowledgeChannelKeyDelivery({
      channelId: recoveryChannel.id,
      version: 2,
      keyCommitment: freshStartCommitment,
      encryptedKey: freshStartDelivery.encryptedKey,
      deviceId: freshStartDevice.id,
      cookie: freshStartCookie,
      keys: freshStartKeys,
    });
    assert.equal(freshStartAcknowledgement.status, 'active');
    assert.equal(freshStartAcknowledgement.activated, true);
    const oldEndpointDeliveries = await json<Array<{ version: number; encryptedKey: string }>>(
      await request(`/api/channels/${recoveryChannel.id}/keys?version=2`, { cookie: retryDeviceAccount.cookie }),
    );
    const oldEndpointDelivery = oldEndpointDeliveries.find((delivery) => delivery.version === 2);
    assert.ok(oldEndpointDelivery);
    assert.deepEqual(unwrapKey(oldEndpointDelivery.encryptedKey, retryDeviceKeys.encryptionPrivateKey), freshStartKey);
    const freshStartWrite = await request(`/api/channels/${recoveryChannel.id}/messages`, {
      method: 'POST',
      cookie: freshStartCookie,
      body: encryptedMessage(
        recoveryChannel.id,
        retryDeviceAccount.user.id,
        freshStartDevice.id,
        freshStartKeys.signingPrivateKey,
        freshStartKey,
        'fresh messages wait for every current endpoint',
        undefined,
        2,
      ).body,
    });
    assert.equal(freshStartWrite.status, 201);
    assert.equal((await request(`/api/devices/${freshStartDevice.id}`, {
      method: 'DELETE', cookie: freshStartCookie,
    })).status, 200);

    const recoveryLogin = await request('/api/auth/login', {
      method: 'POST',
      body: { email: 'device-retry@example.test', password: 'Correct-Horse-Battery-10!' },
    });
    assert.equal(recoveryLogin.status, 200);
    const recoveryCookie = recoveryLogin.headers.get('set-cookie')!.split(';', 1)[0];
    const recoveryKeys = deviceFixture();
    const recoveryDevice = await registerDevice(
      { ...retryDeviceAccount, cookie: recoveryCookie },
      recoveryKeys,
      'Recovery identity',
    );
    const postRevocationAttempt = await deviceRegistrationBody(
      retryDeviceAccount,
      retryDeviceKeys,
      'Retry identity',
      recoveryCookie,
    );
    assert.equal((await request(`/api/devices/${firstRetryDevice.id}`, {
      method: 'DELETE', cookie: recoveryCookie,
    })).status, 200);
    const revokedIdentityRetry = await request('/api/devices', {
      method: 'POST', cookie: retryDeviceAccount.cookie,
      body: postRevocationAttempt,
    });
    assert.equal(revokedIdentityRetry.status, 401, 'revoking the bound device invalidates its session');
    const revokedIdentityWithFreshSession = await request('/api/devices', {
      method: 'POST', cookie: recoveryCookie, body: postRevocationAttempt,
    });
    assert.equal(revokedIdentityWithFreshSession.status, 409);
    assert.equal((await json<{ error: string }>(revokedIdentityWithFreshSession)).error, 'IDENTITY_REVOKED');
    const enrollmentFixtureEpochs = await enrollmentDatabaseModule.db.query.channelKeyEpochs.findMany({
      where: inArray(enrollmentSchemaModule.channelKeyEpochs.channelId, enrollmentFixtureChannelIds),
    });
    assert.equal(enrollmentFixtureEpochs.length, 65);
    assert.equal(enrollmentFixtureEpochs.every((epoch) => epoch.status === 'aborted'), true);
    assert.equal((await enrollmentDatabaseModule.db.query.channelKeyEpochRecipients.findMany({
      where: inArray(enrollmentSchemaModule.channelKeyEpochRecipients.channelId, enrollmentFixtureChannelIds),
    })).length, 0);
    assert.equal((await enrollmentDatabaseModule.db.query.channelKeys.findMany({
      where: inArray(enrollmentSchemaModule.channelKeys.channelId, enrollmentFixtureChannelIds),
    })).length, 0);
    await enrollmentDatabaseModule.db.delete(enrollmentSchemaModule.channelKeyEpochs)
      .where(inArray(enrollmentSchemaModule.channelKeyEpochs.channelId, enrollmentFixtureChannelIds));
    await enrollmentDatabaseModule.db.delete(enrollmentSchemaModule.channels)
      .where(inArray(enrollmentSchemaModule.channels.id, enrollmentFixtureChannelIds));
    const recoveryState = await json<{
      historyRecoveryRequired: boolean;
      rotationRequired: boolean;
      canRotate: boolean;
      recipients: Array<{ deviceId: string; identityKey: string }>;
    }>(await request(`/api/channels/${recoveryChannel.id}/key-recipients`, { cookie: recoveryCookie }));
    assert.equal(recoveryState.historyRecoveryRequired, true);
    assert.equal(recoveryState.rotationRequired, true);
    assert.equal(recoveryState.canRotate, true);
    assert.deepEqual(recoveryState.recipients.map((recipient) => recipient.deviceId), [recoveryDevice.id]);
    const recoveredChannelKey = randomBytes(32);
    await distributeAndAcknowledgeChannelKey({
      channelId: recoveryChannel.id,
      version: 3,
      rawKey: recoveredChannelKey,
      senderCookie: recoveryCookie,
      senderKeys: recoveryKeys,
      recipients: recoveryState.recipients,
      acknowledgements: [{ deviceId: recoveryDevice.id, cookie: recoveryCookie, keys: recoveryKeys }],
    });
    const recoveredWrite = await request(`/api/channels/${recoveryChannel.id}/messages`, {
      method: 'POST', cookie: recoveryCookie,
      body: encryptedMessage(
        recoveryChannel.id,
        retryDeviceAccount.user.id,
        recoveryDevice.id,
        recoveryKeys.signingPrivateKey,
        recoveredChannelKey,
        'future writes survive total key-holder loss',
        undefined,
        3,
      ).body,
    });
    assert.equal(recoveredWrite.status, 201);
    const recoveryAudit = await json<{ data: Array<{ action: string }> }>(await request(
      `/api/workspaces/${recoveryWorkspace.id}/audit-logs?limit=100`,
      { method: 'POST', cookie: recoveryCookie, body: {} },
    ));
    assert.equal(recoveryAudit.data.some((entry) => entry.action === 'channel.key.epoch.recovery.propose'), true);
    assert.equal(recoveryAudit.data.some((entry) => entry.action === 'channel.key.epoch.fresh_start'), true);
    // Keep this account from becoming an unintended recipient in the shared
    // workspace scenarios below. Self-revocation also proves that the newly
    // recovered epoch remains subject to the same fail-closed holder-loss rule.
    assert.equal((await request(`/api/devices/${recoveryDevice.id}`, {
      method: 'DELETE', cookie: recoveryCookie,
    })).status, 200);

    const outsiderWorkspaceResponse = await request('/api/workspaces', {
      method: 'POST', cookie: alice.cookie, body: { name: 'Outsider Test' },
    });
    assert.equal(outsiderWorkspaceResponse.status, 201);
    const outsiderWorkspace = await json<{ id: string }>(outsiderWorkspaceResponse);
    const existingAccountInvitation = await createWorkspaceInvitation(outsiderWorkspace.id, alice.cookie, 'bob@example.test');
    const acceptExisting = await request('/api/invitations/accept', {
      method: 'POST', cookie: bob.cookie, body: { token: existingAccountInvitation.token },
    });
    assert.equal(acceptExisting.status, 200);
    const reuseExisting = await request('/api/invitations/accept', {
      method: 'POST', cookie: bob.cookie, body: { token: existingAccountInvitation.token },
    });
    assert.equal(reuseExisting.status, 403);
    const malloryInvitation = await createWorkspaceInvitation(outsiderWorkspace.id, alice.cookie, 'mallory@example.test');
    const mallory = await createAccount('mallory@example.test', 'Correct-Horse-Battery-3!', 'Mallory', malloryInvitation.token);

    const revokedInvitation = await createWorkspaceInvitation(workspace.id, alice.cookie, 'revoked@example.test');
    const revokeResponse = await request(`/api/workspaces/${workspace.id}/invitations/${revokedInvitation.id}`, {
      method: 'DELETE', cookie: alice.cookie,
    });
    assert.equal(revokeResponse.status, 200);
    const revokedRegistration = await request('/api/auth/register', {
      method: 'POST',
      body: { email: 'revoked@example.test', password: 'Correct-Horse-Battery-7!', displayName: 'Revoked', inviteToken: revokedInvitation.token },
    });
    assert.equal(revokedRegistration.status, 403);

    const expiredInvitation = await createWorkspaceInvitation(workspace.id, alice.cookie, 'expired@example.test');
    const { db: invitationDb } = await import('../db/index.js');
    await invitationDb.execute(sql`UPDATE workspace_invitations SET expires_at = now() - interval '1 minute' WHERE id = ${expiredInvitation.id}`);
    assert.equal((await request('/api/auth/register', {
      method: 'POST',
      body: { email: 'expired@example.test', password: 'Correct-Horse-Battery-8!', displayName: 'Expired', inviteToken: expiredInvitation.token },
    })).status, 403, 'an expired invitation must not admit a registration');

    const singleUseInvitation = await createWorkspaceInvitation(workspace.id, alice.cookie);
    const racingRegistrations = await Promise.all(['race-a@example.test', 'race-b@example.test'].map((email) => request('/api/auth/register', {
      method: 'POST',
      body: { email, password: 'Correct-Horse-Battery-9!', displayName: 'Race', inviteToken: singleUseInvitation.token },
    })));
    assert.deepEqual(racingRegistrations.map((response) => response.status).sort(), [201, 403],
      'a single-use invitation must be consumed at most once under concurrency');

    const bobKeys = deviceFixture();
    const malloryKeys = deviceFixture();
    const bobDevice = await registerDevice(bob, bobKeys, 'Bob test device');
    const malloryDevice = await registerDevice(mallory, malloryKeys, 'Mallory test device');

    // A channel left only with a non-manager who never held the active key
    // must not stay unwritable: that viewer may start fresh after step-up,
    // while automatic rotation stays manager-only.
    const orphanWorkspaceResponse = await request('/api/workspaces', {
      method: 'POST', cookie: alice.cookie, body: { name: 'Orphan recovery' },
    });
    assert.equal(orphanWorkspaceResponse.status, 201);
    const orphanWorkspace = await json<{ id: string }>(orphanWorkspaceResponse);
    const orphanChannelResponse = await request(`/api/workspaces/${orphanWorkspace.id}/channels`, {
      method: 'POST', cookie: alice.cookie, body: { name: 'orphan-check', isPrivate: true },
    });
    assert.equal(orphanChannelResponse.status, 201);
    const orphanChannel = await json<{ id: string }>(orphanChannelResponse);
    const holderOnly = await json<{ recipients: Array<{ deviceId: string; identityKey: string }> }>(
      await request(`/api/channels/${orphanChannel.id}/key-recipients`, { cookie: alice.cookie }),
    );
    assert.deepEqual(holderOnly.recipients.map((recipient) => recipient.deviceId), [aliceDevice.id]);
    await distributeAndAcknowledgeChannelKey({
      channelId: orphanChannel.id,
      version: 1,
      rawKey: randomBytes(32),
      senderCookie: alice.cookie,
      senderKeys: aliceKeys,
      recipients: holderOnly.recipients,
      acknowledgements: [{ deviceId: aliceDevice.id, cookie: alice.cookie, keys: aliceKeys }],
    });
    const orphanInvitation = await createWorkspaceInvitation(orphanWorkspace.id, alice.cookie, 'mallory@example.test');
    assert.equal((await request('/api/invitations/accept', {
      method: 'POST', cookie: mallory.cookie, body: { token: orphanInvitation.token },
    })).status, 200);
    assert.equal((await request(`/api/channels/${orphanChannel.id}/members`, {
      method: 'POST', cookie: alice.cookie, body: { userId: mallory.user.id },
    })).status, 201);
    assert.equal((await request(`/api/channels/${orphanChannel.id}/members/${alice.user.id}`, {
      method: 'DELETE', cookie: alice.cookie,
    })).status, 200);
    const orphanState = await json<{
      historyRecoveryRequired: boolean;
      canRotate: boolean;
      nextVersion: number;
      recipients: Array<{ deviceId: string; identityKey: string }>;
    }>(await request(`/api/channels/${orphanChannel.id}/key-recipients`, { cookie: mallory.cookie }));
    assert.equal(orphanState.historyRecoveryRequired, true);
    assert.equal(orphanState.canRotate, false, 'automatic rotation stays manager-only');
    assert.deepEqual(orphanState.recipients.map((recipient) => recipient.deviceId), [malloryDevice.id]);
    const { io: orphanIo } = await import('socket.io-client');
    const orphanManagerSocket = orphanIo(baseUrl, {
      transports: ['websocket'],
      extraHeaders: { Cookie: alice.cookie, Origin: 'http://localhost:5173' },
    });
    sockets.push(orphanManagerSocket);
    await onceConnected(orphanManagerSocket);
    const managerNotice = onceSocketEventMatching<{ kind: string; workspaceId: string; channelId: string }>(
      orphanManagerSocket, 'attention:new', (payload) => payload.kind === 'channel-restarted', 5_000,
    );
    const orphanKey = randomBytes(32);
    const { keyCommitment: orphanCommitment, keys: orphanWraps } = await proposeFixtureMls({
      channelId: orphanChannel.id, version: orphanState.nextVersion, rawKey: orphanKey,
      senderCookie: mallory.cookie, senderKeys: malloryKeys, recipients: orphanState.recipients, fresh: true,
    });
    const notice = await managerNotice;
    assert.equal(notice.workspaceId, orphanWorkspace.id, 'managers are told that earlier messages became unreadable');
    assert.equal(notice.channelId, orphanChannel.id);
    orphanManagerSocket.disconnect();
    const orphanAcknowledgement = await acknowledgeChannelKeyDelivery({
      channelId: orphanChannel.id,
      version: orphanState.nextVersion,
      keyCommitment: orphanCommitment,
      encryptedKey: orphanWraps[0].encryptedKey,
      deviceId: malloryDevice.id,
      cookie: mallory.cookie,
      keys: malloryKeys,
    });
    assert.equal(orphanAcknowledgement.status, 'active');
    assert.equal((await request(`/api/channels/${orphanChannel.id}/messages`, {
      method: 'POST', cookie: mallory.cookie,
      body: encryptedMessage(
        orphanChannel.id, mallory.user.id, malloryDevice.id, malloryKeys.signingPrivateKey, orphanKey,
        'the remaining member restarted the channel', undefined, orphanState.nextVersion,
      ).body,
    })).status, 201);

    const membersResponse = await request(`/api/workspaces/${workspace.id}/members`, { cookie: alice.cookie });
    assert.equal(membersResponse.status, 200);
    const memberDtos = await json<Array<{ user: Record<string, unknown> }>>(membersResponse);
    for (const member of memberDtos) {
      assert.equal(Object.hasOwn(member.user, 'email'), false);
      assert.equal(Object.hasOwn(member.user, 'passwordHash'), false);
      assert.equal(Object.hasOwn(member.user, 'password_hash'), false);
    }

    const selfOnlyDm = await request(`/api/workspaces/${workspace.id}/dms`, {
      method: 'POST', cookie: bob.cookie, body: { memberIds: [bob.user.id] },
    });
    assert.equal(selfOnlyDm.status, 400, 'a DM must retain another distinct participant');
    const dmResponse = await request(`/api/workspaces/${workspace.id}/dms`, {
      method: 'POST', cookie: alice.cookie, body: { memberIds: [bob.user.id] },
    });
    assert.equal(dmResponse.status, 201);
    const dm = await json<{ channelId: string; members: Array<{ id: string }> }>(dmResponse);
    assert.deepEqual(new Set(dm.members.map((member) => member.id)), new Set([alice.user.id, bob.user.id]));
    const replayedDm = await json<{ channelId: string }>(await request(`/api/workspaces/${workspace.id}/dms`, {
      method: 'POST', cookie: alice.cookie, body: { memberIds: [bob.user.id] },
    }));
    assert.equal(replayedDm.channelId, dm.channelId, 'the bulk snapshot reuses the exact normalized DM member set');
    assert.equal((await request(`/api/channels/${dm.channelId}`, {
      method: 'PUT', cookie: alice.cookie, body: { isPrivate: false },
    })).status, 404);
    assert.equal((await request(`/api/channels/${dm.channelId}/members`, {
      method: 'POST', cookie: alice.cookie, body: { userId: retryDeviceAccount.user.id },
    })).status, 404);
    assert.equal((await request(`/api/channels/${dm.channelId}/members/${bob.user.id}`, {
      method: 'DELETE', cookie: alice.cookie,
    })).status, 404);
    assert.equal((await request(`/api/workspaces/${workspace.id}/channels/${dm.channelId}/permission-overrides`, {
      cookie: alice.cookie,
    })).status, 404);
    assert.equal((await request(`/api/channels/${dm.channelId}`, {
      method: 'DELETE', cookie: alice.cookie,
    })).status, 404);
    const dmAfterRejectedMutations = await request(`/api/workspaces/${workspace.id}/dms`, { cookie: alice.cookie });
    assert.equal(dmAfterRejectedMutations.status, 200);
    const dmRows = await json<Array<{ channelId: string; members: Array<{ id: string }> }>>(dmAfterRejectedMutations);
    assert.deepEqual(
      new Set(dmRows.find((row) => row.channelId === dm.channelId)?.members.map((member) => member.id)),
      new Set([alice.user.id, bob.user.id]),
    );

    // A provisional epoch is never writable after only the proposer's ACK.
    // A poisoned immutable delivery cannot be overwritten; another eligible
    // participant can abort it and retry with a strictly higher version.
    const dmRecipientsResponse = await request(`/api/channels/${dm.channelId}/key-recipients`, {
      cookie: alice.cookie,
    });
    assert.equal(dmRecipientsResponse.status, 200);
    const dmRecipients = await json<{
      recipients: Array<{ deviceId: string; identityKey: string }>;
    }>(dmRecipientsResponse);
    const dmAliceRecipient = dmRecipients.recipients.find((recipient) => recipient.deviceId === aliceDevice.id);
    const dmBobRecipient = dmRecipients.recipients.find((recipient) => recipient.deviceId === bobDevice.id);
    assert.ok(dmAliceRecipient && dmBobRecipient);
    const provisionalDmKey = randomBytes(32);
    const { keyCommitment: provisionalDmCommitment, keys: provisionalWraps } = await proposeFixtureMls({
      channelId: dm.channelId, version: 1, rawKey: provisionalDmKey, senderCookie: alice.cookie,
      senderKeys: aliceKeys, recipients: dmRecipients.recipients, poisonWelcome: true,
    });
    const provisionalAliceWrap = provisionalWraps.find(k => k.deviceId === aliceDevice.id)!;
    const provisionalBobWrap = provisionalWraps.find(k => k.deviceId === bobDevice.id)!;
    const provisionalAliceAcknowledgement = await acknowledgeChannelKeyDelivery({
      channelId: dm.channelId,
      version: 1,
      keyCommitment: provisionalDmCommitment,
      encryptedKey: provisionalAliceWrap.encryptedKey,
      deviceId: aliceDevice.id,
      cookie: alice.cookie,
      keys: aliceKeys,
    });
    assert.equal(provisionalAliceAcknowledgement.status, 'pending');
    assert.equal(provisionalAliceAcknowledgement.activated, false);
    assert.equal((await request(`/api/channels/${dm.channelId}/messages`, {
      method: 'POST',
      cookie: alice.cookie,
      body: encryptedMessage(
        dm.channelId,
        alice.user.id,
        aliceDevice.id,
        aliceKeys.signingPrivateKey,
        provisionalDmKey,
        'a self-acknowledged pending epoch must not be writable',
      ).body,
    })).status, 400);

    const changedBobWrap = signedChannelKeyWrap({
      channelId: dm.channelId,
      version: 1,
      keyCommitment: provisionalDmCommitment,
      rawKey: provisionalDmKey,
      recipient: dmBobRecipient,
      senderKeys: aliceKeys,
    });
    assert.equal((await request(`/api/channels/${dm.channelId}/keys`, {
      method: 'POST',
      cookie: alice.cookie,
      body: { version: 1, keyCommitment: provisionalDmCommitment, keys: [changedBobWrap] },
    })).status, 409, 'one distributor cannot replace its immutable delivery candidate');
    assert.throws(() => unwrapKey(provisionalBobWrap.encryptedKey, bobKeys.encryptionPrivateKey), 'a malformed Welcome cannot be joined');

    const abortSignature = sign('sha256', Buffer.from(serializeChannelKeyEpochAbort({
      channelId: dm.channelId,
      keyVersion: 1,
      keyCommitment: provisionalDmCommitment,
      deviceId: bobDevice.id,
    })), {
      key: bobKeys.signingPrivateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64');
    const abortResponse = await request(`/api/channels/${dm.channelId}/keys/abort`, {
      method: 'POST',
      cookie: bob.cookie,
      body: { version: 1, keyCommitment: provisionalDmCommitment, signature: abortSignature },
    });
    assert.equal(abortResponse.status, 200);
    assert.deepEqual(await json<{ version: number; status: string }>(abortResponse), {
      version: 1,
      status: 'aborted',
    });
    const dmAfterAbort = await json<{
      currentVersion: number;
      pendingVersion: number | null;
      nextVersion: number;
      canRotate: boolean;
      canAbortPending: boolean;
    }>(await request(`/api/channels/${dm.channelId}/key-recipients`, { cookie: bob.cookie }));
    assert.equal(dmAfterAbort.currentVersion, 0);
    assert.equal(dmAfterAbort.pendingVersion, null);
    assert.equal(dmAfterAbort.nextVersion, 2);
    assert.equal(dmAfterAbort.canRotate, true);
    assert.equal(dmAfterAbort.canAbortPending, false);
    assert.deepEqual(
      await json<unknown[]>(await request(`/api/channels/${dm.channelId}/keys`, { cookie: bob.cookie })),
      [],
      'aborted provisional delivery material is removed',
    );

    const activeDmKey = randomBytes(32);
    await distributeAndAcknowledgeChannelKey({
      channelId: dm.channelId,
      version: 2,
      rawKey: activeDmKey,
      senderCookie: bob.cookie,
      senderKeys: bobKeys,
      recipients: dmRecipients.recipients,
      acknowledgements: [
        { deviceId: bobDevice.id, cookie: bob.cookie, keys: bobKeys },
        { deviceId: aliceDevice.id, cookie: alice.cookie, keys: aliceKeys },
      ],
    });
    const forbiddenVersionThreeKey = randomBytes(32);
    const forbiddenVersionThreeCommitment = createHash('sha256')
      .update(forbiddenVersionThreeKey)
      .digest('base64url');
    const forbiddenVersionThreeWraps = dmRecipients.recipients.map((recipient) => signedChannelKeyWrap({
      channelId: dm.channelId,
      version: 3,
      keyCommitment: forbiddenVersionThreeCommitment,
      rawKey: forbiddenVersionThreeKey,
      recipient,
      senderKeys: aliceKeys,
    }));
    assert.equal((await request(`/api/channels/${dm.channelId}/keys`, {
      method: 'POST',
      cookie: alice.cookie,
      body: {
        version: 3,
        keyCommitment: forbiddenVersionThreeCommitment,
        keys: forbiddenVersionThreeWraps,
      },
    })).status, 409, 'legacy group proposals are refused even for a healthy active epoch');
    const healthyDmState = await json<{
      currentVersion: number;
      pendingVersion: number | null;
      rotationRequired: boolean;
    }>(await request(`/api/channels/${dm.channelId}/key-recipients`, { cookie: alice.cookie }));
    assert.equal(healthyDmState.currentVersion, 2);
    assert.equal(healthyDmState.pendingVersion, null);
    assert.equal(healthyDmState.rotationRequired, false);

    const forbiddenWorkspace = await request(`/api/workspaces/${workspace.id}`, { cookie: mallory.cookie });
    assert.notEqual(forbiddenWorkspace.status, 200);
    const unauthorizedInvite = await request(`/api/workspaces/${workspace.id}/invite`, {
      method: 'POST', cookie: bob.cookie, body: { userId: mallory.user.id },
    });
    assert.equal(unauthorizedInvite.status, 404, 'legacy direct-add endpoint must not exist');

    const categoryResponse = await request(`/api/workspaces/${workspace.id}/categories`, {
      method: 'POST', cookie: alice.cookie, body: { name: 'Temporary', position: 7 },
    });
    assert.equal(categoryResponse.status, 201);
    const category = await json<{ id: string }>(categoryResponse);
    const forbiddenCategoryUpdate = await request(`/api/workspaces/${workspace.id}/categories/${category.id}`, {
      method: 'PUT', cookie: bob.cookie, body: { position: 8 },
    });
    assert.equal(forbiddenCategoryUpdate.status, 403);
    const categoryUpdate = await request(`/api/workspaces/${workspace.id}/categories/${category.id}`, {
      method: 'PUT', cookie: alice.cookie, body: { name: 'Temporary Updated', position: 8 },
    });
    assert.equal(categoryUpdate.status, 200);
    const categorizedChannelResponse = await request(`/api/workspaces/${workspace.id}/channels`, {
      method: 'POST', cookie: alice.cookie, body: { name: 'temporary-channel', categoryId: category.id, position: 100 },
    });
    assert.equal(categorizedChannelResponse.status, 201);
    const categorizedChannel = await json<{ id: string }>(categorizedChannelResponse);
    const categoryDelete = await request(`/api/workspaces/${workspace.id}/categories/${category.id}`, {
      method: 'DELETE', cookie: alice.cookie,
    });
    assert.equal(categoryDelete.status, 200);
    assert.equal((await json<{ movedChannelIds: string[] }>(categoryDelete)).movedChannelIds.includes(categorizedChannel.id), true);
    const movedChannelResponse = await request(`/api/channels/${categorizedChannel.id}`, { cookie: alice.cookie });
    assert.equal(movedChannelResponse.status, 200);
    assert.equal((await json<{ categoryId: string | null }>(movedChannelResponse)).categoryId, null);
    const makePrivate = await request(`/api/channels/${categorizedChannel.id}`, {
      method: 'PUT', cookie: alice.cookie, body: { isPrivate: true },
    });
    assert.equal(makePrivate.status, 200);
    assert.equal((await request(`/api/channels/${categorizedChannel.id}`, { cookie: bob.cookie })).status, 404);
    const makePublic = await request(`/api/channels/${categorizedChannel.id}`, {
      method: 'PUT', cookie: alice.cookie, body: { isPrivate: false },
    });
    assert.equal(makePublic.status, 200);
    assert.equal((await request(`/api/channels/${categorizedChannel.id}`, { cookie: bob.cookie })).status, 200);

    const rolesResponse = await request(`/api/workspaces/${workspace.id}/roles`, { cookie: alice.cookie });
    assert.equal(rolesResponse.status, 200);
    const workspaceRoles = await json<Array<{ id: string; name: string; permissionMask: number }>>(rolesResponse);
    const ownerRole = workspaceRoles.find((role) => role.name === 'Owner');
    const memberRole = workspaceRoles.find((role) => role.name === 'Member');
    assert.ok(ownerRole);
    assert.ok(memberRole);
    const ownerProtectionRevisionResponse = await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST', cookie: alice.cookie,
      body: { operation: 'role.update', roleId: memberRole.id, permissions: memberRole.permissionMask },
    });
    assert.equal(ownerProtectionRevisionResponse.status, 200);
    const ownerProtectionRevision = (await json<{ authorizationRevision: string }>(ownerProtectionRevisionResponse)).authorizationRevision;
    const ownerDelete = await request(`/api/workspaces/${workspace.id}/roles/${ownerRole.id}`, {
      method: 'DELETE', cookie: alice.cookie, body: { expectedAuthorizationRevision: ownerProtectionRevision },
    });
    assert.equal(ownerDelete.status, 409);
    const invalidRole = await request(`/api/workspaces/${workspace.id}/roles`, {
      method: 'POST', cookie: alice.cookie, body: { name: 'Unknown Bit', permissions: 1 << 20, position: 10 },
    });
    assert.equal(invalidRole.status, 400);
    const reviewerRoleResponse = await request(`/api/workspaces/${workspace.id}/roles`, {
      method: 'POST', cookie: alice.cookie, body: { name: 'Reviewer', permissions: Permissions.VIEW_AUDIT_LOG, position: 10 },
    });
    assert.equal(reviewerRoleResponse.status, 201);
    const reviewerRole = await json<{ id: string }>(reviewerRoleResponse);
    assert.equal((await request(`/api/workspaces/${workspace.id}/audit-logs`, {
      method: 'POST', cookie: bob.cookie, body: {},
    })).status, 403);
    assert.equal((await request(`/api/workspaces/${workspace.id}/audit-integrity`, {
      method: 'POST', cookie: bob.cookie, body: {},
    })).status, 403);
    const assignmentPreview = await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST',
      cookie: alice.cookie,
      body: { operation: 'role.assign', roleId: reviewerRole.id, userId: bob.user.id },
    });
    assert.equal(assignmentPreview.status, 200);
    const assignmentPreviewBody = await json<{ affectedUserIds: string[]; authorizationRevision: string }>(assignmentPreview);
    assert.equal(assignmentPreviewBody.affectedUserIds.includes(bob.user.id), true);
    const revisionBump = await request(`/api/workspaces/${workspace.id}/roles`, {
      method: 'POST', cookie: alice.cookie,
      body: { name: 'Revision Bump', permissions: Permissions.VIEW_CHANNELS, position: 9 },
    });
    assert.equal(revisionBump.status, 201);
    const revisionBumpRole = await json<{ id: string }>(revisionBump);
    const staleAssignment = await request(`/api/workspaces/${workspace.id}/members/${bob.user.id}/roles/${reviewerRole.id}`, {
      method: 'POST', cookie: alice.cookie,
      body: { expectedAuthorizationRevision: assignmentPreviewBody.authorizationRevision },
    });
    assert.equal(staleAssignment.status, 409);
    assert.equal((await json<{ error: string }>(staleAssignment)).error, 'STALE_PREVIEW');
    const freshAssignmentPreview = await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST', cookie: alice.cookie,
      body: { operation: 'role.assign', roleId: reviewerRole.id, userId: bob.user.id },
    });
    assert.equal(freshAssignmentPreview.status, 200);
    const freshAuthorizationRevision = (await json<{ authorizationRevision: string }>(freshAssignmentPreview)).authorizationRevision;
    const assignment = await request(`/api/workspaces/${workspace.id}/members/${bob.user.id}/roles/${reviewerRole.id}`, {
      method: 'POST', cookie: alice.cookie, body: { expectedAuthorizationRevision: freshAuthorizationRevision },
    });
    assert.equal(assignment.status, 200);
    const memberManagerResponse = await request(`/api/workspaces/${workspace.id}/roles`, {
      method: 'POST', cookie: alice.cookie,
      body: { name: 'Member Manager Without Kick', permissions: Permissions.MANAGE_MEMBERS, position: 60 },
    });
    assert.equal(memberManagerResponse.status, 201);
    const memberManager = await json<{ id: string }>(memberManagerResponse);
    await assignWorkspaceRole(workspace.id, alice.cookie, memberManager.id, bob.user.id);
    assert.equal((await request(`/api/workspaces/${workspace.id}/members/${retryDeviceAccount.user.id}`, {
      method: 'DELETE', cookie: bob.cookie,
    })).status, 403, 'MANAGE_MEMBERS must not imply KICK_MEMBERS');

    const kickerRoleResponse = await request(`/api/workspaces/${workspace.id}/roles`, {
      method: 'POST', cookie: alice.cookie,
      body: { name: 'Limited Kicker', permissions: Permissions.KICK_MEMBERS, position: 61 },
    });
    assert.equal(kickerRoleResponse.status, 201);
    const kickerRole = await json<{ id: string }>(kickerRoleResponse);
    const protectedRoleResponse = await request(`/api/workspaces/${workspace.id}/roles`, {
      method: 'POST', cookie: alice.cookie,
      body: { name: 'Protected Member', permissions: 0, position: 70 },
    });
    assert.equal(protectedRoleResponse.status, 201);
    const protectedRole = await json<{ id: string }>(protectedRoleResponse);
    await assignWorkspaceRole(workspace.id, alice.cookie, kickerRole.id, bob.user.id);
    await assignWorkspaceRole(workspace.id, alice.cookie, protectedRole.id, retryDeviceAccount.user.id);
    assert.equal((await request(`/api/workspaces/${workspace.id}/members/${retryDeviceAccount.user.id}`, {
      method: 'DELETE', cookie: bob.cookie,
    })).status, 403, 'a kicker must not remove an equal-or-higher ranked member');
    const limitedRoleManagerResponse = await request(`/api/workspaces/${workspace.id}/roles`, {
      method: 'POST', cookie: alice.cookie,
      body: { name: 'Limited Role Manager', permissions: Permissions.MANAGE_ROLES, position: 62 },
    });
    assert.equal(limitedRoleManagerResponse.status, 201);
    const limitedRoleManager = await json<{ id: string }>(limitedRoleManagerResponse);
    await assignWorkspaceRole(workspace.id, alice.cookie, limitedRoleManager.id, bob.user.id);
    const higherMemberUnassignPreview = await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST', cookie: bob.cookie,
      body: { operation: 'role.unassign', roleId: reviewerRole.id, userId: retryDeviceAccount.user.id },
    });
    assert.equal(higherMemberUnassignPreview.status, 403, 'role removal preview must respect the target member rank');
    const managerRevisionPreview = await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST', cookie: bob.cookie,
      body: { operation: 'role.assign', roleId: reviewerRole.id, userId: bob.user.id },
    });
    assert.equal(managerRevisionPreview.status, 200);
    const managerRevision = (await json<{ authorizationRevision: string }>(managerRevisionPreview)).authorizationRevision;
    assert.equal((await request(`/api/workspaces/${workspace.id}/members/${retryDeviceAccount.user.id}/roles/${memberRole.id}`, {
      method: 'DELETE', cookie: bob.cookie, body: { expectedAuthorizationRevision: managerRevision },
    })).status, 403, 'a role manager must not strip roles from an equal-or-higher ranked member');
    assert.equal((await request(`/api/workspaces/${workspace.id}/members/${alice.user.id}/roles/${memberRole.id}`, {
      method: 'DELETE', cookie: bob.cookie, body: { expectedAuthorizationRevision: managerRevision },
    })).status, 403, 'a role manager must not strip roles from the workspace owner');
    const managerSelfRemovalPreview = await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST', cookie: bob.cookie,
      body: { operation: 'role.unassign', roleId: limitedRoleManager.id, userId: bob.user.id },
    });
    assert.equal(managerSelfRemovalPreview.status, 403, 'a role at the actor rank still cannot be managed');

    // Role edits, overrides and assignment must not reduce a higher-ranked member either.
    const hierarchyChannelResponse = await request(`/api/workspaces/${workspace.id}/channels`, {
      method: 'POST', cookie: alice.cookie, body: { name: 'hierarchy-check' },
    });
    assert.equal(hierarchyChannelResponse.status, 201);
    const hierarchyChannel = await json<{ id: string }>(hierarchyChannelResponse);
    const channelManagerResponse = await request(`/api/workspaces/${workspace.id}/roles`, {
      method: 'POST', cookie: alice.cookie,
      body: { name: 'Limited Channel Manager', permissions: Permissions.MANAGE_CHANNELS, position: 62 },
    });
    assert.equal(channelManagerResponse.status, 201);
    const channelManager = await json<{ id: string }>(channelManagerResponse);
    await assignWorkspaceRole(workspace.id, alice.cookie, channelManager.id, bob.user.id);
    const bobRevision = async () => (await json<{ authorizationRevision: string }>(await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST', cookie: bob.cookie,
      body: { operation: 'role.assign', roleId: reviewerRole.id, userId: bob.user.id },
    }))).authorizationRevision;
    const overridePath = (roleId: string) => `/api/workspaces/${workspace.id}/channels/${hierarchyChannel.id}/permission-overrides/${roleId}`;
    const sharedRoleDenyPreview = await request(`/api/workspaces/${workspace.id}/channels/${hierarchyChannel.id}/permission-overrides/preview`, {
      method: 'POST', cookie: bob.cookie,
      body: { operation: 'upsert', roleId: memberRole.id, allowMask: 0, denyMask: Permissions.SEND_MESSAGES },
    });
    assert.equal(sharedRoleDenyPreview.status, 403, 'a deny on a role shared with a higher member must be refused in preview');
    assert.equal((await json<{ error: string }>(sharedRoleDenyPreview)).error, 'MEMBER_HIERARCHY');
    assert.equal((await request(overridePath(memberRole.id), {
      method: 'PUT', cookie: bob.cookie,
      body: { allowMask: 0, denyMask: Permissions.SEND_MESSAGES, expectedRevision: 0, expectedAuthorizationRevision: await bobRevision() },
    })).status, 403, 'a deny on a role shared with a higher member must be refused');
    const mutedRoleResponse = await request(`/api/workspaces/${workspace.id}/roles`, {
      method: 'POST', cookie: bob.cookie, body: { name: 'Muted Here', permissions: 0, position: 10 },
    });
    assert.equal(mutedRoleResponse.status, 201);
    const mutedRole = await json<{ id: string }>(mutedRoleResponse);
    assert.equal((await request(overridePath(mutedRole.id), {
      method: 'PUT', cookie: bob.cookie,
      body: { allowMask: 0, denyMask: Permissions.SEND_MESSAGES, expectedRevision: 0, expectedAuthorizationRevision: await bobRevision() },
    })).status, 200, 'an override on an unassigned lower role affects nobody');
    assert.equal((await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST', cookie: bob.cookie,
      body: { operation: 'role.assign', roleId: mutedRole.id, userId: retryDeviceAccount.user.id },
    })).status, 403, 'assigning a deny-carrying role to a higher member must be refused in preview');
    assert.equal((await request(`/api/workspaces/${workspace.id}/members/${retryDeviceAccount.user.id}/roles/${mutedRole.id}`, {
      method: 'POST', cookie: bob.cookie, body: { expectedAuthorizationRevision: await bobRevision() },
    })).status, 403, 'assigning a deny-carrying role to a higher member must be refused');
    assert.equal((await request(`/api/workspaces/${workspace.id}/members/${bob.user.id}/roles/${mutedRole.id}`, {
      method: 'POST', cookie: bob.cookie, body: { expectedAuthorizationRevision: await bobRevision() },
    })).status, 200, 'an actor may still restrict itself');
    assert.equal((await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST', cookie: bob.cookie,
      body: { operation: 'role.update', roleId: memberRole.id, permissions: memberRole.permissionMask & ~Permissions.SEND_MESSAGES },
    })).status, 403, 'editing a role shared with a higher member must be refused when it reduces them');
    const privateHierarchyResponse = await request(`/api/workspaces/${workspace.id}/channels`, {
      method: 'POST', cookie: alice.cookie, body: { name: 'hierarchy-private', isPrivate: true },
    });
    assert.equal(privateHierarchyResponse.status, 201);
    const privateHierarchy = await json<{ id: string }>(privateHierarchyResponse);
    for (const userId of [bob.user.id, retryDeviceAccount.user.id]) {
      assert.equal((await request(`/api/channels/${privateHierarchy.id}/members`, {
        method: 'POST', cookie: alice.cookie, body: { userId },
      })).status, 201);
    }
    const superiorRemoval = await request(`/api/channels/${privateHierarchy.id}/members/${retryDeviceAccount.user.id}`, {
      method: 'DELETE', cookie: bob.cookie,
    });
    assert.equal(superiorRemoval.status, 403, 'a lower channel manager must not remove a higher member from a private channel');
    assert.equal((await json<{ error: string }>(superiorRemoval)).error, 'MEMBER_HIERARCHY');
    assert.equal((await request(`/api/channels/${privateHierarchy.id}/members/${bob.user.id}`, {
      method: 'DELETE', cookie: bob.cookie,
    })).status, 200, 'a member may still leave a private channel');
    assert.equal((await request(`/api/channels/${privateHierarchy.id}/members/${retryDeviceAccount.user.id}`, {
      method: 'DELETE', cookie: alice.cookie,
    })).status, 200, 'the owner may remove anyone');
    assert.equal((await request(`/api/channels/${privateHierarchy.id}`, { method: 'DELETE', cookie: alice.cookie })).status, 200);
    const ownerRemovesChannelManager = await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST', cookie: alice.cookie,
      body: { operation: 'role.unassign', roleId: channelManager.id, userId: bob.user.id },
    });
    assert.equal((await request(`/api/workspaces/${workspace.id}/members/${bob.user.id}/roles/${channelManager.id}`, {
      method: 'DELETE', cookie: alice.cookie,
      body: { expectedAuthorizationRevision: (await json<{ authorizationRevision: string }>(ownerRemovesChannelManager)).authorizationRevision },
    })).status, 200);
    assert.equal((await request(`/api/channels/${hierarchyChannel.id}`, { method: 'DELETE', cookie: alice.cookie })).status, 200);
    const ownerRemovesManager = await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST', cookie: alice.cookie,
      body: { operation: 'role.unassign', roleId: limitedRoleManager.id, userId: bob.user.id },
    });
    assert.equal(ownerRemovesManager.status, 200);
    assert.equal((await request(`/api/workspaces/${workspace.id}/members/${bob.user.id}/roles/${limitedRoleManager.id}`, {
      method: 'DELETE', cookie: alice.cookie,
      body: { expectedAuthorizationRevision: (await json<{ authorizationRevision: string }>(ownerRemovesManager)).authorizationRevision },
    })).status, 200);
    const blockedDeletePreview = await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST', cookie: alice.cookie, body: { operation: 'role.delete', roleId: reviewerRole.id },
    });
    assert.equal(blockedDeletePreview.status, 409);
    const effectiveResponse = await request(`/api/workspaces/${workspace.id}/members/${bob.user.id}/permissions`, { cookie: alice.cookie });
    assert.equal(effectiveResponse.status, 200);
    const effective = await json<{ permissionDetails: Array<{ permission: string; allowed: boolean; reasons: Array<{ roleId: string }> }> }>(effectiveResponse);
    const auditPermission = effective.permissionDetails.find((permission) => permission.permission === 'VIEW_AUDIT_LOG');
    assert.equal(auditPermission?.allowed, true);
    assert.equal(auditPermission?.reasons.some((reason) => reason.roleId === reviewerRole.id), true);
    const firstAuditView = await request(`/api/workspaces/${workspace.id}/audit-logs?limit=100`, {
      method: 'POST', cookie: bob.cookie, body: {},
    });
    assert.equal(firstAuditView.status, 200);
    const firstAuditBody = await json<{ data: Array<{ action: string; targetId: string | null; details: Record<string, unknown> | null }> }>(firstAuditView);
    assert.equal(firstAuditBody.data.some((entry) => entry.targetId === outsiderWorkspace.id), false);
    assert.equal(firstAuditBody.data.some((entry) => entry.details?.workspaceId === outsiderWorkspace.id), false);
    const secondAuditView = await request(`/api/workspaces/${workspace.id}/audit-logs?limit=100`, {
      method: 'POST', cookie: bob.cookie, body: {},
    });
    assert.equal(secondAuditView.status, 200);
    assert.equal((await json<{ data: Array<{ action: string }> }>(secondAuditView)).data.some((entry) => entry.action === 'audit.view'), true);
    const integrityResponse = await request(`/api/workspaces/${workspace.id}/audit-integrity`, {
      method: 'POST', cookie: bob.cookie, body: {},
    });
    assert.equal(integrityResponse.status, 200);
    assert.equal((await json<{ valid: boolean }>(integrityResponse)).valid, true);
    const outsiderRoles = await json<Array<{ id: string }>>(await request(`/api/workspaces/${outsiderWorkspace.id}/roles`, { cookie: alice.cookie }));
    const crossWorkspacePreview = await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST', cookie: alice.cookie,
      body: { operation: 'role.assign', roleId: reviewerRole.id, userId: bob.user.id },
    });
    const crossWorkspaceRevision = (await json<{ authorizationRevision: string }>(crossWorkspacePreview)).authorizationRevision;
    const crossWorkspaceAssignment = await request(`/api/workspaces/${workspace.id}/members/${bob.user.id}/roles/${outsiderRoles[0].id}`, {
      method: 'POST', cookie: alice.cookie, body: { expectedAuthorizationRevision: crossWorkspaceRevision },
    });
    assert.equal(crossWorkspaceAssignment.status, 404);

    const channelsResponse = await request(`/api/workspaces/${workspace.id}/channels`, { cookie: alice.cookie });
    const channels = await json<Array<{ id: string; type: string }>>(channelsResponse);
    const normalChannel = channels.find((channel) => channel.type !== 'dm');
    assert.ok(normalChannel);
    const channelId = normalChannel.id;
    assert.equal((await request(`/api/channels/${channelId}/messages`, { cookie: mallory.cookie })).status, 404);
    assert.equal((await request(`/api/channels/${channelId}/messages`, {
      method: 'POST', cookie: mallory.cookie, body: { encryptedContent: 'x' },
    })).status, 404, 'a non-member must not post into another workspace channel');

    const privateChannelResponse = await request(`/api/workspaces/${workspace.id}/channels`, {
      method: 'POST', cookie: alice.cookie, body: { name: 'private', isPrivate: true },
    });
    assert.equal(privateChannelResponse.status, 201);
    const privateChannel = await json<{ id: string }>(privateChannelResponse);
    assert.equal((await request(`/api/channels/${privateChannel.id}`, { cookie: bob.cookie })).status, 404);
    const lastPrivateMemberRemoval = await request(`/api/channels/${privateChannel.id}/members/${alice.user.id}`, {
      method: 'DELETE', cookie: alice.cookie,
    });
    assert.equal(lastPrivateMemberRemoval.status, 409);
    assert.equal((await json<{ error: string }>(lastPrivateMemberRemoval)).error, 'LAST_PRIVATE_MEMBER');

    const { io } = await import('socket.io-client');
    const aliceSocket = io(baseUrl, {
      transports: ['websocket'],
      extraHeaders: { Cookie: alice.cookie, Origin: 'http://localhost:5173' },
    });
    const mallorySocket = io(baseUrl, {
      transports: ['websocket'],
      extraHeaders: { Cookie: mallory.cookie, Origin: 'http://localhost:5173' },
    });
    sockets.push(aliceSocket, mallorySocket);
    await Promise.all([onceConnected(aliceSocket), onceConnected(mallorySocket)]);

    // Presence follows live connections: online while a socket is open,
    // offline after the last one closes, in both events and the member list.
    const memberStatusOf = async (userId: string) => (await json<Array<{ userId: string; user: { status: string } }>>(
      await request(`/api/workspaces/${workspace.id}/members`, { cookie: alice.cookie }),
    )).find((member) => member.userId === userId)?.user.status;
    const bobOnline = onceSocketEventMatching<{ userId: string; status: string }>(
      aliceSocket, 'presence:changed', (payload) => payload.userId === bob.user.id, 5_000,
    );
    const presenceSocket = io(baseUrl, {
      transports: ['websocket'],
      extraHeaders: { Cookie: bob.cookie, Origin: 'http://localhost:5173' },
    });
    sockets.push(presenceSocket);
    await onceConnected(presenceSocket);
    assert.equal((await bobOnline).status, 'online');
    assert.equal(await memberStatusOf(bob.user.id), 'online');
    const bobOffline = onceSocketEventMatching<{ userId: string; status: string }>(
      aliceSocket, 'presence:changed', (payload) => payload.userId === bob.user.id, 5_000,
    );
    presenceSocket.disconnect();
    assert.equal((await bobOffline).status, 'offline');
    assert.equal(await memberStatusOf(bob.user.id), 'offline');

    // Profiles: display name, self-introduction and avatar, visible only to
    // people who share a workspace; workspace-scoped warnings with a single
    // lifetime request to lift one. A dedicated owner keeps this independent.
    const profileHost = await json<{ id: string }>(await request('/api/workspaces', {
      method: 'POST', cookie: mallory.cookie, body: { name: 'Profile host' },
    }));
    const profileOwnerInvitation = await createWorkspaceInvitation(profileHost.id, mallory.cookie, 'profile-owner@example.test');
    const profileOwner = await createAccount('profile-owner@example.test', 'Correct-Horse-Battery-13!', 'Profile Owner', profileOwnerInvitation.token);
    await registerDevice(profileOwner, deviceFixture(), 'Profile owner device');
    const profileWorkspace = await json<{ id: string }>(await request('/api/workspaces', {
      method: 'POST', cookie: profileOwner.cookie, body: { name: 'Profiles' },
    }));
    const secondProfileWorkspace = await json<{ id: string }>(await request('/api/workspaces', {
      method: 'POST', cookie: profileOwner.cookie, body: { name: 'Profiles Two' },
    }));
    const subjectInvitation = await createWorkspaceInvitation(profileWorkspace.id, profileOwner.cookie, 'profile-subject@example.test');
    const subject = await createAccount('profile-subject@example.test', 'Correct-Horse-Battery-12!', 'Subject', subjectInvitation.token);
    await registerDevice(subject, deviceFixture(), 'Profile subject device');
    const secondSubjectInvitation = await createWorkspaceInvitation(secondProfileWorkspace.id, profileOwner.cookie, 'profile-subject@example.test');
    assert.equal((await request('/api/invitations/accept', {
      method: 'POST', cookie: subject.cookie, body: { token: secondSubjectInvitation.token },
    })).status, 200);
    const { io: profileIo } = await import('socket.io-client');
    const ownerSocket = profileIo(baseUrl, {
      transports: ['websocket'],
      extraHeaders: { Cookie: profileOwner.cookie, Origin: 'http://localhost:5173' },
    });
    sockets.push(ownerSocket);
    await onceConnected(ownerSocket);
    const profileUpdate = await request('/api/profile', {
      method: 'PATCH', cookie: subject.cookie, body: { displayName: 'Subject Renamed', bio: '  こんにちは\nよろしくお願いします ' },
    });
    assert.equal(profileUpdate.status, 200);
    const ownProfile = await json<{ displayName: string; bio: string; appealUsed: boolean }>(profileUpdate);
    assert.equal(ownProfile.displayName, 'Subject Renamed');
    assert.equal(ownProfile.bio, 'こんにちは\nよろしくお願いします');
    assert.equal((await request('/api/profile', { method: 'PATCH', cookie: subject.cookie, body: { bio: '1\n2\n3\n4\n5\n6' } })).status, 400);
    assert.equal((await request('/api/profile', { method: 'PATCH', cookie: subject.cookie, body: { displayName: '\u2800' } })).status, 400);
    const { db: profileDb } = await import('../db/index.js');
    const { auditLogs: profileAudit } = await import('../db/schema.js');
    const profileEvents = await profileDb.select().from(profileAudit).where(eq(profileAudit.action, 'user.profile.update'));
    assert.equal(profileEvents.length > 0, true);
    assert.equal(profileEvents.every((event) => event.actorId === subject.user.id
      && Object.keys((event.details ?? {}) as Record<string, unknown>).every((key) => ['requestId', 'traceId', 'result'].includes(key))), true,
      'profile changes are logged without their content');

    const pngChunk = (type: string, data: Buffer = Buffer.alloc(0)) => {
      const header = Buffer.alloc(8);
      header.writeUInt32BE(data.length, 0);
      header.write(type, 4, 'latin1');
      const crc = Buffer.alloc(4);
      crc.writeUInt32BE(crc32(data, crc32(Buffer.from(type, 'latin1'))) >>> 0);
      return Buffer.concat([header, data, crc]);
    };
    const avatarHeader = Buffer.alloc(13);
    avatarHeader.writeUInt32BE(256, 0);
    avatarHeader.writeUInt32BE(256, 4);
    avatarHeader.set([8, 6, 0, 0, 0], 8);
    const avatarPng = Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      pngChunk('IHDR', avatarHeader),
      pngChunk('tEXt', Buffer.from('Comment\0home address')),
      pngChunk('IDAT', deflateSync(Buffer.concat(Array.from({ length: 256 }, () => Buffer.concat([Buffer.from([0]), Buffer.alloc(1024, 7)]))))),
      pngChunk('IEND'),
    ]);
    assert.equal((await request('/api/profile/avatar', {
      method: 'PUT', cookie: subject.cookie, body: Buffer.from('<svg onload="alert(1)"/>'), contentType: 'image/png',
    })).status, 400);
    assert.equal((await request('/api/profile/avatar', {
      method: 'PUT', cookie: subject.cookie, body: avatarPng, contentType: 'image/svg+xml',
    })).status, 415);
    const avatarResponse = await request('/api/profile/avatar', { method: 'PUT', cookie: subject.cookie, body: avatarPng, contentType: 'image/png' });
    assert.equal(avatarResponse.status, 200);
    const { avatarUrl } = await json<{ avatarUrl: string }>(avatarResponse);
    assert.match(avatarUrl, new RegExp(`^/api/users/${subject.user.id}/avatar/[0-9a-f-]{36}$`));
    const servedAvatar = await request(avatarUrl, { cookie: profileOwner.cookie });
    assert.equal(servedAvatar.status, 200);
    assert.equal(servedAvatar.headers.get('content-type'), 'image/png');
    assert.equal(servedAvatar.headers.get('x-content-type-options'), 'nosniff');
    const servedBytes = Buffer.from(await servedAvatar.arrayBuffer());
    assert.equal(servedBytes.includes(Buffer.from('home address')), false, 'embedded text is removed before storage');
    assert.equal((await request(avatarUrl.replace(/[0-9a-f-]{36}$/, randomUUID()), { cookie: profileOwner.cookie })).status, 404);
    const sameAvatar = await request('/api/profile/avatar', { method: 'PUT', cookie: subject.cookie, body: avatarPng, contentType: 'image/png' });
    assert.equal((await json<{ avatarUrl: string }>(sameAvatar)).avatarUrl, avatarUrl, 'the picture already in use is not stored again');
    assert.equal((await fetch(`${baseUrl}${avatarUrl}`, { headers: { Origin: 'http://localhost:5173' } })).status, 401);
    assert.equal((await request(avatarUrl, { cookie: mallory.cookie })).status, 404, 'no shared workspace, no avatar');
    const profileMembers = await json<Array<{ userId: string; user: { displayName: string; avatarUrl: string | null } }>>(
      await request(`/api/workspaces/${profileWorkspace.id}/members`, { cookie: profileOwner.cookie }),
    );
    assert.equal(profileMembers.find((member) => member.userId === subject.user.id)?.user.avatarUrl, avatarUrl);

    const bobViewed = await json<{ bio: string; flagged: boolean; canManageFlag: boolean }>(
      await request(`/api/workspaces/${profileWorkspace.id}/members/${subject.user.id}/profile`, { cookie: profileOwner.cookie }),
    );
    assert.deepEqual([bobViewed.bio, bobViewed.flagged, bobViewed.canManageFlag], ['こんにちは\nよろしくお願いします', false, true]);
    assert.equal((await request(`/api/workspaces/${profileWorkspace.id}/members/${profileOwner.user.id}/profile-flag`, {
      method: 'PUT', cookie: subject.cookie, body: {},
    })).status, 403, 'nobody can flag the owner');
    assert.equal((await request(`/api/workspaces/${profileWorkspace.id}/members/${subject.user.id}/profile-flag`, {
      method: 'PUT', cookie: profileOwner.cookie, body: {},
    })).status, 200);
    const flaggedMembers = await json<Array<{ userId: string; profileFlagged?: boolean }>>(
      await request(`/api/workspaces/${profileWorkspace.id}/members`, { cookie: profileOwner.cookie }),
    );
    assert.equal(flaggedMembers.find((member) => member.userId === subject.user.id)?.profileFlagged, true);
    assert.equal(flaggedMembers.find((member) => member.userId === profileOwner.user.id)?.profileFlagged, false);
    const outsiderView = await json<{ flagged: boolean }>(
      await request(`/api/workspaces/${secondProfileWorkspace.id}/members/${subject.user.id}/profile`, { cookie: profileOwner.cookie }),
    );
    assert.equal(outsiderView.flagged, false, 'a warning applies to its own workspace only');

    const appealPath = `/api/workspaces/${profileWorkspace.id}/profile-flag/appeal`;
    const needsChange = await request(appealPath, { method: 'POST', cookie: subject.cookie, body: {} });
    assert.equal(needsChange.status, 409);
    assert.equal((await json<{ error: string }>(needsChange)).error, 'PROFILE_APPEAL_NEEDS_CHANGE');
    // Saving the same name, text or picture is not a change.
    assert.equal((await request('/api/profile', {
      method: 'PATCH', cookie: subject.cookie, body: { displayName: 'Subject Renamed', bio: 'こんにちは\nよろしくお願いします' },
    })).status, 200);
    assert.equal((await request('/api/profile/avatar', { method: 'PUT', cookie: subject.cookie, body: avatarPng, contentType: 'image/png' })).status, 200);
    assert.equal((await json<{ flags: Array<{ canAppeal: boolean }> }>(await request('/api/profile', { cookie: subject.cookie }))).flags[0].canAppeal, false);
    assert.equal((await json<{ error: string }>(await request(appealPath, { method: 'POST', cookie: subject.cookie, body: {} }))).error,
      'PROFILE_APPEAL_NEEDS_CHANGE');
    assert.equal((await request('/api/profile', { method: 'PATCH', cookie: subject.cookie, body: { bio: '内容を見直しました' } })).status, 200);
    assert.equal((await json<{ flags: Array<{ canAppeal: boolean }> }>(await request('/api/profile', { cookie: subject.cookie }))).flags[0].canAppeal, true);
    const appealNotice = onceSocketEventMatching<{ kind: string; workspaceId: string; channelId: string | null }>(
      ownerSocket, 'attention:new', (payload) => payload.kind === 'profile-appeal', 5_000,
    );
    assert.equal((await request(appealPath, { method: 'POST', cookie: subject.cookie, body: {} })).status, 200);
    const appealAlert = await appealNotice;
    assert.deepEqual([appealAlert.workspaceId, appealAlert.channelId], [profileWorkspace.id, null]);
    const secondAppeal = await request(appealPath, { method: 'POST', cookie: subject.cookie, body: {} });
    assert.equal(secondAppeal.status, 409);
    assert.equal((await json<{ error: string }>(secondAppeal)).error, 'PROFILE_APPEAL_USED');
    const pendingFlags = await json<Array<{ userId: string; appealStatus: string }>>(
      await request(`/api/workspaces/${profileWorkspace.id}/profile-flags`, { cookie: profileOwner.cookie }),
    );
    assert.equal(pendingFlags.find((flag) => flag.userId === subject.user.id)?.appealStatus, 'pending');
    assert.equal((await request(`/api/workspaces/${profileWorkspace.id}/members/${subject.user.id}/profile-flag/deny`, {
      method: 'POST', cookie: profileOwner.cookie, body: {},
    })).status, 200);
    assert.equal((await request(`/api/workspaces/${profileWorkspace.id}/profile-flags`, { cookie: subject.cookie })).status, 403,
      'only managers list warnings');
    // Denied: the warning stays and no further request is possible anywhere.
    assert.equal((await request(`/api/workspaces/${secondProfileWorkspace.id}/members/${subject.user.id}/profile-flag`, {
      method: 'PUT', cookie: profileOwner.cookie, body: {},
    })).status, 200);
    assert.equal((await request('/api/profile', { method: 'PATCH', cookie: subject.cookie, body: { bio: 'もう一度見直しました' } })).status, 200);
    const exhausted = await json<{ appealUsed: boolean; flags: Array<{ workspaceId: string; appealStatus: string; canAppeal: boolean }> }>(
      await request('/api/profile', { cookie: subject.cookie }),
    );
    assert.equal(exhausted.appealUsed, true);
    assert.equal(exhausted.flags.every((flag) => !flag.canAppeal), true);
    assert.equal((await request(`/api/workspaces/${secondProfileWorkspace.id}/profile-flag/appeal`, {
      method: 'POST', cookie: subject.cookie, body: {},
    })).status, 409, 'the single request is per account, across all workspaces');
    for (const flaggedWorkspaceId of [profileWorkspace.id, secondProfileWorkspace.id]) {
      assert.equal((await request(`/api/workspaces/${flaggedWorkspaceId}/members/${subject.user.id}/profile-flag`, {
        method: 'DELETE', cookie: profileOwner.cookie,
      })).status, 200, 'a manager can still clear the warning');
    }
    assert.equal((await request('/api/profile/avatar', { method: 'DELETE', cookie: subject.cookie })).status, 200);
    assert.equal((await request(avatarUrl, { cookie: profileOwner.cookie })).status, 404);

    // A warned member who leaves stays listed, so their old messages keep the picture hidden.
    assert.equal((await request(`/api/workspaces/${profileWorkspace.id}/members/${subject.user.id}/profile-flag`, {
      method: 'PUT', cookie: profileOwner.cookie, body: {},
    })).status, 200);
    assert.equal((await request(`/api/workspaces/${profileWorkspace.id}/members/${subject.user.id}`, {
      method: 'DELETE', cookie: profileOwner.cookie,
    })).status, 200);
    const warnedAfterLeaving = await json<{ userIds: string[]; complete: boolean }>(
      await request(`/api/workspaces/${profileWorkspace.id}/warned-users`, { cookie: profileOwner.cookie }),
    );
    assert.deepEqual(warnedAfterLeaving, { userIds: [subject.user.id], complete: true });
    assert.equal((await request(`/api/workspaces/${profileWorkspace.id}/warned-users`, { cookie: mallory.cookie })).status >= 400, true,
      'only members see who is warned');

    ownerSocket.disconnect();

    assert.equal(await joinChannel(aliceSocket, privateChannel.id), true);
    assert.equal(await joinChannel(mallorySocket, privateChannel.id), false);
    assert.equal(await joinChannel(aliceSocket, channelId), true);

    const recipientsResponse = await request(`/api/channels/${channelId}/key-recipients`, { cookie: alice.cookie });
    assert.equal(recipientsResponse.status, 200);
    const recipients = await json<{ recipients: Array<{ deviceId: string; identityKey: string }> }>(recipientsResponse);
    const rawChannelKey = randomBytes(32);
    const legacyUnsignedDistribution = await request(`/api/channels/${channelId}/keys`, {
      method: 'POST',
      cookie: alice.cookie,
      body: {
        version: 1,
        keys: recipients.recipients.map((recipient) => ({
          deviceId: recipient.deviceId,
          encryptedKey: wrapKey(rawChannelKey, recipient.identityKey),
        })),
      },
    });
    assert.equal(legacyUnsignedDistribution.status, 400);
    const committedDistribution = await distributeAndAcknowledgeChannelKey({
      channelId,
      version: 1,
      rawKey: rawChannelKey,
      senderCookie: alice.cookie,
      senderKeys: aliceKeys,
      recipients: recipients.recipients,
      acknowledgements: [
        { deviceId: aliceDevice.id, cookie: alice.cookie, keys: aliceKeys },
        { deviceId: bobDevice.id, cookie: bob.cookie, keys: bobKeys },
      ],
    });

    // Keep the new-device backfill notification isolated from the primary
    // message channel, because the secondary device is revoked later and that
    // correctly dirties every active epoch in which it accepted a delivery.
    const backfillChannelResponse = await request(`/api/workspaces/${workspace.id}/channels`, {
      method: 'POST', cookie: alice.cookie, body: { name: 'device-backfill' },
    });
    assert.equal(backfillChannelResponse.status, 201);
    const backfillChannel = await json<{ id: string }>(backfillChannelResponse);
    const backfillRecipients = await json<{
      recipients: Array<{ deviceId: string; identityKey: string }>;
    }>(await request(`/api/channels/${backfillChannel.id}/key-recipients`, { cookie: alice.cookie }));
    const backfillKey = randomBytes(32);
    const backfillDistribution = await distributeAndAcknowledgeChannelKey({
      channelId: backfillChannel.id,
      version: 1,
      rawKey: backfillKey,
      senderCookie: alice.cookie,
      senderKeys: aliceKeys,
      recipients: backfillRecipients.recipients,
      acknowledgements: [
        { deviceId: aliceDevice.id, cookie: alice.cookie, keys: aliceKeys },
        { deviceId: bobDevice.id, cookie: bob.cookie, keys: bobKeys },
      ],
    });
    assert.equal(await joinChannel(aliceSocket, backfillChannel.id), true);

    // Revocation must remain constant-work with respect to device history and
    // must fail closed at each channel's bounded active-recipient boundary.
    const secondaryLogin = await request('/api/auth/login', {
      method: 'POST',
      body: { email: 'alice@example.test', password: alice.password },
    });
    assert.equal(secondaryLogin.status, 200);
    const secondaryCookie = secondaryLogin.headers.get('set-cookie')!.split(';', 1)[0];
    const secondaryKeys = deviceFixture();
    const secondaryDevice = await registerDevice(
      { ...alice, cookie: secondaryCookie },
      secondaryKeys,
      'Alice revocation boundary device',
    );
    const postEnrollmentRecipients = await json<{
      recipients: Array<{ deviceId: string; identityKey: string }>;
    }>(await request(`/api/channels/${backfillChannel.id}/key-recipients`, { cookie: alice.cookie }));
    const secondaryBackfillRecipient = postEnrollmentRecipients.recipients.find(
      (recipient) => recipient.deviceId === secondaryDevice.id,
    );
    assert.ok(secondaryBackfillRecipient);
    const oldBackfill = await request(`/api/channels/${backfillChannel.id}/keys`, {
      method: 'POST', cookie: alice.cookie, body: { version: 1, keyCommitment: backfillDistribution.keyCommitment,
        keys: [signedChannelKeyWrap({ channelId: backfillChannel.id, version: 1, keyCommitment: backfillDistribution.keyCommitment, rawKey: backfillKey, recipient: secondaryBackfillRecipient, senderKeys: aliceKeys })] },
    });
    assert.equal(oldBackfill.status, 409, 'a new device receives a fresh epoch, never an old MLS secret');
    const backfillAvailable = onceSocketEventMatching<{channelId:string}>(aliceSocket, 'channel:key-rotation-required', event => event.channelId === backfillChannel.id);
    await distributeAndAcknowledgeChannelKey({ channelId: backfillChannel.id, version: 2, rawKey: backfillKey,
      senderCookie: alice.cookie, senderKeys: aliceKeys, recipients: postEnrollmentRecipients.recipients,
      acknowledgements: [{deviceId:aliceDevice.id,cookie:alice.cookie,keys:aliceKeys},{deviceId:bobDevice.id,cookie:bob.cookie,keys:bobKeys},{deviceId:secondaryDevice.id,cookie:secondaryCookie,keys:secondaryKeys}],
    });
    assert.equal((await backfillAvailable).channelId, backfillChannel.id);
    const revocationChannelResponse = await request(`/api/workspaces/${workspace.id}/channels`, {
      method: 'POST', cookie: alice.cookie, body: { name: 'revocation-boundary' },
    });
    assert.equal(revocationChannelResponse.status, 201);
    const revocationChannel = await json<{ id: string }>(revocationChannelResponse);
    const revocationRecipients = await json<{
      recipients: Array<{ deviceId: string; identityKey: string }>;
    }>(await request(`/api/channels/${revocationChannel.id}/key-recipients`, { cookie: alice.cookie }));
    assert.equal(revocationRecipients.recipients.some((entry) => entry.deviceId === secondaryDevice.id), true);
    const revocationChannelKey = randomBytes(32);
    await distributeAndAcknowledgeChannelKey({
      channelId: revocationChannel.id,
      version: 1,
      rawKey: revocationChannelKey,
      senderCookie: alice.cookie,
      senderKeys: aliceKeys,
      recipients: revocationRecipients.recipients,
      acknowledgements: [
        { deviceId: aliceDevice.id, cookie: alice.cookie, keys: aliceKeys },
        { deviceId: secondaryDevice.id, cookie: secondaryCookie, keys: secondaryKeys },
        { deviceId: bobDevice.id, cookie: bob.cookie, keys: bobKeys },
      ],
    });
    const pendingRevocationChannelResponse = await request(`/api/workspaces/${workspace.id}/channels`, {
      method: 'POST', cookie: alice.cookie, body: { name: 'pending-revocation-boundary' },
    });
    assert.equal(pendingRevocationChannelResponse.status, 201);
    const pendingRevocationChannel = await json<{ id: string }>(pendingRevocationChannelResponse);
    const pendingRevocationRecipients = await json<{
      recipients: Array<{ deviceId: string; identityKey: string }>;
    }>(await request(`/api/channels/${pendingRevocationChannel.id}/key-recipients`, { cookie: alice.cookie }));
    const pendingRevocationKey = randomBytes(32);
    const {keyCommitment: pendingRevocationCommitment, keys: _pendingRevocationWraps} = await proposeFixtureMls({
      channelId: pendingRevocationChannel.id, version: 1, rawKey: pendingRevocationKey,
      senderCookie: alice.cookie, senderKeys: aliceKeys, recipients: pendingRevocationRecipients.recipients,
    });
    assert.equal((await request(`/api/devices/${secondaryDevice.id}`, {
      method: 'DELETE', cookie: alice.cookie,
    })).status, 200);
    assert.equal((await request('/api/devices', { cookie: secondaryCookie })).status, 401);
    const blockedAfterRecipientRevocation = await request(`/api/channels/${revocationChannel.id}/messages`, {
      method: 'POST',
      cookie: alice.cookie,
      body: encryptedMessage(
        revocationChannel.id,
        alice.user.id,
        aliceDevice.id,
        aliceKeys.signingPrivateKey,
        revocationChannelKey,
        'must not be accepted after any active recipient is revoked',
      ).body,
    });
    assert.equal(blockedAfterRecipientRevocation.status, 400);
    const revocationState = await json<{
      rotationRequired: boolean;
      canRotate: boolean;
      recipients: Array<{ deviceId: string }>;
    }>(await request(`/api/channels/${revocationChannel.id}/key-recipients`, { cookie: alice.cookie }));
    assert.equal(revocationState.rotationRequired, true);
    assert.equal(revocationState.canRotate, true);
    assert.equal(revocationState.recipients.some((entry) => entry.deviceId === secondaryDevice.id), false);
    const postRevocationKey = randomBytes(32);
    await distributeAndAcknowledgeChannelKey({
      channelId: revocationChannel.id,
      version: 2,
      rawKey: postRevocationKey,
      senderCookie: alice.cookie,
      senderKeys: aliceKeys,
      recipients: await json<{ recipients: Array<{ deviceId: string; identityKey: string }> }>(
        await request(`/api/channels/${revocationChannel.id}/key-recipients`, { cookie: alice.cookie }),
      ).then((state) => state.recipients),
      acknowledgements: [
        { deviceId: aliceDevice.id, cookie: alice.cookie, keys: aliceKeys },
        { deviceId: bobDevice.id, cookie: bob.cookie, keys: bobKeys },
      ],
    });
    const acceptedAfterRevocationRotation = await request(`/api/channels/${revocationChannel.id}/messages`, {
      method: 'POST',
      cookie: alice.cookie,
      body: encryptedMessage(
        revocationChannel.id,
        alice.user.id,
        aliceDevice.id,
        aliceKeys.signingPrivateKey,
        postRevocationKey,
        'accepted after bounded revocation recovery',
        undefined,
        2,
      ).body,
    });
    assert.equal(acceptedAfterRevocationRotation.status, 201);

    const invalidPendingState = await json<{
      pendingVersion: number | null;
      pendingInvalid: boolean;
      canAbortPending: boolean;
    }>(await request(`/api/channels/${pendingRevocationChannel.id}/key-recipients`, { cookie: alice.cookie }));
    assert.equal(invalidPendingState.pendingVersion, 1);
    assert.equal(invalidPendingState.pendingInvalid, true);
    assert.equal(invalidPendingState.canAbortPending, true);
    const invalidPendingAbortSignature = sign('sha256', Buffer.from(serializeChannelKeyEpochAbort({
      channelId: pendingRevocationChannel.id,
      keyVersion: 1,
      keyCommitment: pendingRevocationCommitment,
      deviceId: aliceDevice.id,
    })), {
      key: aliceKeys.signingPrivateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64');
    assert.equal((await request(`/api/channels/${pendingRevocationChannel.id}/keys/abort`, {
      method: 'POST',
      cookie: alice.cookie,
      body: {
        version: 1,
        keyCommitment: pendingRevocationCommitment,
        signature: invalidPendingAbortSignature,
      },
    })).status, 200);
    const afterInvalidPendingAbort = await json<{ pendingVersion: number | null }>(
      await request(`/api/channels/${pendingRevocationChannel.id}/key-recipients`, { cookie: alice.cookie }),
    );
    assert.equal(afterInvalidPendingAbort.pendingVersion, null);
    assert.deepEqual(
      await json<unknown[]>(await request(`/api/channels/${pendingRevocationChannel.id}/keys`, { cookie: alice.cookie })),
      [],
      'aborting an invalid pending epoch removes every provisional delivery',
    );
    const databaseModule = await import('../db/index.js');
    const schemaModule = await import('../db/schema.js');
    assert.equal((await databaseModule.db.query.channelKeys.findMany({
      where: and(
        eq(schemaModule.channelKeys.channelId, pendingRevocationChannel.id),
        eq(schemaModule.channelKeys.version, 1),
      ),
    })).length, 0);
    assert.equal((await databaseModule.db.query.channelKeyEpochRecipients.findMany({
      where: and(
        eq(schemaModule.channelKeyEpochRecipients.channelId, pendingRevocationChannel.id),
        eq(schemaModule.channelKeyEpochRecipients.version, 1),
      ),
    })).length, 0);
    let revocationReplayDirtiedWorkspace = false;
    const onRevocationReplayDirty = () => { revocationReplayDirtiedWorkspace = true; };
    aliceSocket.on('workspace:key-state-dirty', onRevocationReplayDirty);
    assert.equal((await request(`/api/devices/${secondaryDevice.id}`, {
      method: 'DELETE', cookie: alice.cookie,
    })).status, 200, 'revocation replay remains idempotent and repairs stale sessions');
    await delay(75);
    aliceSocket.off('workspace:key-state-dirty', onRevocationReplayDirty);
    assert.equal(
      revocationReplayDirtiedWorkspace,
      false,
      'an idempotent revocation replay does not broadcast redundant workspace key dirtiness',
    );

    const aliceRecipient = recipients.recipients.find((recipient) => recipient.deviceId === aliceDevice.id);
    assert.ok(aliceRecipient);
    const poisonEncryptedKey = wrapKey(randomBytes(32), aliceRecipient.identityKey);
    const poisonSignature = sign('sha256', Buffer.from(serializeChannelKeyWrap({
      channelId,
      keyVersion: 1,
      keyCommitment: committedDistribution.keyCommitment,
      recipientDeviceId: aliceDevice.id,
      encryptedKey: poisonEncryptedKey,
    })), {
      key: bobKeys.signingPrivateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64');
    const confirmedWrapOverwrite = await request(`/api/channels/${channelId}/keys`, {
      method: 'POST',
      cookie: bob.cookie,
      body: {
        version: 1,
        keyCommitment: committedDistribution.keyCommitment,
        keys: [{ deviceId: aliceDevice.id, encryptedKey: poisonEncryptedKey, signature: poisonSignature }],
      },
    });
    assert.equal(confirmedWrapOverwrite.status, 409, 'a confirmed recipient wrap is immutable');

    const messageRequest = encryptedMessage(
      channelId,
      alice.user.id,
      aliceDevice.id,
      aliceKeys.signingPrivateKey,
      rawChannelKey,
      'server must never see this plaintext',
    );
    const createdRealtime = onceSocketEvent<{ message: Record<string, unknown> }>(aliceSocket, 'message:new');
    const messageResponse = await request(`/api/channels/${channelId}/messages`, {
      method: 'POST', cookie: alice.cookie, body: messageRequest.body,
    });
    assert.equal(messageResponse.status, 201);
    const message = await json<{ id: string; channelId: string; content: string; encryptedContent: string; author: Record<string, unknown> }>(messageResponse);
    assert.equal(message.content, '');
    assert.notEqual(message.encryptedContent, 'server must never see this plaintext');
    assert.deepEqual((await createdRealtime).message, message);
    assert.equal(Object.hasOwn(message.author, 'passwordHash'), false);

    let replayBroadcast = false;
    const onReplayBroadcast = () => { replayBroadcast = true; };
    aliceSocket.on('message:new', onReplayBroadcast);
    const replayResponse = await request(`/api/channels/${channelId}/messages`, {
      method: 'POST', cookie: alice.cookie, body: messageRequest.body,
    });
    assert.equal(replayResponse.status, 201);
    assert.deepEqual(await json(replayResponse), message);
    await delay(75);
    aliceSocket.off('message:new', onReplayBroadcast);
    assert.equal(replayBroadcast, false);

    const conflictingReplay = encryptedMessage(
      channelId,
      alice.user.id,
      aliceDevice.id,
      aliceKeys.signingPrivateKey,
      rawChannelKey,
      'a different but valid encrypted envelope',
      messageRequest.body.idempotencyKey,
    );
    const conflictingReplayResponse = await request(`/api/channels/${channelId}/messages`, {
      method: 'POST', cookie: alice.cookie, body: conflictingReplay.body,
    });
    assert.equal(conflictingReplayResponse.status, 409);
    assert.equal((await json<{ error: string }>(conflictingReplayResponse)).error, 'IDEMPOTENCY_CONFLICT');

    const historyResponse = await request(`/api/channels/${channelId}/messages`, { cookie: alice.cookie });
    assert.equal(historyResponse.status, 200);
    const history = await json<{ data: Array<{ author: Record<string, unknown> }> }>(historyResponse);
    assert.equal(history.data.length, 1);
    assert.equal(Object.hasOwn(history.data[0].author, 'passwordHash'), false);
    assert.equal(Object.hasOwn(history.data[0].author, 'password_hash'), false);
    assert.equal(Object.hasOwn(history.data[0].author, 'email'), false);

    const initialChannelStateResponse = await request(`/api/workspaces/${workspace.id}/channel-state`, { cookie: alice.cookie });
    assert.equal(initialChannelStateResponse.status, 200);
    const initialChannelState = await json<Array<{
      channelId: string;
      unreadCount: number;
      latestMessageId: string | null;
      favorite: boolean;
      muted: boolean;
      notificationLevel: string;
    }>>(initialChannelStateResponse);
    const initialPublicState = initialChannelState.find((state) => state.channelId === channelId);
    assert.ok(initialPublicState);
    assert.equal(initialPublicState.unreadCount, 1);
    assert.equal(initialPublicState.latestMessageId, message.id);

    const preferenceResponse = await request(`/api/channels/${channelId}/preferences`, {
      method: 'PATCH',
      cookie: alice.cookie,
      body: { favorite: true, muted: true, notificationLevel: 'mentions' },
    });
    assert.equal(preferenceResponse.status, 200);
    assert.deepEqual(
      pick(await json<Record<string, unknown>>(preferenceResponse), ['channelId', 'favorite', 'muted', 'notificationLevel']),
      { channelId, favorite: true, muted: true, notificationLevel: 'mentions' },
    );

    const bookmarkResponse = await request(`/api/messages/${message.id}/bookmark`, {
      method: 'POST', cookie: alice.cookie, body: {},
    });
    assert.equal(bookmarkResponse.status, 200);
    assert.equal((await json<{ bookmarked: boolean }>(bookmarkResponse)).bookmarked, true);
    const bookmarksResponse = await request('/api/bookmarks', { cookie: alice.cookie });
    assert.equal(bookmarksResponse.status, 200);
    const bookmarks = await json<Array<{ messageId: string; channelId: string }>>(bookmarksResponse);
    assert.equal(bookmarks.some((bookmark) => bookmark.messageId === message.id && bookmark.channelId === channelId), true);

    const bobMessageResponse = await request(`/api/channels/${channelId}/messages`, {
      method: 'POST', cookie: bob.cookie,
      body: encryptedMessage(
        channelId,
        bob.user.id,
        bobDevice.id,
        bobKeys.signingPrivateKey,
        rawChannelKey,
        'bob attachment authorization boundary',
      ).body,
    });
    assert.equal(bobMessageResponse.status, 201);
    const bobMessage = await json<{ id: string }>(bobMessageResponse);
    const bobUploadRequest = {
      idempotencyKey: randomUUID(),
      messageId: bobMessage.id,
      filenameEnc: Buffer.alloc(32, 0x22).toString('base64'),
      mimeType: 'application/octet-stream',
    };
    const bobUploadResponse = await request('/api/files/uploads', {
      method: 'POST', cookie: bob.cookie,
      body: bobUploadRequest,
    });
    assert.equal(bobUploadResponse.status, 201);
    const bobUpload = await json<{ uploadId: string }>(bobUploadResponse);
    const emptyCiphertextChunk = Buffer.alloc(16, 0x33);
    assert.equal((await request(`/api/files/uploads/${bobUpload.uploadId}/chunks/0`, {
      method: 'PUT', cookie: bob.cookie, body: emptyCiphertextChunk,
    })).status, 201);
    const bobNoncePrefix = Buffer.alloc(8, 0x44);
    const bobWrappedKey = wrapKey(randomBytes(32), bobKeys.identityKey);
    const bobAttachmentResponse = await request(`/api/files/uploads/${bobUpload.uploadId}/finalize`, {
      method: 'POST', cookie: bob.cookie,
      body: signedAttachmentFinalizeBody({
        uploadId: bobUpload.uploadId,
        messageId: bobMessage.id,
        channelId,
        authorId: bob.user.id,
        deviceId: bobDevice.id,
        privateKey: bobKeys.signingPrivateKey,
        filenameEnc: bobUploadRequest.filenameEnc,
        mimeType: bobUploadRequest.mimeType,
        keyVersion: 1,
        chunkCount: 1,
        wrappedKey: bobWrappedKey,
        cryptoManifest: {
          version: 1,
          algorithm: 'AES-256-GCM',
          nonceStrategy: 'prefix-counter-be32',
          noncePrefix: bobNoncePrefix.toString('base64'),
          aadVersion: 1,
          plaintextSize: 0,
        },
      }),
    });
    assert.equal(bobAttachmentResponse.status, 201);
    const bobAttachment = await json<{ id: string }>(bobAttachmentResponse);

    const privateRecipientsResponse = await request(`/api/channels/${privateChannel.id}/key-recipients`, { cookie: alice.cookie });
    assert.equal(privateRecipientsResponse.status, 200);
    const privateRecipients = await json<{ recipients: Array<{ deviceId: string; identityKey: string }> }>(privateRecipientsResponse);
    const rawPrivateChannelKey = randomBytes(32);
    await distributeAndAcknowledgeChannelKey({
      channelId: privateChannel.id,
      version: 1,
      rawKey: rawPrivateChannelKey,
      senderCookie: alice.cookie,
      senderKeys: aliceKeys,
      recipients: privateRecipients.recipients,
      acknowledgements: [{ deviceId: aliceDevice.id, cookie: alice.cookie, keys: aliceKeys }],
    });
    const privateMessageResponse = await request(`/api/channels/${privateChannel.id}/messages`, {
      method: 'POST',
      cookie: alice.cookie,
      body: encryptedMessage(
        privateChannel.id,
        alice.user.id,
        aliceDevice.id,
        aliceKeys.signingPrivateKey,
        rawPrivateChannelKey,
        'private boundary message',
      ).body,
    });
    assert.equal(privateMessageResponse.status, 201);
    const privateMessage = await json<{ id: string }>(privateMessageResponse);
    const privatePreferenceProbe = await request(`/api/channels/${privateChannel.id}/preferences`, {
      method: 'PATCH', cookie: bob.cookie, body: { favorite: true },
    });
    assert.equal(privatePreferenceProbe.status, 404);
    const privateBookmarkProbe = await request(`/api/messages/${privateMessage.id}/bookmark`, {
      method: 'POST', cookie: bob.cookie, body: {},
    });
    assert.equal(privateBookmarkProbe.status, 404);

    const reactionRealtime = onceSocketEvent<Record<string, unknown>>(aliceSocket, 'message:reaction');
    const reactionResponse = await request(`/api/messages/${message.id}/reactions`, {
      method: 'POST', cookie: alice.cookie, body: { emoji: '👍' },
    });
    assert.equal(reactionResponse.status, 200);
    const reaction = await json<{
      messageId: string;
      channelId: string;
      userId: string;
      action: string;
      emoji: string;
      reactions: Array<{ emoji: string; count: number; userIds: string[] }>;
    }>(reactionResponse);
    assert.deepEqual(await reactionRealtime, reaction);
    assert.equal(reaction.messageId, message.id);
    assert.equal(reaction.channelId, channelId);
    assert.equal(reaction.userId, alice.user.id);
    assert.equal(reaction.action, 'added');
    assert.deepEqual(reaction.reactions, [{ emoji: '👍', count: 1, userIds: [alice.user.id] }]);

    const pinRealtime = onceSocketEvent<Record<string, unknown>>(aliceSocket, 'message:pinned');
    const pinResponse = await request(`/api/messages/${message.id}/pin`, {
      method: 'POST', cookie: alice.cookie, body: {},
    });
    assert.equal(pinResponse.status, 200);
    const pin = await json<{ messageId: string; channelId: string; userId: string; pinned: boolean }>(pinResponse);
    assert.deepEqual(await pinRealtime, pin);
    assert.deepEqual(pin, {
      messageId: message.id,
      channelId,
      userId: alice.user.id,
      pinned: true,
    });

    const enrichedHistoryResponse = await request(`/api/channels/${channelId}/messages`, { cookie: alice.cookie });
    assert.equal(enrichedHistoryResponse.status, 200);
    const enrichedHistory = await json<{ data: Array<{
      id: string;
      type: string;
      refMessageId: string | null;
      reactions: Array<{ emoji: string; count: number; userIds: string[] }>;
      isPinned: boolean;
      createdAt: string;
      author: Record<string, unknown>;
    }> }>(enrichedHistoryResponse);
    const baseMessage = enrichedHistory.data.find((event) => event.id === message.id);
    const rawReaction = enrichedHistory.data.find((event) => event.type === 'reaction' && event.refMessageId === message.id);
    assert.ok(baseMessage);
    assert.equal(rawReaction, undefined, 'reaction state must not create durable message events');
    assert.equal(baseMessage.isPinned, true);
    assert.deepEqual(baseMessage.reactions, reaction.reactions);
    for (const event of enrichedHistory.data) {
      assert.equal(Object.hasOwn(event.author, 'passwordHash'), false);
      assert.equal(Object.hasOwn(event.author, 'password_hash'), false);
      assert.equal(Object.hasOwn(event.author, 'email'), false);
    }
    assertNewestFirst(enrichedHistory.data);

    const reactionRemovedRealtime = onceSocketEvent<Record<string, unknown>>(aliceSocket, 'message:reaction');
    const reactionRemovedResponse = await request(`/api/messages/${message.id}/reactions`, {
      method: 'POST', cookie: alice.cookie, body: { emoji: '👍' },
    });
    assert.equal(reactionRemovedResponse.status, 200);
    const reactionRemoved = await json<{ action: string; reactionAction: string; reactions: unknown[] }>(reactionRemovedResponse);
    assert.deepEqual(await reactionRemovedRealtime, reactionRemoved);
    assert.equal(reactionRemoved.action, 'removed');
    assert.equal(reactionRemoved.reactionAction, 'remove');
    assert.deepEqual(reactionRemoved.reactions, []);
    const compactReactionHistory = await json<{ data: Array<{
      type: string;
      refMessageId: string | null;
      reactionAction: string | null;
      reactions: unknown[];
    }> }>(await request(`/api/channels/${channelId}/messages`, { cookie: alice.cookie }));
    const rawReactionEvents = compactReactionHistory.data.filter(
      (event) => event.type === 'reaction' && event.refMessageId === message.id,
    );
    assert.equal(rawReactionEvents.length, 0);
    assert.deepEqual(
      compactReactionHistory.data.find((event: any) => event.id === message.id)?.reactions,
      [],
    );

    const forgedType = await request(`/api/channels/${channelId}/messages`, {
      method: 'POST', cookie: alice.cookie, body: { ...messageRequest.body, type: 'system', idempotencyKey: randomUUID() },
    });
    assert.equal(forgedType.status, 400);

    const bobDeleteEnvelope: SignedMessageEnvelope = {
      type: 'delete',
      channelId,
      authorId: bob.user.id,
      deviceId: bobDevice.id,
      keyVersion: 1,
      idempotencyKey: randomUUID(),
      refMessageId: message.id,
      encryptedContent: '',
      contentNonce: '',
      broadcastMention: false,
    };
    const bobDelete = await request(`/api/messages/${message.id}`, {
      method: 'DELETE',
      cookie: bob.cookie,
      body: {
        deviceId: bobDevice.id,
        keyVersion: 1,
        idempotencyKey: bobDeleteEnvelope.idempotencyKey,
        signature: signEnvelope(bobDeleteEnvelope, bobKeys.signingPrivateKey),
      },
    });
    assert.equal(bobDelete.status, 403);

    const unauthorizedUpload = await request('/api/files/uploads', {
      method: 'POST',
      cookie: bob.cookie,
      body: {
        idempotencyKey: randomUUID(),
        messageId: message.id,
        filenameEnc: Buffer.alloc(32, 1).toString('base64'),
        mimeType: 'text/plain',
      },
    });
    assert.equal(unauthorizedUpload.status, 403);

    const uploadRequest = {
      idempotencyKey: randomUUID(),
      messageId: message.id,
      filenameEnc: Buffer.alloc(32, 2).toString('base64'),
      mimeType: 'text/html',
    };
    const uploadResponse = await request('/api/files/uploads', {
      method: 'POST',
      cookie: alice.cookie,
      body: uploadRequest,
    });
    assert.equal(uploadResponse.status, 201);
    const upload = await json<{
      uploadId: string;
      chunkPlaintextBytes: number;
      chunkCiphertextBytes: number;
      maxChunkCount: number;
      crypto: { version: number; algorithm: string; nonceStrategy: string; noncePrefixBytes: number; aadVersion: number };
    }>(uploadResponse);
    assert.equal(Object.hasOwn(upload, 'url'), false);
    assert.equal(Object.hasOwn(upload, 'fields'), false);
    assert.equal(Object.hasOwn(upload, 'storageKey'), false);
    assert.equal(upload.chunkPlaintextBytes, 5 * 1024 * 1024);
    assert.equal(upload.chunkCiphertextBytes, 5 * 1024 * 1024 + 16);
    assert.equal(upload.uploadId, uploadRequest.idempotencyKey);
    const uploadReplay = await request('/api/files/uploads', {
      method: 'POST', cookie: alice.cookie, body: uploadRequest,
    });
    assert.equal(uploadReplay.status, 200);
    assert.equal((await json<{ uploadId: string }>(uploadReplay)).uploadId, upload.uploadId);
    const uploadConflict = await request('/api/files/uploads', {
      method: 'POST', cookie: alice.cookie,
      body: { ...uploadRequest, mimeType: 'application/octet-stream' },
    });
    assert.equal(uploadConflict.status, 409);
    assert.equal((await json<{ error: string }>(uploadConflict)).error, 'IDEMPOTENCY_CONFLICT');

    const unauthorizedUploadStatus = await request(`/api/files/uploads/${upload.uploadId}`, { cookie: mallory.cookie });
    assert.equal(unauthorizedUploadStatus.status, 404);
    const unauthorizedChunk = await request(`/api/files/uploads/${upload.uploadId}/chunks/0`, {
      method: 'PUT', cookie: mallory.cookie, body: Buffer.alloc(17),
    });
    assert.equal(unauthorizedChunk.status, 404);

    const attachmentKey = randomBytes(32);
    const noncePrefix = randomBytes(8);
    const firstPlaintextChunk = Buffer.alloc(upload.chunkPlaintextBytes, 0x41);
    const finalPlaintextChunk = Buffer.from('resumable encrypted attachment tail', 'utf8');
    const attachmentPlaintextSize = firstPlaintextChunk.length + finalPlaintextChunk.length;
    const attachmentChunkCount = 2;
    const { attachmentChunkAad } = await import('../services/file.service.js');
    const firstCiphertextChunk = encryptAttachmentChunk(
      attachmentKey,
      noncePrefix,
      0,
      attachmentChunkAad(upload.uploadId, message.id, 0, attachmentChunkCount, attachmentPlaintextSize),
      firstPlaintextChunk,
    );
    const finalCiphertextChunk = encryptAttachmentChunk(
      attachmentKey,
      noncePrefix,
      1,
      attachmentChunkAad(upload.uploadId, message.id, 1, attachmentChunkCount, attachmentPlaintextSize),
      finalPlaintextChunk,
    );
    const finalChunkUpload = await request(`/api/files/uploads/${upload.uploadId}/chunks/1`, {
      method: 'PUT', cookie: alice.cookie, body: finalCiphertextChunk,
    });
    assert.equal(finalChunkUpload.status, 201);
    const partialStatusResponse = await request(`/api/files/uploads/${upload.uploadId}`, { cookie: alice.cookie });
    assert.equal(partialStatusResponse.status, 200);
    assert.deepEqual((await json<{ uploadedIndexes: number[] }>(partialStatusResponse)).uploadedIndexes, [1]);
    const firstChunkUpload = await request(`/api/files/uploads/${upload.uploadId}/chunks/0`, {
      method: 'PUT', cookie: alice.cookie, body: firstCiphertextChunk,
    });
    assert.equal(firstChunkUpload.status, 201);
    const completeStatusResponse = await request(`/api/files/uploads/${upload.uploadId}`, { cookie: alice.cookie });
    assert.equal(completeStatusResponse.status, 200);
    assert.deepEqual((await json<{ uploadedIndexes: number[] }>(completeStatusResponse)).uploadedIndexes, [0, 1]);

    const finalizeBody = signedAttachmentFinalizeBody({
      uploadId: upload.uploadId,
      messageId: message.id,
      channelId,
      authorId: alice.user.id,
      deviceId: aliceDevice.id,
      privateKey: aliceKeys.signingPrivateKey,
      filenameEnc: uploadRequest.filenameEnc,
      mimeType: uploadRequest.mimeType,
      keyVersion: 1,
      chunkCount: attachmentChunkCount,
      wrappedKey: wrapKey(attachmentKey, aliceKeys.identityKey),
      cryptoManifest: {
        version: 1,
        algorithm: 'AES-256-GCM',
        nonceStrategy: 'prefix-counter-be32',
        noncePrefix: noncePrefix.toString('base64'),
        aadVersion: 1,
        plaintextSize: attachmentPlaintextSize,
      },
    });
    const forgedAttachmentFinalize = await request(`/api/files/uploads/${upload.uploadId}/finalize`, {
      method: 'POST', cookie: alice.cookie,
      body: { ...finalizeBody, signature: Buffer.alloc(64).toString('base64') },
    });
    assert.equal(forgedAttachmentFinalize.status, 400);
    let attachmentBroadcastCount = 0;
    const onAttachmentCreated = () => { attachmentBroadcastCount += 1; };
    aliceSocket.on('attachment:created', onAttachmentCreated);
    const attachmentRealtime = onceSocketEvent<Record<string, unknown>>(aliceSocket, 'attachment:created');
    const concurrentFinalizes = await Promise.all([
      request(`/api/files/uploads/${upload.uploadId}/finalize`, {
        method: 'POST', cookie: alice.cookie, body: finalizeBody,
      }),
      request(`/api/files/uploads/${upload.uploadId}/finalize`, {
        method: 'POST', cookie: alice.cookie, body: finalizeBody,
      }),
    ]);
    assert.deepEqual(concurrentFinalizes.map((response) => response.status).sort((left, right) => left - right), [201, 409]);
    const finalizedResponse = concurrentFinalizes.find((response) => response.status === 201)!;
    const conflictFinalizeResponse = concurrentFinalizes.find((response) => response.status === 409)!;
    const attachment = await json<{
      id: string;
      messageId: string;
      channelId: string;
      deviceId: string;
      keyVersion: number;
      signature: string;
      mimeType: string;
      dangerousMime: boolean;
      chunkCount: number;
      ciphertextSizeBytes: number;
      plaintextSizeBytes: number;
      cryptoManifest: Record<string, unknown>;
    }>(finalizedResponse);
    assert.equal((await json<{ error: string }>(conflictFinalizeResponse)).error, 'UPLOAD_ALREADY_COMPLETED');
    assert.deepEqual(await attachmentRealtime, attachment);
    await delay(75);
    aliceSocket.off('attachment:created', onAttachmentCreated);
    assert.equal(attachmentBroadcastCount, 1);
    assert.equal(attachment.messageId, message.id);
    assert.equal(attachment.channelId, channelId);
    assert.equal(attachment.deviceId, aliceDevice.id);
    assert.equal(attachment.keyVersion, 1);
    assert.equal(attachment.signature, finalizeBody.signature);
    assert.equal(attachment.mimeType, 'text/html');
    assert.equal(attachment.dangerousMime, true);
    assert.equal(attachment.chunkCount, 2);
    assert.equal(attachment.plaintextSizeBytes, attachmentPlaintextSize);
    assert.equal(attachment.ciphertextSizeBytes, firstCiphertextChunk.length + finalCiphertextChunk.length);

    const metadataResponse = await request(`/api/files/${attachment.id}`, { cookie: alice.cookie });
    assert.equal(metadataResponse.status, 200);
    const metadata = await json<Record<string, unknown>>(metadataResponse);
    assert.equal(Object.hasOwn(metadata, 'url'), false);
    assert.equal(Object.hasOwn(metadata, 'storageKey'), false);
    assert.equal(metadata.downloadPolicy, 'attachment-only');
    assert.equal(metadata.dangerousMime, true);
    const chunkDownloadResponse = await request(`/api/files/${attachment.id}/chunks/1`, { cookie: alice.cookie });
    assert.equal(chunkDownloadResponse.status, 200);
    assert.equal(chunkDownloadResponse.headers.get('content-type'), 'application/octet-stream');
    assert.equal(chunkDownloadResponse.headers.get('cache-control'), 'no-store');
    assert.equal(chunkDownloadResponse.headers.get('x-content-type-options'), 'nosniff');
    assert.match(chunkDownloadResponse.headers.get('content-disposition') || '', /^attachment;/);
    const downloadedFinalChunk = Buffer.from(await chunkDownloadResponse.arrayBuffer());
    assert.deepEqual(downloadedFinalChunk, finalCiphertextChunk);
    const firstChunkDownloadResponse = await request(`/api/files/${attachment.id}/chunks/0`, { cookie: alice.cookie });
    assert.equal(firstChunkDownloadResponse.status, 200);
    const downloadedFirstChunk = Buffer.from(await firstChunkDownloadResponse.arrayBuffer());
    const downloadedPlaintext = Buffer.concat([
      decryptAttachmentChunk(
        attachmentKey,
        noncePrefix,
        0,
        attachmentChunkAad(upload.uploadId, message.id, 0, attachmentChunkCount, attachmentPlaintextSize),
        downloadedFirstChunk,
      ),
      decryptAttachmentChunk(
        attachmentKey,
        noncePrefix,
        1,
        attachmentChunkAad(upload.uploadId, message.id, 1, attachmentChunkCount, attachmentPlaintextSize),
        downloadedFinalChunk,
      ),
    ]);
    const originalPlaintext = Buffer.concat([firstPlaintextChunk, finalPlaintextChunk]);
    assert.equal(
      createHash('sha256').update(downloadedPlaintext).digest('hex'),
      createHash('sha256').update(originalPlaintext).digest('hex'),
    );
    assert.equal((await request(`/api/files/${attachment.id}`, { cookie: mallory.cookie })).status, 404);
    assert.equal((await request(`/api/files/${attachment.id}/chunks/1`, { cookie: mallory.cookie })).status, 404);

    const attachmentHistoryResponse = await request(`/api/channels/${channelId}/messages`, { cookie: alice.cookie });
    assert.equal(attachmentHistoryResponse.status, 200);
    const attachmentHistory = await json<{ data: Array<{ id: string; type: string; attachments: Array<{ id: string }> }> }>(attachmentHistoryResponse);
    const attachedBaseMessage = attachmentHistory.data.find((event) => event.id === message.id);
    assert.ok(attachedBaseMessage);
    assert.deepEqual(attachedBaseMessage.attachments.map((item) => item.id), [attachment.id]);
    for (const event of attachmentHistory.data.filter((item) => item.type !== 'message')) {
      assert.deepEqual(event.attachments, []);
    }

    const newerMessageRequest = encryptedMessage(
      channelId,
      alice.user.id,
      aliceDevice.id,
      aliceKeys.signingPrivateKey,
      rawChannelKey,
      'newer read-position boundary',
    );
    const newerMessageResponse = await request(`/api/channels/${channelId}/messages`, {
      method: 'POST', cookie: alice.cookie, body: newerMessageRequest.body,
    });
    assert.equal(newerMessageResponse.status, 201);
    const newerMessage = await json<{ id: string }>(newerMessageResponse);
    const readNewerResponse = await request(`/api/channels/${channelId}/read`, {
      method: 'POST', cookie: alice.cookie, body: { messageId: newerMessage.id },
    });
    assert.equal(readNewerResponse.status, 200);
    assert.equal((await json<{ lastReadMessageId: string }>(readNewerResponse)).lastReadMessageId, newerMessage.id);
    const readOlderResponse = await request(`/api/channels/${channelId}/read`, {
      method: 'POST', cookie: alice.cookie, body: { messageId: message.id },
    });
    assert.equal(readOlderResponse.status, 200);
    assert.equal((await json<{ lastReadMessageId: string }>(readOlderResponse)).lastReadMessageId, newerMessage.id);
    const readChannelStateResponse = await request(`/api/workspaces/${workspace.id}/channel-state`, { cookie: alice.cookie });
    assert.equal(readChannelStateResponse.status, 200);
    const readChannelState = (await json<Array<{
      channelId: string;
      unreadCount: number;
      latestMessageId: string | null;
      lastReadMessageId: string | null;
      favorite: boolean;
      muted: boolean;
      notificationLevel: string;
    }>>(readChannelStateResponse)).find((state) => state.channelId === channelId);
    assert.ok(readChannelState);
    assert.equal(readChannelState.latestMessageId, newerMessage.id);
    assert.equal(readChannelState.lastReadMessageId, newerMessage.id);
    assert.equal(readChannelState.unreadCount, 0);
    assert.equal(readChannelState.favorite, true);
    assert.equal(readChannelState.muted, true);
    assert.equal(readChannelState.notificationLevel, 'mentions');

    const orphanReservationRequest = {
      idempotencyKey: randomUUID(),
      messageId: message.id,
      filenameEnc: Buffer.alloc(32, 3).toString('base64'),
      mimeType: 'application/octet-stream',
    };
    const orphanReservationResponse = await request('/api/files/uploads', {
      method: 'POST',
      cookie: alice.cookie,
      body: orphanReservationRequest,
    });
    assert.equal(orphanReservationResponse.status, 201);
    const orphanReservation = await json<{ uploadId: string }>(orphanReservationResponse);
    const orphanChunkUpload = await request(`/api/files/uploads/${orphanReservation.uploadId}/chunks/0`, {
      method: 'PUT', cookie: alice.cookie, body: Buffer.alloc(17, 0x7f),
    });
    assert.equal(orphanChunkUpload.status, 201);
    const [{ db: integrationDb }, schema, drizzle, Minio, fileService] = await Promise.all([
      import('../db/index.js'),
      import('../db/schema.js'),
      import('drizzle-orm'),
      import('minio'),
      import('../services/file.service.js'),
    ]);
    const attachmentOnlyKeys = deviceFixture();
    const [attachmentOnlyDevice] = await integrationDb.insert(schema.devices).values({
      userId: bob.user.id,
      name: 'Revoked attachment-only signer',
      identityKey: attachmentOnlyKeys.identityKey,
      revokedAt: new Date(),
    }).returning({ id: schema.devices.id });
    await integrationDb.insert(schema.attachments).values({
      messageId: bobMessage.id,
      channelId,
      signerDeviceId: attachmentOnlyDevice.id,
      keyVersion: 1,
      signature: Buffer.alloc(64).toString('base64'),
      filenameEnc: Buffer.alloc(32, 0x7a).toString('base64'),
      mimeType: 'application/octet-stream',
      sizeBytes: 16,
      storageKey: `integration/attachment-only/${randomUUID()}`,
      chunkCount: 1,
      wrappedKey: Buffer.alloc(32, 0x7b).toString('base64'),
      contentNonce: Buffer.alloc(8, 0x7c).toString('base64'),
      cryptoManifest: {
        version: 1,
        algorithm: 'AES-256-GCM',
        nonceStrategy: 'prefix-counter-be32',
        noncePrefix: Buffer.alloc(8, 0x7c).toString('base64'),
        aadVersion: 1,
        plaintextSize: 0,
        chunkPlaintextBytes: 5 * 1024 * 1024,
        authenticationTagBytes: 16,
        chunkCount: 1,
        uploadId: randomUUID(),
        messageId: bobMessage.id,
        aadFormat: 'test-fixture',
      },
    });
    const orphanChunkRow = await integrationDb.query.attachmentUploadChunks.findFirst({
      where: drizzle.and(
        drizzle.eq(schema.attachmentUploadChunks.uploadId, orphanReservation.uploadId),
        drizzle.eq(schema.attachmentUploadChunks.chunkIndex, 0),
      ),
    });
    assert.ok(orphanChunkRow);
    await integrationDb.update(schema.attachmentUploads)
      .set({ expiresAt: new Date(0) })
      .where(drizzle.eq(schema.attachmentUploads.id, orphanReservation.uploadId));
    const expiredReservationReplay = await request('/api/files/uploads', {
      method: 'POST', cookie: alice.cookie, body: orphanReservationRequest,
    });
    assert.equal(expiredReservationReplay.status, 410);
    assert.equal((await json<{ error: string }>(expiredReservationReplay)).error, 'UPLOAD_EXPIRED');
    assert.equal(await fileService.cleanupExpiredUploads(), 1);
    assert.equal(await integrationDb.query.attachmentUploads.findFirst({
      where: drizzle.eq(schema.attachmentUploads.id, orphanReservation.uploadId),
    }), undefined);
    assert.equal(await integrationDb.query.attachmentUploadChunks.findFirst({
      where: drizzle.eq(schema.attachmentUploadChunks.uploadId, orphanReservation.uploadId),
    }), undefined);
    const storageClient = new Minio.Client({
      endPoint: process.env.MINIO_ENDPOINT || 'localhost',
      port: Number(process.env.MINIO_PORT || 9000),
      useSSL: process.env.MINIO_USE_SSL === 'true',
      accessKey: process.env.MINIO_ACCESS_KEY!,
      secretKey: process.env.MINIO_SECRET_KEY!,
    });
    await assert.rejects(
      storageClient.statObject(process.env.MINIO_BUCKET || 'alparts', orphanChunkRow.storageKey),
      (error: any) => error?.code === 'NotFound' || error?.code === 'NoSuchKey',
    );

    const cancellableUploadId = randomUUID();
    assert.equal((await request('/api/files/uploads', {
      method: 'POST', cookie: alice.cookie,
      body: {
        idempotencyKey: cancellableUploadId,
        messageId: message.id,
        filenameEnc: Buffer.alloc(32, 0x54).toString('base64'),
        mimeType: 'application/octet-stream',
      },
    })).status, 201);
    assert.equal((await request(`/api/files/uploads/${cancellableUploadId}`, {
      method: 'DELETE', cookie: alice.cookie,
    })).status, 200);
    assert.equal((await request(`/api/files/uploads/${cancellableUploadId}`, {
      method: 'DELETE', cookie: alice.cookie,
    })).status, 200);
    assert.equal((await request(`/api/files/uploads/${cancellableUploadId}`, { cookie: alice.cookie })).status, 404);

    const pendingAtDeleteRequest = {
      idempotencyKey: randomUUID(),
      messageId: message.id,
      filenameEnc: Buffer.alloc(32, 0x55).toString('base64'),
      mimeType: 'application/octet-stream',
    };
    const pendingAtDeleteResponse = await request('/api/files/uploads', {
      method: 'POST', cookie: alice.cookie,
      body: pendingAtDeleteRequest,
    });
    assert.equal(pendingAtDeleteResponse.status, 201);
    const pendingAtDelete = await json<{ uploadId: string }>(pendingAtDeleteResponse);
    const fillerUploadIds = [randomUUID(), randomUUID()];
    for (const [index, fillerUploadId] of fillerUploadIds.entries()) {
      assert.equal((await request('/api/files/uploads', {
        method: 'POST', cookie: alice.cookie,
        body: {
          idempotencyKey: fillerUploadId,
          messageId: message.id,
          filenameEnc: Buffer.alloc(32, 0x60 + index).toString('base64'),
          mimeType: 'application/octet-stream',
        },
      })).status, 201);
    }
    const overAttachmentLimit = await request('/api/files/uploads', {
      method: 'POST', cookie: alice.cookie,
      body: {
        idempotencyKey: randomUUID(),
        messageId: message.id,
        filenameEnc: Buffer.alloc(32, 0x69).toString('base64'),
        mimeType: 'application/octet-stream',
      },
    });
    assert.equal(overAttachmentLimit.status, 409);
    assert.equal((await json<{ error: string }>(overAttachmentLimit)).error, 'ATTACHMENT_LIMIT_EXCEEDED');
    for (const fillerUploadId of fillerUploadIds) {
      assert.equal((await request(`/api/files/uploads/${fillerUploadId}`, {
        method: 'DELETE', cookie: alice.cookie,
      })).status, 200);
    }

    const editRequest = encryptedEdit(
      channelId,
      message.id,
      alice.user.id,
      aliceDevice.id,
      aliceKeys.signingPrivateKey,
      rawChannelKey,
      'edited plaintext',
    );
    const editedRealtime = onceSocketEvent<{ message: Record<string, unknown> }>(aliceSocket, 'message:edited');
    const editResponse = await request(`/api/messages/${message.id}`, {
      method: 'PUT', cookie: alice.cookie, body: editRequest.body,
    });
    assert.equal(editResponse.status, 200);
    const editEvent = await json<Record<string, unknown>>(editResponse);
    assert.deepEqual((await editedRealtime).message, editEvent);

    const deleteEnvelope: SignedMessageEnvelope = {
      type: 'delete',
      channelId,
      authorId: alice.user.id,
      deviceId: aliceDevice.id,
      keyVersion: 1,
      idempotencyKey: randomUUID(),
      refMessageId: message.id,
      encryptedContent: '',
      contentNonce: '',
      broadcastMention: false,
    };
    const deleteSignature = signEnvelope(deleteEnvelope, aliceKeys.signingPrivateKey);
    const deletedRealtime = onceSocketEvent<Record<string, unknown>>(aliceSocket, 'message:deleted');
    const deleteResponse = await request(`/api/messages/${message.id}`, {
      method: 'DELETE',
      cookie: alice.cookie,
      body: {
        deviceId: aliceDevice.id,
        keyVersion: 1,
        idempotencyKey: deleteEnvelope.idempotencyKey,
        signature: deleteSignature,
      },
    });
    assert.equal(deleteResponse.status, 200);
    const deleteResult = await json<Record<string, unknown>>(deleteResponse);
    assert.deepEqual(await deletedRealtime, deleteResult);
    assert.equal(Object.hasOwn(deleteResult, 'isNewEvent'), false);

    const deleteReplayResponse = await request(`/api/messages/${message.id}`, {
      method: 'DELETE',
      cookie: alice.cookie,
      body: {
        deviceId: aliceDevice.id,
        keyVersion: 1,
        idempotencyKey: deleteEnvelope.idempotencyKey,
        signature: deleteSignature,
      },
    });
    assert.equal(deleteReplayResponse.status, 200);
    assert.deepEqual(await json(deleteReplayResponse), deleteResult);
    assert.equal((await request(`/api/messages/${message.id}`, {
      method: 'PUT', cookie: alice.cookie, body: editRequest.body,
    })).status, 404);
    assert.equal((await request(`/api/messages/${message.id}/reactions`, {
      method: 'POST', cookie: alice.cookie, body: { emoji: 'after' },
    })).status, 404);
    assert.equal((await request(`/api/messages/${message.id}/pin`, {
      method: 'POST', cookie: alice.cookie, body: {},
    })).status, 404);
    assert.equal((await request('/api/files/uploads', {
      method: 'POST', cookie: alice.cookie,
      body: {
        idempotencyKey: randomUUID(),
        messageId: message.id,
        filenameEnc: Buffer.alloc(32, 0x66).toString('base64'),
        mimeType: 'application/octet-stream',
      },
    })).status, 404);
    assert.equal((await request(`/api/files/uploads/${pendingAtDelete.uploadId}/finalize`, {
      method: 'POST', cookie: alice.cookie,
      body: signedAttachmentFinalizeBody({
        uploadId: pendingAtDelete.uploadId,
        messageId: message.id,
        channelId,
        authorId: alice.user.id,
        deviceId: aliceDevice.id,
        privateKey: aliceKeys.signingPrivateKey,
        filenameEnc: pendingAtDeleteRequest.filenameEnc,
        mimeType: pendingAtDeleteRequest.mimeType,
        keyVersion: 1,
        chunkCount: 1,
        wrappedKey: wrapKey(randomBytes(32), aliceKeys.identityKey),
        cryptoManifest: {
          version: 1,
          algorithm: 'AES-256-GCM',
          nonceStrategy: 'prefix-counter-be32',
          noncePrefix: Buffer.alloc(8, 0x77).toString('base64'),
          aadVersion: 1,
          plaintextSize: 0,
        },
      }),
    })).status, 404);
    assert.equal((await request(`/api/files/${attachment.id}`, { cookie: alice.cookie })).status, 404);
    assert.equal((await request(`/api/files/${attachment.id}/chunks/0`, { cookie: alice.cookie })).status, 404);

    const unreadDeletedRequest = encryptedMessage(
      channelId,
      alice.user.id,
      aliceDevice.id,
      aliceKeys.signingPrivateKey,
      rawChannelKey,
      'unread message removed from channel state',
    );
    const unreadDeletedResponse = await request(`/api/channels/${channelId}/messages`, {
      method: 'POST', cookie: alice.cookie, body: unreadDeletedRequest.body,
    });
    assert.equal(unreadDeletedResponse.status, 201);
    const unreadDeletedMessage = await json<{ id: string }>(unreadDeletedResponse);
    const unreadBeforeDelete = (await json<Array<{ channelId: string; unreadCount: number; latestMessageId: string | null }>>(
      await request(`/api/workspaces/${workspace.id}/channel-state`, { cookie: alice.cookie }),
    )).find((state) => state.channelId === channelId);
    assert.equal(unreadBeforeDelete?.unreadCount, 1);
    assert.equal(unreadBeforeDelete?.latestMessageId, unreadDeletedMessage.id);
    const unreadDeleteEnvelope: SignedMessageEnvelope = {
      type: 'delete',
      channelId,
      authorId: alice.user.id,
      deviceId: aliceDevice.id,
      keyVersion: 1,
      idempotencyKey: randomUUID(),
      refMessageId: unreadDeletedMessage.id,
      encryptedContent: '',
      contentNonce: '',
      broadcastMention: false,
    };
    assert.equal((await request(`/api/messages/${unreadDeletedMessage.id}`, {
      method: 'DELETE', cookie: alice.cookie,
      body: {
        deviceId: aliceDevice.id,
        keyVersion: 1,
        idempotencyKey: unreadDeleteEnvelope.idempotencyKey,
        signature: signEnvelope(unreadDeleteEnvelope, aliceKeys.signingPrivateKey),
      },
    })).status, 200);
    const unreadAfterDelete = (await json<Array<{ channelId: string; unreadCount: number; latestMessageId: string | null }>>(
      await request(`/api/workspaces/${workspace.id}/channel-state`, { cookie: alice.cookie }),
    )).find((state) => state.channelId === channelId);
    assert.equal(unreadAfterDelete?.unreadCount, 0);
    assert.equal(unreadAfterDelete?.latestMessageId, newerMessage.id);

    const overrideTarget = await json<{ categoryId: string | null }>(
      await request(`/api/channels/${channelId}`, { cookie: alice.cookie }),
    );
    assert.ok(overrideTarget.categoryId);
    const bobSocket = io(baseUrl, {
      transports: ['websocket'],
      extraHeaders: { Cookie: bob.cookie, Origin: 'http://localhost:5173' },
    });
    sockets.push(bobSocket);
    await onceConnected(bobSocket);
    assert.equal(await joinChannel(bobSocket, channelId), true);

    const voiceChannelResponse = await request(`/api/workspaces/${workspace.id}/channels`, {
      method: 'POST',
      cookie: alice.cookie,
      body: {
        name: 'team-voice',
        type: 'voice',
        categoryId: overrideTarget.categoryId,
        position: 1_000_000,
      },
    });
    assert.equal(voiceChannelResponse.status, 201);
    const voiceChannel = await json<{ id: string }>(voiceChannelResponse);

    // Viewing a voice channel does not grant participation or presence access.
    const voiceOverridePath = `/api/workspaces/${workspace.id}/channels/${voiceChannel.id}/permission-overrides`;
    const denyVoicePreview = await json<any>(await request(`${voiceOverridePath}/preview`, {
      method: 'POST', cookie: alice.cookie,
      body: { operation: 'upsert', roleId: memberRole.id, allowMask: 0, denyMask: Permissions.CONNECT_VOICE },
    }));
    assert.equal((await request(`${voiceOverridePath}/${memberRole.id}`, {
      method: 'PUT', cookie: alice.cookie,
      body: { allowMask: 0, denyMask: Permissions.CONNECT_VOICE, expectedRevision: 0, expectedAuthorizationRevision: denyVoicePreview.authorizationRevision },
    })).status, 200);
    assert.equal((await request(`/api/channels/${voiceChannel.id}`, { cookie: bob.cookie })).status, 200);
    assert.equal((await joinVoice(bobSocket, voiceChannel.id)).ok, false);
    const deniedPresence: any = await emitSocketAck(bobSocket, 'voice:watch', { channelIds: [voiceChannel.id] });
    assert.equal(deniedPresence.channels?.some((entry: any) => entry.channelId === voiceChannel.id) ?? false, false);
    const restoreVoicePreview = await json<any>(await request(`${voiceOverridePath}/preview`, {
      method: 'POST', cookie: alice.cookie, body: { operation: 'upsert', roleId: memberRole.id, allowMask: 0, denyMask: 0 },
    }));
    assert.equal((await request(`${voiceOverridePath}/${memberRole.id}`, {
      method: 'PUT', cookie: alice.cookie,
      body: { allowMask: 0, denyMask: 0, expectedRevision: 1, expectedAuthorizationRevision: restoreVoicePreview.authorizationRevision },
    })).status, 200);

    assert.deepEqual(await emitSocketAck(bobSocket, 'voice:watch', { channelIds: [voiceChannel.id] }), {
      ok: true,
      channels: [{ channelId: voiceChannel.id, participants: [] }],
    });
    const alicePresenceChanged = onceSocketEvent<{
      channelId: string;
      participants: import('@alparts/shared').VoiceParticipant[];
    }>(bobSocket, 'voice:participants-changed');
    const aliceVoiceJoin = await joinVoice(aliceSocket, voiceChannel.id);
    assert.equal(aliceVoiceJoin.ok, true);
    assert.equal(aliceVoiceJoin.self?.deviceId, aliceDevice.id);
    assert.deepEqual(aliceVoiceJoin.participants, []);
    assert.deepEqual(await alicePresenceChanged, {
      channelId: voiceChannel.id,
      participants: [aliceVoiceJoin.self!],
    });
    const bobJoinedVoice = onceSocketEvent<{ participantId: string; deviceId: string }>(
      aliceSocket,
      'voice:participant-joined',
    );
    const bobVoiceJoin = await joinVoice(bobSocket, voiceChannel.id);
    assert.equal(bobVoiceJoin.ok, true);
    assert.equal(bobVoiceJoin.self?.deviceId, bobDevice.id);
    assert.deepEqual(
      bobVoiceJoin.participants?.map((participant) => participant.participantId),
      [aliceVoiceJoin.self!.participantId],
    );
    assert.deepEqual(await bobJoinedVoice, bobVoiceJoin.self);
    const unauthorizedVoiceJoin = await joinVoice(mallorySocket, voiceChannel.id);
    assert.deepEqual(unauthorizedVoiceJoin, { ok: false, error: 'FORBIDDEN' });

    const voiceEnvelope: SignedVoiceSignalEnvelope = {
      type: 'voice-signal',
      signalId: randomUUID(),
      sequence: 1,
      channelId: voiceChannel.id,
      senderParticipantId: aliceVoiceJoin.self!.participantId,
      senderDeviceId: aliceDevice.id,
      targetParticipantId: bobVoiceJoin.self!.participantId,
      kind: 'offer',
      descriptionType: 'offer',
      sdp: 'v=0\r\na=fingerprint:sha-256 AA:BB\r\n',
      candidate: null,
      sdpMid: null,
      sdpMLineIndex: null,
      usernameFragment: null,
    };
    const voiceSignature = sign('sha256', Buffer.from(serializeVoiceSignalEnvelope(voiceEnvelope)), {
      key: aliceKeys.signingPrivateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64');
    const relayedVoiceSignal = onceSocketEvent<{ envelope: SignedVoiceSignalEnvelope; signature: string }>(
      bobSocket,
      'voice:signal',
    );
    assert.deepEqual(
      await emitSocketAck(aliceSocket, 'voice:signal', { ...voiceEnvelope, signature: voiceSignature }),
      { ok: true },
    );
    assert.deepEqual(await relayedVoiceSignal, { envelope: voiceEnvelope, signature: voiceSignature });
    assert.deepEqual(await emitSocketAck(bobSocket, 'voice:signal', {
      ...voiceEnvelope,
      signalId: randomUUID(),
      sequence: 2,
      senderParticipantId: aliceVoiceJoin.self!.participantId,
      senderDeviceId: bobDevice.id,
      targetParticipantId: aliceVoiceJoin.self!.participantId,
      signature: voiceSignature,
    }), { ok: false }, 'a participant cannot spoof another signaling sender');

    const aliceVoiceState = onceSocketEvent<{ participantId: string; muted: boolean; speaking: boolean }>(
      bobSocket,
      'voice:participant-updated',
    );
    aliceSocket.emit('voice:state', { channelId: voiceChannel.id, muted: true, speaking: true });
    assert.deepEqual(await aliceVoiceState, {
      ...aliceVoiceJoin.self!,
      muted: true,
      speaking: false,
    });

    const disposableChannelResponse = await request(`/api/workspaces/${workspace.id}/channels`, {
      method: 'POST',
      cookie: alice.cookie,
      body: { name: 'delete-notification-check' },
    });
    assert.equal(disposableChannelResponse.status, 201);
    const disposableChannel = await json<{ id: string; workspaceId: string }>(disposableChannelResponse);
    assert.equal(await joinChannel(bobSocket, disposableChannel.id), true);
    const channelDeletedDirect = onceSocketEvent<{ workspaceId: string; channelId: string }>(
      bobSocket,
      'channel:deleted',
    );
    assert.equal((await request(`/api/channels/${disposableChannel.id}`, {
      method: 'DELETE',
      cookie: alice.cookie,
    })).status, 200);
    assert.deepEqual(await channelDeletedDirect, {
      workspaceId: workspace.id,
      channelId: disposableChannel.id,
    });
    assert.equal(await joinChannel(bobSocket, disposableChannel.id), false);

    // Bob receives a wrapped key but deliberately creates no message, read
    // position, preference, or bookmark in this channel. The historical key
    // row is the only durable evidence that the channel is known to him.
    const keyOnlyChannelResponse = await request(`/api/workspaces/${workspace.id}/channels`, {
      method: 'POST',
      cookie: alice.cookie,
      body: { name: 'key-only-known-channel' },
    });
    assert.equal(keyOnlyChannelResponse.status, 201);
    const keyOnlyChannel = await json<{ id: string }>(keyOnlyChannelResponse);
    const keyOnlyRecipientsResponse = await request(`/api/channels/${keyOnlyChannel.id}/key-recipients`, {
      cookie: alice.cookie,
    });
    assert.equal(keyOnlyRecipientsResponse.status, 200);
    const keyOnlyRecipients = await json<{ recipients: Array<{ deviceId: string; identityKey: string }> }>(
      keyOnlyRecipientsResponse,
    );
    assert.equal(keyOnlyRecipients.recipients.some((recipient) => recipient.deviceId === bobDevice.id), true);
    const keyOnlyMaterial = randomBytes(32);
    await distributeAndAcknowledgeChannelKey({
      channelId: keyOnlyChannel.id,
      version: 1,
      rawKey: keyOnlyMaterial,
      senderCookie: alice.cookie,
      senderKeys: aliceKeys,
      recipients: keyOnlyRecipients.recipients,
      acknowledgements: [
        { deviceId: aliceDevice.id, cookie: alice.cookie, keys: aliceKeys },
        { deviceId: bobDevice.id, cookie: bob.cookie, keys: bobKeys },
      ],
    });

    const categoryOverridePreviewResponse = await request(
      `/api/workspaces/${workspace.id}/categories/${overrideTarget.categoryId}/permission-overrides/preview`,
      {
        method: 'POST', cookie: alice.cookie,
        body: { operation: 'upsert', roleId: memberRole.id, allowMask: 0, denyMask: Permissions.VIEW_CHANNELS },
      },
    );
    assert.equal(categoryOverridePreviewResponse.status, 200);
    const categoryOverridePreview = await json<{
      currentRevision: number;
      authorizationRevision: string;
      roomEffects: Array<{ channelId: string }>;
    }>(categoryOverridePreviewResponse);
    assert.equal(categoryOverridePreview.currentRevision, 0);
    assert.equal(categoryOverridePreview.roomEffects.some((effect) => effect.channelId === channelId), true);
    const invalidGlobalOverride = await request(
      `/api/workspaces/${workspace.id}/categories/${overrideTarget.categoryId}/permission-overrides/${memberRole.id}`,
      {
        method: 'PUT', cookie: alice.cookie,
        body: {
          allowMask: Permissions.MANAGE_CHANNELS,
          denyMask: 0,
          expectedRevision: 0,
          expectedAuthorizationRevision: categoryOverridePreview.authorizationRevision,
        },
      },
    );
    assert.equal(invalidGlobalOverride.status, 400);
    const crossWorkspaceOverride = await request(
      `/api/workspaces/${workspace.id}/categories/${overrideTarget.categoryId}/permission-overrides/${outsiderRoles[0].id}`,
      {
        method: 'PUT', cookie: alice.cookie,
        body: {
          allowMask: Permissions.VIEW_CHANNELS,
          denyMask: 0,
          expectedRevision: 0,
          expectedAuthorizationRevision: categoryOverridePreview.authorizationRevision,
        },
      },
    );
    assert.equal(crossWorkspaceOverride.status, 404);
    const rolePreviewBeforeOverride = await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST', cookie: alice.cookie,
      body: { operation: 'role.update', roleId: memberRole.id, permissions: memberRole.permissionMask },
    });
    assert.equal(rolePreviewBeforeOverride.status, 200);
    const roleRevisionBeforeOverride = (
      await json<{ authorizationRevision: string }>(rolePreviewBeforeOverride)
    ).authorizationRevision;
    const channelAccessRevoked = onceSocketEventMatching<{ workspaceId: string; channelId: string }>(
      bobSocket,
      'channel:access-revoked',
      (payload) => payload.workspaceId === workspace.id && payload.channelId === channelId,
    );
    const bobRemovedFromVoice = onceSocketEvent<{ channelId: string; participantId: string }>(
      aliceSocket,
      'voice:participant-left',
    );
    let receivedRevokedRoomBroadcast = false;
    const onRevokedRoomBroadcast = () => { receivedRevokedRoomBroadcast = true; };
    bobSocket.once('channel:permissions-updated', onRevokedRoomBroadcast);
    const categoryOverrideApply = await request(
      `/api/workspaces/${workspace.id}/categories/${overrideTarget.categoryId}/permission-overrides/${memberRole.id}`,
      {
        method: 'PUT', cookie: alice.cookie,
        body: {
          allowMask: 0,
          denyMask: Permissions.VIEW_CHANNELS,
          expectedRevision: 0,
          expectedAuthorizationRevision: categoryOverridePreview.authorizationRevision,
        },
      },
    );
    assert.equal(categoryOverrideApply.status, 200);
    assert.deepEqual(await channelAccessRevoked, { workspaceId: workspace.id, channelId });
    assert.deepEqual(await bobRemovedFromVoice, {
      channelId: voiceChannel.id,
      participantId: bobVoiceJoin.self!.participantId,
    });
    await delay(50);
    bobSocket.off('channel:permissions-updated', onRevokedRoomBroadcast);
    assert.equal(receivedRevokedRoomBroadcast, false, 'revoked sockets must not receive later channel-room broadcasts');
    const categoryApplyBody = await json<{
      authorizationRevision: string;
      roomEffects: Array<{ channelId: string; rotationRequired: boolean }>;
    }>(categoryOverrideApply);
    const staleRoleAfterOverride = await request(`/api/workspaces/${workspace.id}/roles/${memberRole.id}`, {
      method: 'PUT', cookie: alice.cookie,
      body: {
        permissions: memberRole.permissionMask,
        expectedAuthorizationRevision: roleRevisionBeforeOverride,
      },
    });
    assert.equal(staleRoleAfterOverride.status, 409);
    assert.equal((await json<{ error: string }>(staleRoleAfterOverride)).error, 'STALE_PREVIEW');
    assert.equal(categoryApplyBody.roomEffects.some((effect) => effect.channelId === channelId && effect.rotationRequired), true);
    assert.equal((await request(`/api/channels/${channelId}/messages`, { cookie: bob.cookie })).status, 404);
    assert.equal((await request(`/api/channels/${channelId}/key-recipients`, { cookie: bob.cookie })).status, 404);
    assert.equal((await request(`/api/files/${bobAttachment.id}`, { cookie: bob.cookie })).status, 404);
    const bobCategoriesAfterDeny = await request(`/api/workspaces/${workspace.id}/categories`, { cookie: bob.cookie });
    assert.equal(bobCategoriesAfterDeny.status, 200);
    assert.equal(
      (await json<Array<{ id: string }>>(bobCategoriesAfterDeny)).some((item) => item.id === overrideTarget.categoryId),
      false,
    );
    assert.equal(
      (await json<Array<{ id: string }>>(await request(`/api/workspaces/${workspace.id}/categories`, { cookie: alice.cookie })))
        .some((item) => item.id === overrideTarget.categoryId),
      true,
    );
    assert.equal(await joinChannel(bobSocket, channelId), false);
    assert.equal((await request(`/api/channels/${channelId}/messages`, { cookie: alice.cookie })).status, 200, 'owner cannot be override-locked out');

    const staleAuthorizationOverride = await request(
      `/api/workspaces/${workspace.id}/channels/${channelId}/permission-overrides/${memberRole.id}`,
      {
        method: 'PUT', cookie: alice.cookie,
        body: {
          allowMask: Permissions.VIEW_CHANNELS,
          denyMask: 0,
          expectedRevision: 0,
          expectedAuthorizationRevision: categoryOverridePreview.authorizationRevision,
        },
      },
    );
    assert.equal(staleAuthorizationOverride.status, 409);
    assert.equal((await json<{ error: string }>(staleAuthorizationOverride)).error, 'STALE_PREVIEW');

    const channelOverrideApply = await request(
      `/api/workspaces/${workspace.id}/channels/${channelId}/permission-overrides/${memberRole.id}`,
      {
        method: 'PUT', cookie: alice.cookie,
        body: {
          allowMask: Permissions.VIEW_CHANNELS,
          denyMask: 0,
          expectedRevision: 0,
          expectedAuthorizationRevision: categoryApplyBody.authorizationRevision,
        },
      },
    );
    assert.equal(channelOverrideApply.status, 200);
    const channelApplyBody = await json<{ authorizationRevision: string }>(channelOverrideApply);
    assert.equal((await request(`/api/channels/${channelId}/messages`, { cookie: bob.cookie })).status, 200);
    assert.equal(await joinChannel(bobSocket, channelId), true);

    const rotatedRecipientsResponse = await request(`/api/channels/${channelId}/key-recipients`, { cookie: alice.cookie });
    assert.equal(rotatedRecipientsResponse.status, 200);
    const rotatedRecipients = await json<{ recipients: Array<{ deviceId: string; identityKey: string }> }>(rotatedRecipientsResponse);
    const rotatedChannelKey = randomBytes(32);
    await distributeAndAcknowledgeChannelKey({
      channelId,
      version: 2,
      rawKey: rotatedChannelKey,
      senderCookie: alice.cookie,
      senderKeys: aliceKeys,
      recipients: rotatedRecipients.recipients,
      acknowledgements: [
        { deviceId: aliceDevice.id, cookie: alice.cookie, keys: aliceKeys },
        { deviceId: bobDevice.id, cookie: bob.cookie, keys: bobKeys },
      ],
    });

    const staleChannelOverride = await request(
      `/api/workspaces/${workspace.id}/channels/${channelId}/permission-overrides/${memberRole.id}`,
      {
        method: 'PUT', cookie: alice.cookie,
        body: {
          allowMask: Permissions.VIEW_CHANNELS,
          denyMask: Permissions.SEND_MESSAGES | Permissions.ATTACH_FILES,
          expectedRevision: 0,
          expectedAuthorizationRevision: channelApplyBody.authorizationRevision,
        },
      },
    );
    assert.equal(staleChannelOverride.status, 409);
    const channelOverridePreviewResponse = await request(
      `/api/workspaces/${workspace.id}/channels/${channelId}/permission-overrides/preview`,
      {
        method: 'POST', cookie: alice.cookie,
        body: {
          operation: 'upsert',
          roleId: memberRole.id,
          allowMask: Permissions.VIEW_CHANNELS,
          denyMask: Permissions.SEND_MESSAGES | Permissions.ATTACH_FILES,
        },
      },
    );
    assert.equal(channelOverridePreviewResponse.status, 200);
    const channelOverridePreview = await json<{ currentRevision: number; authorizationRevision: string }>(channelOverridePreviewResponse);
    assert.equal(channelOverridePreview.currentRevision, 1);
    const channelOverrideUpdate = await request(
      `/api/workspaces/${workspace.id}/channels/${channelId}/permission-overrides/${memberRole.id}`,
      {
        method: 'PUT', cookie: alice.cookie,
        body: {
          allowMask: Permissions.VIEW_CHANNELS,
          denyMask: Permissions.SEND_MESSAGES | Permissions.ATTACH_FILES,
          expectedRevision: 1,
          expectedAuthorizationRevision: channelOverridePreview.authorizationRevision,
        },
      },
    );
    assert.equal(channelOverrideUpdate.status, 200);
    const channelUpdateBody = await json<{ authorizationRevision: string }>(channelOverrideUpdate);
    const deniedSend = await request(`/api/channels/${channelId}/messages`, {
      method: 'POST', cookie: bob.cookie,
      body: encryptedMessage(
        channelId,
        bob.user.id,
        bobDevice.id,
        bobKeys.signingPrivateKey,
        rotatedChannelKey,
        'must be denied by channel override',
      ).body,
    });
    assert.equal(deniedSend.status, 403);
    assert.equal((await request('/api/files/uploads', {
      method: 'POST', cookie: bob.cookie,
      body: {
        idempotencyKey: randomUUID(),
        messageId: bobMessage.id,
        filenameEnc: Buffer.alloc(32, 0x78).toString('base64'),
        mimeType: 'application/octet-stream',
      },
    })).status, 403);
    const effectiveChannelResponse = await request(
      `/api/workspaces/${workspace.id}/channels/${channelId}/permissions/effective?userId=${bob.user.id}`,
      { cookie: alice.cookie },
    );
    assert.equal(effectiveChannelResponse.status, 200);
    const effectiveChannel = await json<{
      permissionDetails: Array<{ permission: string; allowed: boolean; reasons: Array<{ source: string; effect: string }> }>;
    }>(effectiveChannelResponse);
    const viewDetail = effectiveChannel.permissionDetails.find((detail) => detail.permission === 'VIEW_CHANNELS');
    assert.equal(viewDetail?.allowed, true);
    assert.equal(viewDetail?.reasons.some((reason) => reason.source === 'category' && reason.effect === 'deny'), true);
    assert.equal(viewDetail?.reasons.some((reason) => reason.source === 'channel' && reason.effect === 'allow'), true);
    assert.equal(effectiveChannel.permissionDetails.find((detail) => detail.permission === 'SEND_MESSAGES')?.allowed, false);
    assert.equal(effectiveChannel.permissionDetails.find((detail) => detail.permission === 'ATTACH_FILES')?.allowed, false);

    const roleOverrideApply = await request(
      `/api/workspaces/${workspace.id}/channels/${channelId}/permission-overrides/${revisionBumpRole.id}`,
      {
        method: 'PUT', cookie: alice.cookie,
        body: {
          allowMask: Permissions.SEND_MESSAGES,
          denyMask: 0,
          expectedRevision: 0,
          expectedAuthorizationRevision: channelUpdateBody.authorizationRevision,
        },
      },
    );
    assert.equal(roleOverrideApply.status, 200);
    const roleOverrideApplyBody = await json<{ authorizationRevision: string }>(roleOverrideApply);
    assert.equal((await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST', cookie: alice.cookie,
      body: { operation: 'role.delete', roleId: revisionBumpRole.id },
    })).status, 409);
    const roleOverrideDelete = await request(
      `/api/workspaces/${workspace.id}/channels/${channelId}/permission-overrides/${revisionBumpRole.id}`,
      {
        method: 'DELETE', cookie: alice.cookie,
        body: {
          expectedRevision: 1,
          expectedAuthorizationRevision: roleOverrideApplyBody.authorizationRevision,
        },
      },
    );
    assert.equal(roleOverrideDelete.status, 200);
    const roleOverrideDeleteBody = await json<{ authorizationRevision: string }>(roleOverrideDelete);

    const channelOverrideDelete = await request(
      `/api/workspaces/${workspace.id}/channels/${channelId}/permission-overrides/${memberRole.id}`,
      {
        method: 'DELETE', cookie: alice.cookie,
        body: {
          expectedRevision: 2,
          expectedAuthorizationRevision: roleOverrideDeleteBody.authorizationRevision,
        },
      },
    );
    assert.equal(channelOverrideDelete.status, 200);
    assert.equal((await request(`/api/channels/${channelId}/messages`, { cookie: bob.cookie })).status, 404);
    assert.equal((await request(`/api/channels/${channelId}/key-recipients`, { cookie: bob.cookie })).status, 404);
    assert.equal((await request(`/api/files/${bobAttachment.id}`, { cookie: bob.cookie })).status, 404);
    assert.equal((await request(`/api/files/${bobAttachment.id}`, { cookie: alice.cookie })).status, 200);
    assert.equal(await joinChannel(bobSocket, channelId), false);

    const inUseChannelDelete = await request(`/api/channels/${channelId}`, {
      method: 'DELETE', cookie: alice.cookie,
    });
    assert.equal(inUseChannelDelete.status, 409);

    const removalPreview = await request(`/api/workspaces/${workspace.id}/roles/preview`, {
      method: 'POST', cookie: alice.cookie,
      body: { operation: 'role.unassign', roleId: memberRole.id, userId: bob.user.id },
    });
    assert.equal(removalPreview.status, 200);
    const removalRevision = (await json<{ authorizationRevision: string }>(removalPreview)).authorizationRevision;
    const workspacePermissionsUpdated = onceSocketEvent<{ workspaceId: string; membershipRemoved: boolean }>(
      bobSocket,
      'workspace:permissions-updated',
    );
    const removeMemberRole = await request(`/api/workspaces/${workspace.id}/members/${bob.user.id}/roles/${memberRole.id}`, {
      method: 'DELETE', cookie: alice.cookie, body: { expectedAuthorizationRevision: removalRevision },
    });
    assert.equal(removeMemberRole.status, 200);
    assert.deepEqual(await workspacePermissionsUpdated, { workspaceId: workspace.id, membershipRemoved: false });
    const selfPermissions = await request(`/api/workspaces/${workspace.id}/members/${bob.user.id}/permissions`, { cookie: bob.cookie });
    assert.equal(selfPermissions.status, 200);
    const selfPermissionBody = await json<{ permissionDetails: Array<{ permission: string; allowed: boolean }> }>(selfPermissions);
    assert.equal(selfPermissionBody.permissionDetails.find((permission) => permission.permission === 'VIEW_CHANNELS')?.allowed, false);
    const workspaceAccessRevoked = onceSocketEvent<{ workspaceId: string; membershipRemoved: boolean; channelIds: string[] }>(
      bobSocket,
      'workspace:access-revoked',
    );
    const removeBobWorkspaceMember = await request(`/api/workspaces/${workspace.id}/members/${bob.user.id}`, {
      method: 'DELETE', cookie: alice.cookie,
    });
    assert.equal(removeBobWorkspaceMember.status, 200);
    const workspaceAccessRevokedPayload = await workspaceAccessRevoked;
    assert.equal(workspaceAccessRevokedPayload.workspaceId, workspace.id);
    assert.equal(workspaceAccessRevokedPayload.membershipRemoved, true);
    assert.equal(workspaceAccessRevokedPayload.channelIds.includes(channelId), true);
    assert.equal(
      workspaceAccessRevokedPayload.channelIds.includes(keyOnlyChannel.id),
      true,
      'historical wrapped-key delivery is sufficient proof that the removed member knew the channel',
    );
    const recipientsAfterRemovalResponse = await request(`/api/channels/${channelId}/key-recipients`, { cookie: alice.cookie });
    assert.equal(recipientsAfterRemovalResponse.status, 200);
    const recipientsAfterRemoval = await json<{
      recipients: Array<{ deviceId: string; identityKey: string }>;
    }>(recipientsAfterRemovalResponse);
    assert.equal(recipientsAfterRemoval.recipients.some((recipient) => recipient.deviceId === bobDevice.id), false);
    assert.equal(recipientsAfterRemoval.recipients.some((recipient) => recipient.deviceId === attachmentOnlyDevice.id), false);
    await distributeAndAcknowledgeChannelKey({
      channelId,
      version: 3,
      rawKey: randomBytes(32),
      senderCookie: alice.cookie,
      senderKeys: aliceKeys,
      recipients: recipientsAfterRemoval.recipients,
      acknowledgements: [{ deviceId: aliceDevice.id, cookie: alice.cookie, keys: aliceKeys }],
    });
    assert.equal((await request(`/api/devices/${bobDevice.id}`, {
      method: 'DELETE', cookie: bob.cookie,
    })).status, 200);
    const afterFormerMemberRevoke = await json<{ rotationRequired: boolean }>(
      await request(`/api/channels/${channelId}/key-recipients`, { cookie: alice.cookie }),
    );
    assert.equal(
      afterFormerMemberRevoke.rotationRequired,
      false,
      'revoking a former member device must not stale the current epoch',
    );
    const historicalIds = encodeURIComponent([bobDevice.id, attachmentOnlyDevice.id, randomUUID()].join(','));
    const historicalDirectoryResponse = await request(
      `/api/channels/${channelId}/device-directory?ids=${historicalIds}`,
      { cookie: alice.cookie },
    );
    assert.equal(historicalDirectoryResponse.status, 200);
    const historicalDirectory = await json<Array<{ deviceId: string }>>(historicalDirectoryResponse);
    assert.equal(
      historicalDirectory.some((device) => device.deviceId === bobDevice.id),
      true,
      'historical signing keys remain available after the author leaves',
    );
    assert.equal(
      historicalDirectory.some((device) => device.deviceId === attachmentOnlyDevice.id),
      true,
      'attachment-only historical signer keys remain available after revocation and membership loss',
    );
    assert.equal(historicalDirectory.length, 2, 'unreferenced requested device IDs are not disclosed');
    const legacyDirectoryResponse = await request(
      `/api/channels/${channelId}/device-directory`,
      { cookie: alice.cookie },
    );
    assert.equal(legacyDirectoryResponse.headers.get('deprecation'), 'true');
    const legacyDirectory = await json<Array<{ deviceId: string }>>(legacyDirectoryResponse);
    assert.equal(legacyDirectory.some((device) => device.deviceId === aliceDevice.id), true);
    assert.equal(legacyDirectory.some((device) => device.deviceId === bobDevice.id), true);
    assert.equal(legacyDirectory.some((device) => device.deviceId === attachmentOnlyDevice.id), true);
    const currentKeyDeliveries = await json<Array<{ version: number; epochStatus: string }>>(
      await request(`/api/channels/${channelId}/keys?scope=current`, { cookie: alice.cookie }),
    );
    assert.equal(currentKeyDeliveries.length > 0, true);
    assert.equal(currentKeyDeliveries.every((delivery) => delivery.version === 3 && delivery.epochStatus === 'active'), true);
    const legacyKeyResponse = await request(`/api/channels/${channelId}/keys`, { cookie: alice.cookie });
    assert.equal(legacyKeyResponse.headers.get('deprecation'), 'true');
    const legacyKeyDeliveries = await json<Array<{ version: number; epochStatus: string }>>(legacyKeyResponse);
    assert.equal(legacyKeyDeliveries.some((delivery) => delivery.version === 1), true);
    assert.equal(legacyKeyDeliveries.some((delivery) => delivery.version === 2), true);
    assert.equal(legacyKeyDeliveries.some((delivery) => delivery.version === 3), true);
    const retiredKeyDeliveries = await json<Array<{ version: number; epochStatus: string }>>(
      await request(`/api/channels/${channelId}/keys?version=2`, { cookie: alice.cookie }),
    );
    assert.equal(retiredKeyDeliveries.length > 0, true);
    assert.equal(retiredKeyDeliveries.every((delivery) => delivery.version === 2 && delivery.epochStatus === 'retired'), true);
    const batchedHistoricalDeliveries = await json<Array<{ version: number; epochStatus: string }>>(
      await request(`/api/channels/${channelId}/keys?versions=1,2`, { cookie: alice.cookie }),
    );
    assert.equal(batchedHistoricalDeliveries.some((delivery) => delivery.version === 1), true);
    assert.equal(batchedHistoricalDeliveries.some((delivery) => delivery.version === 2), true);
    assert.equal(batchedHistoricalDeliveries.every((delivery) => [1, 2].includes(delivery.version)), true);
    assert.equal((await request(`/api/channels/${channelId}/keys?versions=1,1`, {
      cookie: alice.cookie,
    })).status, 400);
    assert.equal((await request(`/api/channels/${channelId}/keys?version=not-a-version`, {
      cookie: alice.cookie,
    })).status, 400);

    const { db: auditDb } = await import('../db/index.js');
    const { auditLogs: auditLogTable } = await import('../db/schema.js');
    const expectedMessageAuditActions = [
      'message.create',
      'message.create.replay',
      'message.edit',
      'message.delete',
      'message.delete.replay',
      'message.reaction.add',
      'message.reaction.remove',
      'message.pin.add',
      'channel.preference.update',
      'message.bookmark.add',
    ];
    const messageAuditRows = await auditDb.select({
      action: auditLogTable.action,
      targetId: auditLogTable.targetId,
      details: auditLogTable.details,
    }).from(auditLogTable).where(inArray(auditLogTable.action, expectedMessageAuditActions));
    const recordedActions = new Set(messageAuditRows.map((row) => row.action));
    for (const action of expectedMessageAuditActions) assert.equal(recordedActions.has(action), true, action);
    const createdMessageAudit = messageAuditRows.find((row) => (
      row.action === 'message.create' && row.targetId === message.id
    ));
    assert.ok(createdMessageAudit);
    const createdMessageAuditDetails = createdMessageAudit.details as Record<string, unknown>;
    assert.equal(createdMessageAuditDetails.requestId, messageResponse.headers.get('x-request-id'));
    assert.match(String(createdMessageAuditDetails.traceId), /^[a-f0-9]{32}$/);
    const serializedMessageAudit = JSON.stringify(messageAuditRows);
    assert.equal(serializedMessageAudit.includes('server must never see this plaintext'), false);
    assert.equal(serializedMessageAudit.includes('👍'), false);
    assert.equal(serializedMessageAudit.includes(messageRequest.body.signature), false);
    assert.equal(serializedMessageAudit.includes(messageRequest.body.idempotencyKey), false);

    assert.equal((await request('/api/auth/reauthenticate', {
      method: 'POST', body: { password: alice.password },
    })).status, 401);
    assert.equal((await request('/api/auth/reauthenticate', {
      method: 'POST', cookie: alice.cookie, body: { password: 'not-the-password' },
    })).status, 403);
    const reauthenticated = await request('/api/auth/reauthenticate', {
      method: 'POST', cookie: alice.cookie, body: { password: alice.password },
    });
    assert.equal(reauthenticated.status, 200);
    assert.equal((await json<{ id: string }>(reauthenticated)).id, alice.user.id);
    assert.equal((await request('/api/auth/me', { cookie: alice.cookie })).status, 200);

    const disconnected = new Promise<void>((resolve) => aliceSocket.once('disconnect', () => resolve()));
    const logout = await request('/api/auth/logout', { method: 'POST', cookie: alice.cookie, body: {} });
    assert.equal(logout.status, 200);
    await disconnected;
    assert.equal((await request('/api/auth/me', { cookie: alice.cookie })).status, 401);

    mallorySocket.disconnect();
    const audit = await verifyAuditChain();
    assert.equal(audit.valid, true);
    assert.ok(audit.checked > 0);
  });

  it('keeps forum posts bound to their post, channel and permissions', async () => {
    const { db } = await import('../db/index.js');
    const { auditLogs, forumPosts: forumPostTable } = await import('../db/schema.js');
    const messageService = await import('../services/message.service.js');
    // An account from the first scenario that never enrolled a device.
    const ownerLogin = await request('/api/auth/login', {
      method: 'POST', body: { email: 'unbound@example.test', password: 'Correct-Horse-Battery-9!' },
    });
    assert.equal(ownerLogin.status, 200);
    const owner = {
      cookie: ownerLogin.headers.get('set-cookie')!.split(';', 1)[0],
      user: (await json<{ user: { id: string } }>(ownerLogin)).user,
      password: 'Correct-Horse-Battery-9!',
    };
    const ownerKeys = deviceFixture();
    const ownerDevice = await registerDevice(owner, ownerKeys, 'Forum owner device');
    const workspace = await json<{ id: string }>(await request('/api/workspaces', {
      method: 'POST', cookie: owner.cookie, body: { name: 'Forum security' },
    }));
    const memberInvitation = await createWorkspaceInvitation(workspace.id, owner.cookie, 'forum-member@example.test');
    const member = await createAccount('forum-member@example.test', 'Correct-Horse-Battery-31!', 'Forum Member', memberInvitation.token);
    const memberKeys = deviceFixture();
    const memberDevice = await registerDevice(member, memberKeys, 'Forum member device');
    const outsiderInvitation = await createWorkspaceInvitation(workspace.id, owner.cookie, 'forum-outsider@example.test');
    const outsider = await createAccount('forum-outsider@example.test', 'Correct-Horse-Battery-32!', 'Forum Outsider', outsiderInvitation.token);
    const outsiderMembership = await request(`/api/workspaces/${workspace.id}/members/${outsider.user.id}`, {
      method: 'DELETE', cookie: owner.cookie,
    });
    assert.equal(outsiderMembership.status, 200, await outsiderMembership.text());

    const forumResponse = await request(`/api/workspaces/${workspace.id}/channels`, {
      method: 'POST', cookie: owner.cookie, body: { name: 'questions', type: 'forum' },
    });
    assert.equal(forumResponse.status, 201);
    const forum = await json<{ id: string; type: string }>(forumResponse);
    assert.equal(forum.type, 'forum');
    const recipients = await json<{ recipients: Array<{ deviceId: string; identityKey: string }> }>(
      await request(`/api/channels/${forum.id}/key-recipients`, { cookie: owner.cookie }),
    );
    const forumKey = randomBytes(32);
    await distributeAndAcknowledgeChannelKey({
      channelId: forum.id,
      version: 1,
      rawKey: forumKey,
      senderCookie: owner.cookie,
      senderKeys: ownerKeys,
      recipients: recipients.recipients,
      acknowledgements: [
        { deviceId: ownerDevice.id, cookie: owner.cookie, keys: ownerKeys },
        { deviceId: memberDevice.id, cookie: member.cookie, keys: memberKeys },
      ],
    });
    const asMember = (input: Omit<Parameters<typeof encryptedForumEvent>[0], 'channelId' | 'authorId' | 'deviceId' | 'privateKey' | 'key'>) => (
      encryptedForumEvent({ ...input, channelId: forum.id, authorId: member.user.id, deviceId: memberDevice.id, privateKey: memberKeys.signingPrivateKey, key: forumKey })
    );
    const asOwner = (input: Omit<Parameters<typeof encryptedForumEvent>[0], 'channelId' | 'authorId' | 'deviceId' | 'privateKey' | 'key'>) => (
      encryptedForumEvent({ ...input, channelId: forum.id, authorId: owner.user.id, deviceId: ownerDevice.id, privateKey: ownerKeys.signingPrivateKey, key: forumKey })
    );

    // Tags are managed by channel managers only.
    assert.equal((await request(`/api/channels/${forum.id}/forum/tags`, {
      method: 'POST', cookie: member.cookie, body: { name: 'bug' },
    })).status, 403);
    const tagResponse = await request(`/api/channels/${forum.id}/forum/tags`, {
      method: 'POST', cookie: owner.cookie, body: { name: '質問' },
    });
    assert.equal(tagResponse.status, 201);
    const tag = await json<{ id: string; name: string }>(tagResponse);
    assert.equal((await request(`/api/channels/${forum.id}/forum/tags`, {
      method: 'POST', cookie: owner.cookie, body: { name: '質問' },
    })).status, 409);
    assert.equal((await request(`/api/channels/${forum.id}/forum/tags`, {
      method: 'POST', cookie: owner.cookie, body: { name: 'bad‮eman' },
    })).status, 400);

    // Starting a post needs the v4 envelope with no post; chat-style writes are refused.
    const post = asMember({ type: 'message', refMessageId: null, postId: null, plaintext: 'Title\nBody that the server must not see' });
    const legacyShape = encryptedMessage(forum.id, member.user.id, memberDevice.id, memberKeys.signingPrivateKey, forumKey, 'no post id');
    assert.equal((await request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie: member.cookie, body: legacyShape.body,
    })).status, 400);
    assert.equal((await request(`/api/channels/${forum.id}/forum/posts`, {
      method: 'POST', cookie: member.cookie, body: legacyShape.body,
    })).status, 400);
    const postResponse = await request(`/api/channels/${forum.id}/forum/posts`, {
      method: 'POST', cookie: member.cookie, body: { ...post.body, tagIds: [tag.id] },
    });
    assert.equal(postResponse.status, 201, await postResponse.clone().text());
    const created = await json<{ message: { id: string; postId: string | null }; state: { tagIds: string[]; replyCount: number } }>(postResponse);
    const postId = created.message.id;
    assert.equal(created.message.postId, null);
    assert.deepEqual(created.state.tagIds, [tag.id]);
    assert.equal(created.state.replyCount, 0);

    // A reply is bound to its post: a signature for another post, or a
    // quote from another post, is rejected.
    const secondPost = asOwner({ type: 'message', refMessageId: null, postId: null, plaintext: 'Other\npost' });
    const secondResponse = await request(`/api/channels/${forum.id}/forum/posts`, {
      method: 'POST', cookie: owner.cookie, body: secondPost.body,
    });
    assert.equal(secondResponse.status, 201);
    const secondPostId = (await json<{ message: { id: string } }>(secondResponse)).message.id;
    const relocated = asOwner({ type: 'message', refMessageId: null, postId: secondPostId, plaintext: 'moved' });
    assert.equal((await request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie: owner.cookie, body: { ...relocated.body, postId },
    })).status, 400);
    const crossQuote = asOwner({ type: 'message', refMessageId: secondPostId, postId, plaintext: 'cross' });
    assert.equal((await request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie: owner.cookie, body: { ...crossQuote.body, refMessageId: secondPostId },
    })).status, 400);
    const reply = asOwner({ type: 'message', refMessageId: null, postId, plaintext: 'An answer' });
    const replyResponse = await request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie: owner.cookie, body: reply.body,
    });
    assert.equal(replyResponse.status, 201);
    const replyEvent = await json<{ id: string; postId: string }>(replyResponse);
    assert.equal(replyEvent.postId, postId);
    // Only the post itself can be pinned in a forum.
    assert.equal((await request(`/api/messages/${replyEvent.id}/pin`, { method: 'POST', cookie: owner.cookie })).status, 403);

    // A forum event outside a forum, and a missing post inside one, fail closed.
    const general = (await json<Array<{ id: string; type: string }>>(
      await request(`/api/workspaces/${workspace.id}/channels`, { cookie: owner.cookie }),
    )).find((channel) => channel.type === 'text');
    assert.ok(general);
    await assert.rejects(messageService.createMessage(general.id, owner.user.id, {
      ...reply.body, postId,
    }), /INVALID_REFERENCE/);
    const { postId: _omitted, ...withoutPost } = reply.body;
    await assert.rejects(messageService.createMessage(forum.id, owner.user.id, {
      ...withoutPost, idempotencyKey: randomUUID(),
    }), /INVALID_REFERENCE/);

    // Listing reflects the reply; unread is per viewer and uses server time.
    const memberList = await json<{ data: Array<{ root: { id: string }; state: { postId: string; replyCount: number; unread: boolean } }> }>(
      await request(`/api/channels/${forum.id}/forum/posts`, { cookie: member.cookie }),
    );
    const listed = memberList.data.find((entry) => entry.state.postId === postId);
    assert.ok(listed);
    assert.equal(listed.root.id, postId);
    assert.equal(listed.state.replyCount, 1);
    assert.equal(listed.state.unread, true);
    const ownerList = await json<{ data: Array<{ state: { postId: string; unread: boolean } }> }>(
      await request(`/api/channels/${forum.id}/forum/posts`, { cookie: owner.cookie }),
    );
    assert.equal(ownerList.data.find((entry) => entry.state.postId === postId)?.state.unread, false);
    const tagged = await json<{ data: Array<{ state: { postId: string } }> }>(
      await request(`/api/channels/${forum.id}/forum/posts?tagId=${tag.id}`, { cookie: owner.cookie }),
    );
    assert.deepEqual(tagged.data.map((entry) => entry.state.postId), [postId]);
    const paged = await json<{ data: Array<{ state: { postId: string } }>; cursor: string | null; hasMore: boolean }>(
      await request(`/api/channels/${forum.id}/forum/posts?limit=1`, { cookie: owner.cookie }),
    );
    assert.equal(paged.hasMore, true);
    const nextPage = await json<{ data: Array<{ state: { postId: string } }> }>(
      await request(`/api/channels/${forum.id}/forum/posts?limit=1&cursor=${paged.cursor}`, { cookie: owner.cookie }),
    );
    assert.deepEqual(new Set([...paged.data, ...nextPage.data].map((entry) => entry.state.postId)), new Set([postId, secondPostId]));
    assert.equal((await request(`/api/forum/posts/${postId}/read`, { method: 'POST', cookie: member.cookie, body: {} })).status, 200);
    const afterRead = await json<{ state: { unread: boolean } }>(await request(`/api/forum/posts/${postId}`, { cookie: member.cookie }));
    assert.equal(afterRead.state.unread, false);
    const thread = await json<{ data: Array<{ id: string; postId: string }> }>(
      await request(`/api/forum/posts/${postId}/messages`, { cookie: member.cookie }),
    );
    assert.deepEqual(thread.data.map((event) => event.id), [replyEvent.id]);

    // Moderation: only managers lock; a locked post refuses member replies.
    assert.equal((await request(`/api/forum/posts/${postId}/lock`, {
      method: 'PUT', cookie: member.cookie, body: { locked: true },
    })).status, 403);
    assert.equal((await request(`/api/forum/posts/${postId}/lock`, {
      method: 'PUT', cookie: owner.cookie, body: { locked: true },
    })).status, 200);
    const lockedReply = asMember({ type: 'message', refMessageId: replyEvent.id, postId, plaintext: 'after lock' });
    const lockedResponse = await request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie: member.cookie, body: { ...lockedReply.body, refMessageId: replyEvent.id },
    });
    assert.equal(lockedResponse.status, 409);
    const moderatorReply = asOwner({ type: 'message', refMessageId: null, postId, plaintext: 'locked by moderator' });
    assert.equal((await request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie: owner.cookie, body: moderatorReply.body,
    })).status, 201);
    // The author may mark their own post resolved and retag it; others may not.
    assert.equal((await request(`/api/forum/posts/${secondPostId}/resolved`, {
      method: 'PUT', cookie: member.cookie, body: { resolved: true },
    })).status, 403);
    const resolved = await request(`/api/forum/posts/${postId}/resolved`, {
      method: 'PUT', cookie: member.cookie, body: { resolved: true },
    });
    assert.equal(resolved.status, 200);
    assert.equal((await json<{ resolved: boolean }>(resolved)).resolved, true);
    assert.equal((await request(`/api/forum/posts/${postId}/tags`, {
      method: 'PUT', cookie: member.cookie, body: { tagIds: [randomUUID()] },
    })).status, 400);

    // CREATE_POSTS is separate from replying.
    const memberRole = (await json<Array<{ id: string; name: string }>>(
      await request(`/api/workspaces/${workspace.id}/roles`, { cookie: owner.cookie }),
    )).find((role) => role.name === 'Member');
    assert.ok(memberRole);
    const overridePath = `/api/workspaces/${workspace.id}/channels/${forum.id}/permission-overrides`;
    const denyPostsPreview = await json<any>(await request(`${overridePath}/preview`, {
      method: 'POST', cookie: owner.cookie,
      body: { operation: 'upsert', roleId: memberRole.id, allowMask: 0, denyMask: Permissions.CREATE_POSTS },
    }));
    assert.equal((await request(`${overridePath}/${memberRole.id}`, {
      method: 'PUT', cookie: owner.cookie,
      body: { allowMask: 0, denyMask: Permissions.CREATE_POSTS, expectedRevision: 0, expectedAuthorizationRevision: denyPostsPreview.authorizationRevision },
    })).status, 200);
    const deniedPost = asMember({ type: 'message', refMessageId: null, postId: null, plaintext: 'denied\npost' });
    assert.equal((await request(`/api/channels/${forum.id}/forum/posts`, {
      method: 'POST', cookie: member.cookie, body: deniedPost.body,
    })).status, 403);
    const allowedReply = asMember({ type: 'message', refMessageId: null, postId: secondPostId, plaintext: 'still replying' });
    assert.equal((await request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie: member.cookie, body: allowedReply.body,
    })).status, 201);

    // Posts are invisible outside the workspace.
    assert.equal((await request(`/api/forum/posts/${postId}`, { cookie: outsider.cookie })).status, 404);
    assert.equal((await request(`/api/forum/posts/${postId}/messages`, { cookie: outsider.cookie })).status, 404);
    assert.equal((await request(`/api/forum/posts/${postId}/lock`, {
      method: 'PUT', cookie: outsider.cookie, body: { locked: false },
    })).status, 404);

    // Deleting the post removes it from the list and closes it for replies.
    const deletion = asMember({ type: 'delete', refMessageId: postId, postId, plaintext: '' });
    const deleted = await request(`/api/messages/${postId}`, {
      method: 'DELETE', cookie: member.cookie,
      body: { deviceId: memberDevice.id, keyVersion: 1, idempotencyKey: deletion.envelope.idempotencyKey, signature: deletion.body.signature, postId },
    });
    assert.equal(deleted.status, 200, await deleted.clone().text());
    assert.equal((await request(`/api/forum/posts/${postId}`, { cookie: member.cookie })).status, 404);
    const afterDelete = await json<{ data: Array<{ state: { postId: string } }> }>(
      await request(`/api/channels/${forum.id}/forum/posts`, { cookie: member.cookie }),
    );
    assert.deepEqual(afterDelete.data.map((entry) => entry.state.postId), [secondPostId]);
    const lateReply = asOwner({ type: 'message', refMessageId: null, postId, plaintext: 'too late' });
    assert.equal((await request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie: owner.cookie, body: lateReply.body,
    })).status, 400);
    const stored = await db.query.forumPosts.findFirst({ where: eq(forumPostTable.messageId, postId) });
    assert.ok(stored?.deletedAt);

    const forumAudit = await db.select({ action: auditLogs.action, details: auditLogs.details })
      .from(auditLogs)
      .where(sql`${auditLogs.details}->>'workspaceId' = ${workspace.id}`);
    const actions = new Set(forumAudit.map((row) => row.action));
    for (const action of ['forum.post.create', 'forum.tag.create', 'forum.post.lock', 'forum.post.resolve', 'message.delete']) {
      assert.equal(actions.has(action), true, action);
    }
    assert.equal(JSON.stringify(forumAudit).includes('the server must not see'), false);
    assert.equal((await verifyAuditChain()).valid, true);
  });

  it('fails the schema gate when the journal is intact but a catalog invariant is removed', async () => {
    const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
    await client.connect();
    try {
      await client.query('begin');
      await client.query('set local search_path = pg_catalog');
      await client.query(
        'alter table public.channel_keys drop constraint channel_keys_epoch_recipient_fk',
      );
      const catalog = await import('../db/schema-catalog.js');
      const snapshot = await catalog.loadSchemaCatalogSnapshot(client);
      assert.throws(
        () => catalog.assertSchemaCatalogMatches(snapshot),
        /DATABASE_SCHEMA_CATALOG_MISMATCH/,
      );
    } finally {
      await client.query('rollback').catch(() => undefined);
      await client.end();
    }
    const { checkDatabaseSchema } = await import('../db/index.js');
    assert.equal(await checkDatabaseSchema(), 21);
  });

  it('never re-signs a shortened audit chain after the external checkpoint anchor is deleted', async () => {
    const auditModule = await import('../middleware/audit.js');
    const { db } = await import('../db/index.js');
    const { auditLogs, users } = await import('../db/schema.js');
    await auditModule.flushAuditCheckpoint();
    const checkpointBefore = await readFile(auditCheckpointPath, 'utf8');
    const checkpoint = JSON.parse(checkpointBefore) as { logId: string };
    await assert.rejects(db.delete(auditLogs).where(eq(auditLogs.id, checkpoint.logId)),
      (error: any) => /append-only/.test(error.cause?.message ?? error.message));
    await assert.rejects(db.execute(sql`TRUNCATE audit_logs`),
      (error: any) => /append-only/.test(error.cause?.message ?? error.message));
    // Simulate an owner-level attacker who bypasses the append-only triggers;
    // the checkpoint anchor must still detect the shortened chain.
    await db.transaction(async (transaction) => {
      await transaction.execute(sql`ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_no_rewrite`);
      await transaction.delete(auditLogs).where(eq(auditLogs.id, checkpoint.logId));
      await transaction.execute(sql`ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_no_rewrite`);
    });
    const rowsAfterTruncation = await db.select({ id: auditLogs.id }).from(auditLogs);
    const target = await db.query.users.findFirst();
    assert.ok(target);
    const originalDisplayName = target.displayName;

    await assert.rejects(auditModule.auditedTransaction(async (transaction) => {
      await transaction.update(users).set({ displayName: 'must-roll-back' }).where(eq(users.id, target.id));
      return null;
    }, () => ({
      actorId: target.id,
      action: 'security.audit.truncation-control',
      targetType: 'user',
      targetId: target.id,
    })), /checkpoint|audit/i);

    assert.equal((await db.query.users.findFirst({ where: eq(users.id, target.id) }))?.displayName, originalDisplayName);
    assert.equal((await db.select({ id: auditLogs.id }).from(auditLogs)).length, rowsAfterTruncation.length);
    assert.equal(await readFile(auditCheckpointPath, 'utf8'), checkpointBefore);
    await assert.rejects(auditModule.checkAuditCheckpoint(), /checkpoint|audit/i);
  });

  async function createAccount(email: string, password: string, displayName: string, inviteToken: string) {
    const registration = await request('/api/auth/register', {
      method: 'POST', body: { email, password, displayName, inviteToken },
    });
    assert.equal(registration.status, 201);
    const login = await request('/api/auth/login', { method: 'POST', body: { email, password } });
    assert.equal(login.status, 200);
    const setCookie = login.headers.get('set-cookie');
    assert.ok(setCookie?.includes('HttpOnly'));
    assert.ok(setCookie?.includes('SameSite=Strict'));
    return {
      cookie: setCookie!.split(';', 1)[0],
      user: (await json<{ user: { id: string } }>(login)).user,
      password,
    };
  }

  async function createWorkspaceInvitation(workspaceId: string, cookie: string, email?: string) {
    const response = await request(`/api/workspaces/${workspaceId}/invitations`, {
      method: 'POST',
      cookie,
      body: { ...(email ? { email } : {}), expiresInSeconds: 3_600 },
    });
    assert.equal(response.status, 201);
    return json<{ id: string; token: string }>(response);
  }

  async function assignWorkspaceRole(workspaceId: string, cookie: string, roleId: string, userId: string) {
    const preview = await request(`/api/workspaces/${workspaceId}/roles/preview`, {
      method: 'POST', cookie, body: { operation: 'role.assign', roleId, userId },
    });
    assert.equal(preview.status, 200);
    const { authorizationRevision } = await json<{ authorizationRevision: string }>(preview);
    const assignment = await request(`/api/workspaces/${workspaceId}/members/${userId}/roles/${roleId}`, {
      method: 'POST', cookie, body: { expectedAuthorizationRevision: authorizationRevision },
    });
    assert.equal(assignment.status, 200);
  }

  async function deviceRegistrationBody(
    account: { cookie: string; user: { id: string }; password: string },
    keys: ReturnType<typeof deviceFixture>,
    name: string,
    cookie = account.cookie,
  ) {
    const challengeResponse = await request('/api/devices/challenge', { method: 'POST', cookie, body: {} });
    assert.equal(challengeResponse.status, 200);
    const { challenge } = await json<{ challenge: string }>(challengeResponse);
    const proof = sign('sha256', Buffer.from(serializeDeviceChallengeProof(account.user.id, challenge)), {
      key: keys.signingPrivateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64');
    return {
      name,
      identityKey: keys.identityKey,
      challenge,
      proof,
      currentPassword: account.password,
    };
  }

  async function registerDevice(
    account: { cookie: string; user: { id: string }; password: string },
    keys: ReturnType<typeof deviceFixture>,
    name: string,
  ) {
    const response = await request('/api/devices', {
      method: 'POST',
      cookie: account.cookie,
      body: await deviceRegistrationBody(account, keys, name),
    });
    assert.equal(response.status, 201);
    const device = await json<{ id: string; identityKey: string; approvedAt: string | null }>(response);
    if (!device.approvedAt) {
      const { db } = await import('../db/index.js'); const { devices } = await import('../db/schema.js');
      const actor = (await db.query.devices.findMany({ where: eq(devices.userId, account.user.id) })).find((d) => d.approvedAt && !d.revokedAt);
      assert.ok(actor, 'test fixture must retain an approved device for enrollment');
      const actorKeys = fixtureKeys.get(JSON.parse(actor.identityKey).signingKey.x)!;
      const { directoryHead } = await import('../services/directory.service.js');
      const head = await directoryHead(db, account.user.id);
      const event = { kind: 'approve' as const, deviceId: device.id, identityKey: device.identityKey, actorDeviceId: actor.id };
      const proof = sign('sha256', Buffer.from(serializeDeviceDecision(head, event)), { key: actorKeys.signingPrivateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
      await (await import('../services/device.service.js')).approveDevice(account.user.id, actor.id, device.id, head, proof);
    }
    return device;
  }

  async function proposeFixtureMls(input: { channelId: string; version: number; rawKey: Buffer; senderCookie: string; senderKeys: ReturnType<typeof deviceFixture>; recipients: Array<{deviceId: string;identityKey: string}>; fresh?: boolean; poisonWelcome?: boolean }) {
    const crypto = await import('../../../client/src/services/' + 'mls-crypto.ts');
    const state = await json<any>(await request(`/api/channels/${input.channelId}/key-recipients`, { cookie: input.senderCookie }));
    const materials = new Map<string, Awaited<ReturnType<typeof crypto.generateEpochKeyPackage>>>();
    const roster: GroupKeyPackage[] = [];
    const sender = state.recipients.find((r: any) => JSON.parse(r.identityKey).signingKey.x === JSON.parse(input.senderKeys.identityKey).signingKey.x);
    assert.ok(sender);
    for (const recipient of state.recipients) {
      const keys = fixtureKeys.get(JSON.parse(recipient.identityKey).signingKey.x); assert.ok(keys);
      const material = await crypto.generateEpochKeyPackage(recipient.deviceId); materials.set(recipient.deviceId, material);
      const pkg = { ...recipient, packageId: randomUUID(), keyPackage: material.publicPackage };
      const signature = sign('sha256', Buffer.from(serializeGroupKeyPackage(input.channelId, input.version, pkg)), { key: keys.signingPrivateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
      // These fixture endpoints include offline participants. Their protocol
      // publication is exercised through the service; account-security's suite
      // separately exercises package/session binding over HTTP.
      await (await import('../services/mls.service.js')).publishKeyPackage(input.channelId, recipient.userId, recipient.deviceId, input.version, {...pkg, signature});
      roster.push({...pkg, signature});
    }
    const parent = state.currentVersion && state.protocolVersion === 3 ? await json<any>(await request(`/api/channels/${input.channelId}/mls/epochs/${state.currentVersion}`, {cookie: input.senderCookie})) : null;
    const context = {channelId: input.channelId, version: input.version, previousVersion: state.currentVersion, previousTranscript: parent?.transcript ?? '0'.repeat(64)};
    const groupId = JSON.stringify(['alparts', input.channelId, input.version, context.previousTranscript]);
    const group = await crypto.createEpochGroup(groupId, materials.get(sender.deviceId)!, roster.map(p => p.keyPackage));
    input.rawKey.set(group.raw);
    const keyCommitment = createHash('sha256').update(input.rawKey).digest('base64url');
    const { db } = await import('../db/index.js'); const {directoryHead} = await import('../services/directory.service.js');
    const directoryHeads = await Promise.all([...new Set(roster.map(p => p.userId))].sort().map(id => directoryHead(db, id)));
    const unsigned = {...context, keyCommitment, roster, directoryHeads, distributorDeviceId: sender.deviceId, welcome: input.poisonWelcome ? Buffer.from('invalid MLS welcome').toString('base64') : group.welcome, commit: group.commit};
    const epoch: MlsEpoch = {...unsigned, signature: sign('sha256',Buffer.from(serializeMlsEpoch(unsigned)),{key:input.senderKeys.signingPrivateKey,dsaEncoding:'ieee-p1363'}).toString('base64')};
    const transcript = createHash('sha256').update(serializeMlsEpoch(epoch)).digest('hex');
    const encryptedKey = Buffer.from(JSON.stringify({mls:1,version:input.version,transcript})).toString('base64');
    const keys = roster.map(recipient => ({deviceId:recipient.deviceId,encryptedKey,signature:sign('sha256',Buffer.from(serializeChannelKeyWrap({channelId:input.channelId,keyVersion:input.version,keyCommitment,recipientDeviceId:recipient.deviceId,encryptedKey})),{key:input.senderKeys.signingPrivateKey,dsaEncoding:'ieee-p1363'}).toString('base64')}));
    const joined = new Map<string, Buffer>();
    for(const member of roster) {
      const key = fixtureKeys.get(JSON.parse(member.identityKey).signingKey.x)!;
      if(input.poisonWelcome && member.deviceId !== sender.deviceId) {
        await assert.rejects(crypto.joinEpochGroup(groupId,materials.get(member.deviceId)!,roster.map(p=>p.keyPackage),epoch.welcome));
        continue;
      }
      const raw = member.deviceId === sender.deviceId ? group.raw : await crypto.joinEpochGroup(groupId,materials.get(member.deviceId)!,roster.map(p=>p.keyPackage),epoch.welcome);
      assert.deepEqual(raw,group.raw); joined.set(key.encryptionPrivateKey.export({format:'jwk'}).n!,Buffer.from(raw));
    }
    joinedMlsKeys.set(encryptedKey,joined);
    const freshStartSignature = input.fresh ? sign('sha256',Buffer.from(serializeChannelKeyFreshStart({channelId:input.channelId,keyVersion:input.version,keyCommitment,deviceId:sender.deviceId})),{key:input.senderKeys.signingPrivateKey,dsaEncoding:'ieee-p1363'}).toString('base64') : undefined;
    const response = await request(`/api/channels/${input.channelId}/mls/epochs${input.fresh?'/fresh-start':''}`,{method:'POST',cookie:input.senderCookie,body:{epoch,keys,...(freshStartSignature?{freshStartSignature}:{})}});
    assert.equal(response.status,201,await response.text());
    return {keyCommitment,keys};
  }

  async function distributeAndAcknowledgeChannelKey(input: {
    channelId: string;
    version: number;
    rawKey: Buffer;
    senderCookie: string;
    senderKeys: ReturnType<typeof deviceFixture>;
    recipients: Array<{ deviceId: string; identityKey: string }>;
    acknowledgements: Array<{
      deviceId: string;
      cookie: string;
      keys: ReturnType<typeof deviceFixture>;
    }>;
  }) {
    const {keyCommitment,keys} = await proposeFixtureMls(input);

    for (const acknowledgement of input.acknowledgements) {
      const wrapped = keys.find((key) => key.deviceId === acknowledgement.deviceId);
      assert.ok(wrapped, `missing wrap for ${acknowledgement.deviceId}`);
      const unwrapped = unwrapKey(wrapped.encryptedKey, acknowledgement.keys.encryptionPrivateKey);
      assert.deepEqual(unwrapped, input.rawKey);
      assert.equal(createHash('sha256').update(unwrapped).digest('base64url'), keyCommitment);
      await acknowledgeChannelKeyDelivery({
        channelId: input.channelId,
        version: input.version,
        keyCommitment,
        encryptedKey: wrapped.encryptedKey,
        deviceId: acknowledgement.deviceId,
        cookie: acknowledgement.cookie,
        keys: acknowledgement.keys,
      });
    }
    return { keyCommitment, keys };
  }

  function signedChannelKeyWrap(input: {
    channelId: string;
    version: number;
    keyCommitment: string;
    rawKey: Buffer;
    recipient: { deviceId: string; identityKey: string };
    senderKeys: ReturnType<typeof deviceFixture>;
  }) {
    const encryptedKey = wrapKey(input.rawKey, input.recipient.identityKey);
    const signature = sign('sha256', Buffer.from(serializeChannelKeyWrap({
      channelId: input.channelId,
      keyVersion: input.version,
      keyCommitment: input.keyCommitment,
      recipientDeviceId: input.recipient.deviceId,
      encryptedKey,
    })), {
      key: input.senderKeys.signingPrivateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64');
    return { deviceId: input.recipient.deviceId, encryptedKey, signature };
  }

  async function acknowledgeChannelKeyDelivery(input: {
    channelId: string;
    version: number;
    keyCommitment: string;
    encryptedKey: string;
    deviceId: string;
    cookie: string;
    keys: ReturnType<typeof deviceFixture>;
  }) {
    const deliveriesResponse = await request(`/api/channels/${input.channelId}/keys`, {
      cookie: input.cookie,
    });
    assert.equal(deliveriesResponse.status, 200);
    const deliveries = await json<Array<{
      deliveryId: string;
      version: number;
      keyCommitment: string;
      encryptedKey: string;
      distributorDeviceId: string;
    }>>(deliveriesResponse);
    const delivery = deliveries.find((candidate) => (
      candidate.version === input.version
      && candidate.keyCommitment === input.keyCommitment
      && candidate.encryptedKey === input.encryptedKey
    ));
    assert.ok(delivery, `missing committed delivery for ${input.deviceId}`);
    const signature = sign('sha256', Buffer.from(serializeChannelKeyAcknowledgement({
      deliveryId: delivery.deliveryId,
      channelId: input.channelId,
      keyVersion: input.version,
      keyCommitment: input.keyCommitment,
      recipientDeviceId: input.deviceId,
      distributorDeviceId: delivery.distributorDeviceId,
      encryptedKey: input.encryptedKey,
    })), {
      key: input.keys.signingPrivateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64');
    const response = await request(`/api/channels/${input.channelId}/keys/acknowledge`, {
      method: 'POST',
      cookie: input.cookie,
      body: { deliveryId: delivery.deliveryId, signature },
    });
    assert.equal(response.status, 200);
    return json<{ version: number; status: string; activated: boolean }>(response);
  }

  async function request(path: string, options: { method?: string; cookie?: string; body?: unknown; contentType?: string } = {}): Promise<Response> {
    const headers: Record<string, string> = { Origin: 'http://localhost:5173' };
    if (options.cookie) {
      headers.Cookie = options.cookie;
      const addressSeed = createHash('sha256').update(options.cookie).digest();
      headers['X-Forwarded-For'] = `198.18.${addressSeed[0]}.${addressSeed[1]}`;
    }
    if (options.cookie && options.method === 'DELETE' && /^\/api\/devices\/[^/]+$/.test(path)) {
      const {db} = await import('../db/index.js'); const {devices} = await import('../db/schema.js');
      const sessions = await json<any[]>(await request('/api/auth/sessions',{cookie:options.cookie}));
      const actorId = Array.isArray(sessions) ? sessions.find(s=>s.current)?.deviceId : null;
      const target = await db.query.devices.findFirst({where:eq(devices.id,path.split('/').at(-1)!)});
      const actor = actorId ? await db.query.devices.findFirst({where:eq(devices.id,actorId)}) : null;
      if(actor && target) {
        const head = await (await import('../services/directory.service.js')).directoryHead(db,actor.userId);
        const signature = sign('sha256',Buffer.from(serializeDeviceDecision(head,{kind:'revoke',deviceId:target.id,identityKey:target.identityKey,actorDeviceId:actor.id})),{key:fixtureKeys.get(JSON.parse(actor.identityKey).signingKey.x)!.signingPrivateKey,dsaEncoding:'ieee-p1363'}).toString('base64');
        options = {...options,body:{head,signature}};
      }
    }
    if(options.cookie && credentials.has(options.cookie) && isSensitiveAction(options.method ?? 'GET',path.split('?')[0])) {
      const purpose = `${options.method} ${path.split('?')[0]} ${createHash('sha256').update(canonicalActionBody(options.body)).digest('base64url')}`;
      const optionsResponse = await request('/api/auth/step-up/options',{method:'POST',cookie:options.cookie,body:{purpose}});
      if(optionsResponse.status===200) {
        const challenge = await json<any>(optionsResponse);
        const verified = await request('/api/auth/step-up/verify',{method:'POST',cookie:options.cookie,body:{id:challenge.id,purpose,password:credentials.get(options.cookie)!.password}});
        assert.equal(verified.status,200);headers['X-Alparts-Step-Up']=(await json<any>(verified)).token;
      }
    }
    const rawBody = Buffer.isBuffer(options.body) ? options.body : null;
    if (options.body !== undefined) headers['Content-Type'] = options.contentType ?? (rawBody ? 'application/octet-stream' : 'application/json');
    const response = await fetch(`${baseUrl}${path}`, {
      method: options.method || 'GET',
      headers,
      body: options.body === undefined
        ? undefined
        : rawBody
          ? new Uint8Array(rawBody)
          : JSON.stringify(options.body),
    });
    if (response.status === 429 && response.headers.get('RateLimit-Limit') === '300') {
      // This long scenario now includes real per-action authentication. Respect
      // the unchanged production source budget rather than bypassing it.
      await delay(Math.min(60_000, Number(response.headers.get('Retry-After')) * 1000 + 100));
      return request(path, options);
    }
    if(path==='/api/auth/login' && response.status===200) {const login=await response.clone().json() as any;credentials.set(response.headers.get('set-cookie')!.split(';')[0],{password:(options.body as any).password,userId:login.user.id});}
    return response;
  }
});

async function json<T>(response: Response): Promise<T> {
  return response.json() as Promise<T>;
}

function deviceFixture() {
  const encryption = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
  const signingKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const encryptionKey = encryption.publicKey.export({ format: 'jwk' });
  const signingKey = signingKeys.publicKey.export({ format: 'jwk' });
  encryptionKey.alg = 'RSA-OAEP-256';
  encryptionKey.ext = true;
  encryptionKey.key_ops = ['encrypt'];
  signingKey.alg = 'ES256';
  signingKey.ext = true;
  signingKey.key_ops = ['verify'];
  const fixture = {
    identityKey: JSON.stringify({ version: 1, encryptionKey, signingKey }),
    encryptionPrivateKey: encryption.privateKey,
    signingPrivateKey: signingKeys.privateKey,
  };
  fixtureKeys.set(signingKey.x!, fixture);
  return fixture;
}

function wrapKey(raw: Buffer, identityKey: string): string {
  const encryptionKey = JSON.parse(identityKey).encryptionKey;
  const key = createPublicKey({ key: encryptionKey as any, format: 'jwk' });
  return publicEncrypt({ key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, raw).toString('base64');
}

function unwrapKey(wrapped: string, privateKey: import('node:crypto').KeyObject): Buffer {
  const joined = joinedMlsKeys.get(wrapped)?.get(privateKey.export({format:'jwk'}).n!);
  if (joined) return Buffer.from(joined);
  return privateDecrypt({
    key: privateKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256',
  }, Buffer.from(wrapped, 'base64'));
}

function encryptedMessage(
  channelId: string,
  authorId: string,
  deviceId: string,
  privateKey: import('node:crypto').KeyObject,
  key: Buffer,
  plaintext: string,
  idempotencyKey?: string,
  keyVersion = 1,
) {
  return encryptedCryptoEvent('message', channelId, null, authorId, deviceId, privateKey, key, plaintext, idempotencyKey, keyVersion);
}

function encryptedEdit(
  channelId: string,
  messageId: string,
  authorId: string,
  deviceId: string,
  privateKey: import('node:crypto').KeyObject,
  key: Buffer,
  plaintext: string,
) {
  return encryptedCryptoEvent('edit', channelId, messageId, authorId, deviceId, privateKey, key, plaintext);
}

function encryptedCryptoEvent(
  type: 'message' | 'edit',
  channelId: string,
  refMessageId: string | null,
  authorId: string,
  deviceId: string,
  privateKey: import('node:crypto').KeyObject,
  key: Buffer,
  plaintext: string,
  requestedIdempotencyKey?: string,
  keyVersion = 1,
) {
  const idempotencyKey = requestedIdempotencyKey ?? randomUUID();
  const nonce = randomBytes(12);
  const unsigned = {
    type,
    channelId,
    authorId,
    deviceId,
    keyVersion,
    idempotencyKey,
    refMessageId,
    broadcastMention: false,
  };
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(serializeMessageAad(unsigned)));
  const encryptedContent = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final(), cipher.getAuthTag()]).toString('base64');
  const envelope: SignedMessageEnvelope = { ...unsigned, encryptedContent, contentNonce: nonce.toString('base64') };
  return {
    envelope,
    body: {
      encryptedContent,
      contentNonce: envelope.contentNonce,
      deviceId,
      keyVersion,
      idempotencyKey,
      broadcastMention: false,
      signature: signEnvelope(envelope, privateKey),
    },
  };
}

/** A v4 forum event. Deletes carry no ciphertext, like other deletes. */
function encryptedForumEvent(input: {
  type: 'message' | 'edit' | 'delete';
  channelId: string;
  refMessageId: string | null;
  postId: string | null;
  authorId: string;
  deviceId: string;
  privateKey: import('node:crypto').KeyObject;
  key: Buffer;
  plaintext: string;
}) {
  const idempotencyKey = randomUUID();
  const unsigned = {
    type: input.type,
    channelId: input.channelId,
    authorId: input.authorId,
    deviceId: input.deviceId,
    keyVersion: 1,
    idempotencyKey,
    refMessageId: input.refMessageId,
    broadcastMention: false,
    postId: input.postId,
  };
  let encryptedContent = '';
  let contentNonce = '';
  if (input.type !== 'delete') {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', input.key, nonce);
    cipher.setAAD(Buffer.from(serializeMessageAad(unsigned)));
    encryptedContent = Buffer.concat([cipher.update(input.plaintext, 'utf8'), cipher.final(), cipher.getAuthTag()]).toString('base64');
    contentNonce = nonce.toString('base64');
  }
  const envelope: SignedMessageEnvelope = { ...unsigned, encryptedContent, contentNonce };
  return {
    envelope,
    body: {
      encryptedContent,
      contentNonce,
      deviceId: input.deviceId,
      keyVersion: 1,
      idempotencyKey,
      broadcastMention: false,
      signature: signEnvelope(envelope, input.privateKey),
      ...(input.postId ? { postId: input.postId } : {}),
    },
  };
}

function encryptAttachmentChunk(key: Buffer, noncePrefix: Buffer, index: number, aad: Buffer, plaintext: Buffer): Buffer {
  assert.equal(noncePrefix.length, 8);
  const nonce = Buffer.alloc(12);
  noncePrefix.copy(nonce, 0);
  nonce.writeUInt32BE(index, 8);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function decryptAttachmentChunk(key: Buffer, noncePrefix: Buffer, index: number, aad: Buffer, ciphertext: Buffer): Buffer {
  const nonce = Buffer.alloc(12);
  noncePrefix.copy(nonce, 0);
  nonce.writeUInt32BE(index, 8);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
  return Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]);
}

function signedAttachmentFinalizeBody(input: {
  uploadId: string;
  messageId: string;
  channelId: string;
  authorId: string;
  deviceId: string;
  privateKey: import('node:crypto').KeyObject;
  keyVersion: number;
  filenameEnc: string;
  mimeType: string;
  wrappedKey: string;
  chunkCount: number;
  cryptoManifest: {
    version: 1;
    algorithm: 'AES-256-GCM';
    nonceStrategy: 'prefix-counter-be32';
    noncePrefix: string;
    aadVersion: 1;
    plaintextSize: number;
  };
}) {
  const envelope: SignedAttachmentEnvelope = {
    type: 'attachment',
    uploadId: input.uploadId,
    messageId: input.messageId,
    channelId: input.channelId,
    authorId: input.authorId,
    deviceId: input.deviceId,
    keyVersion: input.keyVersion,
    filenameEnc: input.filenameEnc,
    mimeType: input.mimeType,
    wrappedKey: input.wrappedKey,
    noncePrefix: input.cryptoManifest.noncePrefix,
    plaintextSize: input.cryptoManifest.plaintextSize,
    chunkCount: input.chunkCount,
  };
  const signature = sign('sha256', Buffer.from(serializeAttachmentEnvelope(envelope)), {
    key: input.privateKey,
    dsaEncoding: 'ieee-p1363',
  }).toString('base64');
  return {
    deviceId: input.deviceId,
    keyVersion: input.keyVersion,
    signature,
    wrappedKey: input.wrappedKey,
    chunkCount: input.chunkCount,
    cryptoManifest: input.cryptoManifest,
  };
}

function pick(object: Record<string, unknown>, keys: string[]): Record<string, unknown> {
  return Object.fromEntries(keys.map((key) => [key, object[key]]));
}

function signEnvelope(envelope: SignedMessageEnvelope, privateKey: import('node:crypto').KeyObject): string {
  return sign('sha256', Buffer.from(serializeMessageEnvelope(envelope)), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  }).toString('base64');
}

async function onceConnected(socket: import('socket.io-client').Socket): Promise<void> {
  if (socket.connected) return;
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', () => resolve());
    socket.once('connect_error', reject);
  });
}

async function joinChannel(socket: import('socket.io-client').Socket, channelId: string): Promise<boolean> {
  return new Promise((resolve) => socket.emit('channel:join', channelId, (result: { ok: boolean }) => resolve(result.ok)));
}

interface VoiceJoinAck {
  ok: boolean;
  error?: string;
  self?: import('@alparts/shared').VoiceParticipant;
  participants?: import('@alparts/shared').VoiceParticipant[];
}

async function joinVoice(
  socket: import('socket.io-client').Socket,
  channelId: string,
): Promise<VoiceJoinAck> {
  return new Promise((resolve) => socket.emit('voice:join', { channelId }, (result: VoiceJoinAck) => resolve(result)));
}

async function emitSocketAck(
  socket: import('socket.io-client').Socket,
  event: string,
  payload: unknown,
): Promise<Record<string, unknown>> {
  return new Promise((resolve) => socket.emit(event, payload, (result: Record<string, unknown>) => resolve(result)));
}

async function onceSocketEvent<T>(
  socket: import('socket.io-client').Socket,
  event: string,
  timeoutMs = 2_000,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onEvent = (payload: T) => {
      clearTimeout(timer);
      resolve(payload);
    };
    const timer = setTimeout(() => {
      socket.off(event, onEvent);
      reject(new Error(`Timed out waiting for ${event}`));
    }, timeoutMs);
    socket.once(event, onEvent);
  });
}

async function onceSocketEventMatching<T>(
  socket: import('socket.io-client').Socket,
  event: string,
  predicate: (payload: T) => boolean,
  timeoutMs = 2_000,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onEvent = (payload: T) => {
      if (!predicate(payload)) return;
      clearTimeout(timer);
      socket.off(event, onEvent);
      resolve(payload);
    };
    const timer = setTimeout(() => {
      socket.off(event, onEvent);
      reject(new Error(`Timed out waiting for matching ${event}`));
    }, timeoutMs);
    socket.on(event, onEvent);
  });
}

function assertNewestFirst(events: Array<{ id: string; createdAt: string }>): void {
  for (let index = 1; index < events.length; index += 1) {
    const previous = events[index - 1];
    const current = events[index];
    const previousTime = Date.parse(previous.createdAt);
    const currentTime = Date.parse(current.createdAt);
    assert.ok(
      previousTime > currentTime || (previousTime === currentTime && previous.id > current.id),
      'message history must remain newest-first by (createdAt, id)',
    );
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
