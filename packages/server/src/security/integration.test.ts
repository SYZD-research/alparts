import strictAssert from 'node:assert/strict';
import {
  constants,
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  generateKeyPairSync,
  publicEncrypt,
  randomBytes,
  randomUUID,
  sign,
  verify,
} from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { crc32, deflateSync } from 'node:zlib';
import { eq, inArray, sql } from 'drizzle-orm';
import pg from 'pg';
import {
  acceptAll,
  createCommit,
  createGroup,
  decodeMlsMessage,
  emptyPskIndex,
  encodeMlsMessage,
  generateKeyPackage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  joinGroup,
  makePskIndex,
  mlsExporter,
  processMessage,
  type ClientState,
  type KeyPackage,
  type MlsPublicMessage,
  type PrivateKeyPackage,
} from 'ts-mls';
import { defaultClientConfig } from 'ts-mls/clientConfig.js';
import { signKeyPackage } from 'ts-mls/keyPackage.js';
import { signLeafNodeKeyPackage } from 'ts-mls/leafNode.js';
import {
  MLS_CIPHERSUITE,
  MLS_GROUP_EXPORTER_LABEL,
  mlsExporterContext,
  mlsGroupId,
  serializeMlsGroupCommit,
  serializeMlsMemberPackage,
  type MlsGroupCommit,
  type MlsGroupMember,
  type MlsMemberPackage,
  type DirectoryHead,
  Permissions,
  serializeDeviceDecision,
  serializeAttachmentEnvelope,
  serializeChannelKeyFreshStart,
  serializeChannelKeyWrap,
  serializeDeviceChallengeProof,
  serializeMessageAad,
  serializeMessageEnvelope,
  serializeVoiceSignalEnvelope,
  type SignedAttachmentEnvelope,
  type SignedEventReference,
  type SignedMessageEnvelope,
  type SignedVoiceSignalEnvelope,
} from '@alparts/shared';

/**
 * The scenario tests in this file are long. Every call with an assertion
 * signature (`asserts actual is T`) makes the type checker's flow analysis
 * recurse once more for each later reference, which overflows its stack in
 * functions this size. The equality checks here narrow nothing, so they get
 * plain signatures; assert.ok keeps its narrowing.
 */
type ScenarioAssert = Omit<typeof strictAssert, 'equal' | 'deepEqual'> & {
  equal(actual: unknown, expected: unknown, message?: string | Error): void;
  deepEqual(actual: unknown, expected: unknown, message?: string | Error): void;
};
const assert: ScenarioAssert = strictAssert;

const enabled = process.env.RUN_INTEGRATION === '1';
const fixtureKeys = new Map<string, ReturnType<typeof deviceFixture>>();

describe('security boundaries (PostgreSQL + object storage)', { skip: !enabled }, () => {
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
    assert.equal(await dbModule.checkDatabaseSchema(), 24);
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
    // Registration needs the code mailed to the address. An existing account
    // gets the same answer and a notice, but no code to finish with.
    const { developmentEmails } = await import('../services/email.service.js');
    const existingCodeRequest = await request('/api/auth/register/code', {
      method: 'POST', body: { email: 'alice@example.test', inviteToken: unboundInvitation.token },
    });
    assert.equal(existingCodeRequest.status, 202);
    const existingNotice = [...developmentEmails()].reverse().find((message) => message.to === 'alice@example.test');
    assert.ok(existingNotice && !/\b\d{6}\b/.test(existingNotice.text));
    const existingEmailRegistration = await request('/api/auth/register', {
      method: 'POST',
      body: { email: 'alice@example.test', password: 'Correct-Horse-Battery-8!', displayName: 'Probe', inviteToken: unboundInvitation.token, emailCode: '123456' },
    });
    assert.equal(existingEmailRegistration.status, 400);
    assert.equal((await json<{ error: string }>(existingEmailRegistration)).error, 'INVALID_EMAIL_CODE');
    const withoutCode = await request('/api/auth/register', {
      method: 'POST',
      body: { email: 'unbound@example.test', password: 'Correct-Horse-Battery-9!', displayName: 'Unbound', inviteToken: unboundInvitation.token },
    });
    assert.equal(withoutCode.status, 400, 'a registration without the mailed code is refused');
    const verification = await import('../services/email-verification.service.js');
    const guessedCode = await emailCode('unbound@example.test', unboundInvitation.token);
    const wrongCode = guessedCode === '000000' ? '000001' : '000000';
    for (let attempt = 0; attempt < verification.MAX_EMAIL_CODE_ATTEMPTS; attempt += 1) {
      await assert.rejects(verification.consumeRegistrationCode('unbound@example.test', wrongCode), /INVALID_EMAIL_CODE/);
    }
    await assert.rejects(verification.consumeRegistrationCode('unbound@example.test', guessedCode), /INVALID_EMAIL_CODE/,
      'wrong guesses use the code up');
    const unboundRegistration = await request('/api/auth/register', {
      method: 'POST',
      body: {
        email: 'unbound@example.test',
        password: 'Correct-Horse-Battery-9!',
        displayName: 'Unbound',
        inviteToken: unboundInvitation.token,
        emailCode: await emailCode('unbound@example.test', unboundInvitation.token),
      },
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
    const firstRetryDevice = await json<{ id: string; identityKey: string }>(firstDeviceRegistration);
    const repeatedDeviceRegistration = await request('/api/devices', {
      method: 'POST', cookie: retryDeviceAccount.cookie,
      body: await deviceRegistrationBody(retryDeviceAccount, retryDeviceKeys, 'Retry identity renamed'),
    });
    assert.equal(repeatedDeviceRegistration.status, 200);
    assert.equal((await json<{ id: string }>(repeatedDeviceRegistration)).id, firstRetryDevice.id);

    // Provisional epochs from before continuous groups (more than 64 of them,
    // including an ordinary member) must not consume an account-global
    // enrollment cap and prevent that member from recovering a device. Group
    // protocol 4 creates no such rows, but databases may still hold them.
    // Seed the exact database state directly so this regression test remains
    // fast and independent of API rate limits.
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

    // Losing every device in a channel's group must not permanently wedge
    // future writes. Recovery starts a new group without pretending old
    // ciphertext is decryptable, and is visible in state and audit logs.
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
    const firstRetryMember = asGroupMember(retryDeviceAccount.cookie, retryDeviceAccount.user.id, retryDeviceKeys, firstRetryDevice);
    const recoveryGroup = new ChannelGroup(recoveryChannel.id);
    // Alone, the genesis is an empty commit; the group is usable at once.
    const soleGenesis = await recoveryGroup.create(firstRetryMember);
    assert.equal(soleGenesis.response!.status, 201);
    assert.deepEqual(await json(soleGenesis.response!), { version: 1, epoch: 1 });
    assert.equal(soleGenesis.envelope.welcome, '');

    // A newly enrolled device of the same account joins through an Add
    // commit by a device already in the group. Until then it cannot write,
    // while its waiting addition never stops the others from writing; it
    // writes as soon as the commit is accepted, without any acknowledgement.
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
    const newDeviceMember = asGroupMember(freshStartCookie, retryDeviceAccount.user.id, freshStartKeys, freshStartDevice);
    const newDeviceState = await recoveryGroup.state(newDeviceMember);
    assert.equal(newDeviceState.nextVersion, 2);
    assert.deepEqual(
      [newDeviceState.ownMembership, newDeviceState.canCommit, newDeviceState.canCreate, newDeviceState.historyRecoveryRequired],
      [null, false, false, false],
    );
    assert.equal((await recoveryGroup.publish(newDeviceMember)).status, 201);
    assert.deepEqual((await recoveryGroup.state(firstRetryMember)).pendingAddDeviceIds, [freshStartDevice.id]);
    assert.equal((await groupMessage(firstRetryMember, recoveryChannel.id, recoveryGroup.key(1), 1)).status, 201,
      'a device waiting to be added does not hold up writes');
    assert.deepEqual(await refusal(await groupMessage(newDeviceMember, recoveryChannel.id, randomBytes(32), 1)),
      [400, 'INVALID_KEY_VERSION'], 'a device outside the group cannot write');
    // Starting over is only for a device nobody can add: here a member is reachable.
    const prematureRestart = await recoveryGroup.create(newDeviceMember, [], { freshStart: true });
    assert.deepEqual(await refusal(prematureRestart.response!), [409, 'KEY_FRESH_START_NOT_REQUIRED']);
    const deviceAdded = await recoveryGroup.commit(firstRetryMember, { add: [newDeviceMember] });
    assert.equal(deviceAdded.response!.status, 201);
    assert.equal(deviceAdded.outcomes.get(freshStartDevice.id), 'current', 'the added device joins from the Welcome');
    assert.equal((await groupMessage(newDeviceMember, recoveryChannel.id, recoveryGroup.key(2), 2,
      'written right after the commit was accepted')).status, 201);
    const staleWrite = await groupMessage(firstRetryMember, recoveryChannel.id, recoveryGroup.key(1), 1);
    assert.equal(staleWrite.status, 400);
    assert.deepEqual(pick(await json(staleWrite), ['code', 'currentVersion']), { code: 'KEY_VERSION_STALE', currentVersion: 2 },
      'the writer learns which version to reseal for');
    assert.equal((await groupMessage(firstRetryMember, recoveryChannel.id, recoveryGroup.key(2), 2)).status, 201);
    assert.equal((await request(`/api/devices/${freshStartDevice.id}`, {
      method: 'DELETE', cookie: freshStartCookie,
    })).status, 200);
    assert.deepEqual(await refusal(await groupMessage(firstRetryMember, recoveryChannel.id, recoveryGroup.key(2), 2)),
      [400, 'KEY_ROTATION_REQUIRED'], 'a revoked device in the group stops writes');

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
    // Earlier provisional epochs (before continuous groups) that include an
    // ordinary member never keep that member from enrolling a device.
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
    // Every device of the group is now revoked: nobody can commit, so the
    // remaining device may start over, and only that way.
    const recoveryMember = asGroupMember(recoveryCookie, retryDeviceAccount.user.id, recoveryKeys, recoveryDevice);
    const recoveryState = await recoveryGroup.state(recoveryMember);
    assert.equal(recoveryState.historyRecoveryRequired, true);
    assert.equal(recoveryState.rotationRequired, true);
    assert.equal(recoveryState.canRotate, false, 'no device here can commit to this group');
    assert.deepEqual(recoveryState.requiredRemoveDeviceIds, [firstRetryDevice.id, freshStartDevice.id].sort());
    assert.deepEqual(recoveryState.recipients.map((recipient: { deviceId: string }) => recipient.deviceId), [recoveryDevice.id]);
    const recovered = await recoveryGroup.create(recoveryMember, [], { freshStart: true });
    assert.equal(recovered.response!.status, 201);
    assert.deepEqual(await json(recovered.response!), { version: 3, epoch: 1 });
    assert.equal(recovered.envelope.previousTranscript, groupTranscript(deviceAdded.envelope), 'the new group continues the old chain');
    const recoveredWrite = await groupMessage(recoveryMember, recoveryChannel.id, recoveryGroup.key(3), 3,
      'future writes survive total key-holder loss');
    assert.equal(recoveredWrite.status, 201);
    const recoveryAudit = await json<{ data: Array<{ action: string; details: Record<string, unknown> | null }> }>(await request(
      `/api/workspaces/${recoveryWorkspace.id}/audit-logs?limit=100`,
      { method: 'POST', cookie: recoveryCookie, body: {} },
    ));
    const freshStartAudit = recoveryAudit.data.find((entry) => entry.action === 'channel.key.group.fresh_start');
    assert.ok(freshStartAudit, 'starting over is recorded');
    assert.deepEqual(freshStartAudit.details?.removed, [firstRetryDevice.id, freshStartDevice.id].sort());
    assert.equal(recoveryAudit.data.some((entry) => entry.action === 'channel.key.group.commit'), true);
    // Keep this account from becoming an unintended recipient in the shared
    // workspace scenarios below. Self-revocation also proves that the newly
    // recovered group remains subject to the same fail-closed holder-loss rule.
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
    const raceEmails = ['race-a@example.test', 'race-b@example.test'];
    const raceCodes: string[] = [];
    for (const email of raceEmails) raceCodes.push(await emailCode(email, singleUseInvitation.token));
    const racingRegistrations = await Promise.all(raceEmails.map((email, index) => request('/api/auth/register', {
      method: 'POST',
      body: { email, password: 'Correct-Horse-Battery-9!', displayName: 'Race', inviteToken: singleUseInvitation.token, emailCode: raceCodes[index] },
    })));
    assert.deepEqual(racingRegistrations.map((response) => response.status).sort(), [201, 403],
      'a single-use invitation must be consumed at most once under concurrency');

    const bobKeys = deviceFixture();
    const malloryKeys = deviceFixture();
    const bobDevice = await registerDevice(bob, bobKeys, 'Bob test device');
    const malloryDevice = await registerDevice(mallory, malloryKeys, 'Mallory test device');
    const aliceMember = asGroupMember(alice.cookie, alice.user.id, aliceKeys, aliceDevice);
    const bobMember = asGroupMember(bob.cookie, bob.user.id, bobKeys, bobDevice);
    const malloryMember = asGroupMember(mallory.cookie, mallory.user.id, malloryKeys, malloryDevice);

    // A channel left only with a non-manager who was never in its group must
    // not stay unwritable: nobody remains who could add that viewer, so it
    // may start over after confirming its identity, and managers are told.
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
    const orphanGroup = new ChannelGroup(orphanChannel.id);
    assert.equal((await orphanGroup.create(aliceMember)).response!.status, 201);
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
    const orphanState = await orphanGroup.state(malloryMember);
    assert.equal(orphanState.historyRecoveryRequired, true);
    assert.equal(orphanState.canRotate, false, 'only a usable member commits to the group');
    assert.deepEqual(orphanState.requiredRemoveDeviceIds, [aliceDevice.id]);
    assert.deepEqual(orphanState.recipients.map((recipient: { deviceId: string }) => recipient.deviceId), [malloryDevice.id]);
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
    const orphanRestart = await orphanGroup.create(malloryMember, [], { freshStart: true });
    assert.equal(orphanRestart.response!.status, 201);
    assert.equal(orphanRestart.outcomes.get(aliceDevice.id), 'gone', 'the device that lost access cannot read the new group');
    const notice = await managerNotice;
    assert.equal(notice.workspaceId, orphanWorkspace.id, 'managers are told that earlier messages became unreadable');
    assert.equal(notice.channelId, orphanChannel.id);
    orphanManagerSocket.disconnect();
    assert.equal((await groupMessage(malloryMember, orphanChannel.id, orphanGroup.key(), orphanGroup.version,
      'the remaining member restarted the channel')).status, 201);

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

    // An accepted commit is usable at once: no device acknowledges anything.
    // Only the committer chose its Welcome, and the server cannot open it. A
    // device that cannot use its Welcome asks to be added again and is
    // re-added by a member, so it is never locked out for good.
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
    const dmGroup = new ChannelGroup(dm.channelId);
    const poisonedGenesis = await dmGroup.create(aliceMember, [bobMember], { welcome: poisonWelcome });
    assert.equal(poisonedGenesis.response!.status, 201);
    assert.equal(poisonedGenesis.outcomes.get(bobDevice.id), 'unreadable', 'a malformed Welcome cannot be joined');
    assert.equal((await groupMessage(aliceMember, dm.channelId, dmGroup.key(1), 1,
      'written right after the commit was accepted')).status, 201);

    // An accepted version and its key cannot be replaced: neither by a
    // per-device delivery nor by another envelope for the same version. The
    // identical envelope (a retry after a lost response) is answered again.
    const changedBobWrap = signedChannelKeyWrap({
      channelId: dm.channelId,
      version: 1,
      keyCommitment: poisonedGenesis.envelope.keyCommitment,
      rawKey: randomBytes(32),
      recipient: dmBobRecipient,
      senderKeys: aliceKeys,
    });
    assert.equal((await request(`/api/channels/${dm.channelId}/keys`, {
      method: 'POST',
      cookie: alice.cookie,
      body: { version: 1, keyCommitment: poisonedGenesis.envelope.keyCommitment, keys: [changedBobWrap] },
    })).status, 400, 'a group version takes no per-device delivery');
    const { signature: _genesisSignature, ...genesisFields } = poisonedGenesis.envelope;
    const replacedGenesis = dmGroup.sign(aliceMember, { ...genesisFields, keyCommitment: keyCommitmentOf(randomBytes(32)) });
    assert.deepEqual(await refusal(await dmGroup.send(aliceMember, replacedGenesis)), [409, 'MLS_CONFLICT']);
    const resentGenesis = await dmGroup.send(aliceMember, poisonedGenesis.envelope);
    assert.equal(resentGenesis.status, 200);
    assert.deepEqual(await json(resentGenesis), { version: 1, epoch: 1, replay: true });
    assert.deepEqual(
      await json<unknown[]>(await request(`/api/channels/${dm.channelId}/keys`, { cookie: bob.cookie })),
      [],
      'group versions leave no key material on the server',
    );

    let bobDmState = await dmGroup.state(bobMember);
    assert.deepEqual(
      [bobDmState.ownMembership, bobDmState.canCommit],
      [{ joinedVersion: 1, leafIndex: 1, rejoinRequested: false }, true],
    );
    assert.equal((await dmGroup.publish(bobMember, { rejoin: true })).status, 201);
    bobDmState = await dmGroup.state(bobMember);
    assert.deepEqual([bobDmState.ownMembership.rejoinRequested, bobDmState.canCommit], [true, false]);
    assert.deepEqual((await dmGroup.state(aliceMember)).pendingAddDeviceIds, [bobDevice.id]);
    assert.equal((await groupMessage(aliceMember, dm.channelId, dmGroup.key(1), 1)).status, 201,
      'a request to be added again does not hold up writes');
    const bobReadded = await dmGroup.commit(aliceMember, { remove: [bobMember], add: [bobMember] });
    assert.equal(bobReadded.response!.status, 201);
    assert.equal(bobReadded.outcomes.get(bobDevice.id), 'current', 'the re-added device joins from the new Welcome');
    assert.deepEqual(bobReadded.envelope.members.map((member) => [member.deviceId, member.leafIndex]),
      [[aliceDevice.id, 0], [bobDevice.id, 1]]);
    assert.equal((await groupMessage(bobMember, dm.channelId, dmGroup.key(2), 2)).status, 201);
    assert.deepEqual((await dmGroup.state(bobMember)).ownMembership, { joinedVersion: 2, leafIndex: 1, rejoinRequested: false });

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
    })).status, 409, 'legacy group proposals are refused even for a healthy group');
    const healthyDmState = await dmGroup.state(aliceMember);
    assert.equal(healthyDmState.currentVersion, 2);
    assert.equal(healthyDmState.pendingVersion, null);
    assert.equal(healthyDmState.rotationRequired, false);
    assert.deepEqual(healthyDmState.pendingAddDeviceIds, []);

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
    const legacyUnsignedDistribution = await request(`/api/channels/${channelId}/keys`, {
      method: 'POST',
      cookie: alice.cookie,
      body: {
        version: 1,
        keys: recipients.recipients.map((recipient) => ({
          deviceId: recipient.deviceId,
          encryptedKey: wrapKey(randomBytes(32), recipient.identityKey),
        })),
      },
    });
    assert.equal(legacyUnsignedDistribution.status, 400);
    // Clients from before continuous groups are told to reload instead of
    // writing per-epoch groups.
    for (const [method, path] of [
      ['POST', 'mls/packages'], ['GET', 'mls/packages'], ['POST', 'mls/epochs'], ['POST', 'mls/epochs/fresh-start'], ['POST', 'keys/start-fresh'],
    ]) {
      const response = await request(`/api/channels/${channelId}/${path}`, { method, cookie: alice.cookie, ...(method === 'POST' ? { body: {} } : {}) });
      assert.deepEqual([response.status, (await json<{ error: string }>(response)).error], [410, 'UPDATE_REQUIRED'], `${method} ${path}`);
    }
    const mainGroup = new ChannelGroup(channelId);
    const mainGenesis = await mainGroup.create(aliceMember, [bobMember]);
    assert.equal(mainGenesis.response!.status, 201);
    assert.equal(mainGenesis.outcomes.get(bobDevice.id), 'current');
    const rawChannelKey = mainGroup.key(1);

    // Keep the new-device addition isolated from the primary message
    // channel, because the secondary device is revoked later.
    const backfillChannelResponse = await request(`/api/workspaces/${workspace.id}/channels`, {
      method: 'POST', cookie: alice.cookie, body: { name: 'device-backfill' },
    });
    assert.equal(backfillChannelResponse.status, 201);
    const backfillChannel = await json<{ id: string }>(backfillChannelResponse);
    const backfillGroup = new ChannelGroup(backfillChannel.id);
    assert.equal((await backfillGroup.create(aliceMember, [bobMember])).response!.status, 201);
    assert.equal(await joinChannel(aliceSocket, backfillChannel.id), true);

    // Revocation must remain constant-work with respect to device history and
    // must fail closed at each channel's bounded group boundary.
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
    const secondaryMember = asGroupMember(secondaryCookie, alice.user.id, secondaryKeys, secondaryDevice);
    const postEnrollmentRecipients = await json<{
      recipients: Array<{ deviceId: string; identityKey: string }>;
    }>(await request(`/api/channels/${backfillChannel.id}/key-recipients`, { cookie: alice.cookie }));
    const secondaryBackfillRecipient = postEnrollmentRecipients.recipients.find(
      (recipient) => recipient.deviceId === secondaryDevice.id,
    );
    assert.ok(secondaryBackfillRecipient);
    // A new device never receives an earlier version's secret: no delivery,
    // and neither the commit log nor the roster of a version before it joined.
    const oldBackfill = await request(`/api/channels/${backfillChannel.id}/keys`, {
      method: 'POST', cookie: alice.cookie, body: { version: 1, keyCommitment: keyCommitmentOf(backfillGroup.key(1)),
        keys: [signedChannelKeyWrap({ channelId: backfillChannel.id, version: 1, keyCommitment: keyCommitmentOf(backfillGroup.key(1)), rawKey: backfillGroup.key(1), recipient: secondaryBackfillRecipient, senderKeys: aliceKeys })] },
    });
    assert.equal(oldBackfill.status, 400, 'a new device is added to the group, never sent an old secret');
    assert.deepEqual(await json(await request(`/api/channels/${backfillChannel.id}/mls/group/commits?after=0`, { cookie: secondaryCookie })), []);
    assert.equal((await request(`/api/channels/${backfillChannel.id}/mls/group/members?version=1`, { cookie: secondaryCookie })).status, 404);
    // Its package tells the members (also in other channels and workspaces
    // through their user rooms) that a device waits to be added.
    const backfillAvailable = onceSocketEventMatching<{channelId:string}>(aliceSocket, 'channel:key-rotation-required', event => event.channelId === backfillChannel.id);
    assert.equal((await backfillGroup.publish(secondaryMember)).status, 201);
    assert.equal((await backfillAvailable).channelId, backfillChannel.id);
    const secondaryAdded = await backfillGroup.commit(bobMember, { add: [secondaryMember] });
    assert.equal(secondaryAdded.response!.status, 201);
    assert.deepEqual([...secondaryAdded.outcomes.entries()].sort(), [[aliceDevice.id, 'current'], [secondaryDevice.id, 'current']].sort());
    assert.deepEqual(await json(await request(`/api/channels/${backfillChannel.id}/mls/group/commits?after=0`, { cookie: secondaryCookie })), [],
      'the log starts at the version that added the device');
    assert.deepEqual((await json<Array<{ version: number }>>(await request(`/api/channels/${backfillChannel.id}/mls/group/commits?after=1`, { cookie: secondaryCookie })))
      .map((record) => record.version), [2]);
    assert.equal((await groupMessage(secondaryMember, backfillChannel.id, backfillGroup.key(2), 2)).status, 201);

    const revocationChannelResponse = await request(`/api/workspaces/${workspace.id}/channels`, {
      method: 'POST', cookie: alice.cookie, body: { name: 'revocation-boundary' },
    });
    assert.equal(revocationChannelResponse.status, 201);
    const revocationChannel = await json<{ id: string }>(revocationChannelResponse);
    const revocationRecipients = await json<{
      recipients: Array<{ deviceId: string; identityKey: string }>;
    }>(await request(`/api/channels/${revocationChannel.id}/key-recipients`, { cookie: alice.cookie }));
    assert.equal(revocationRecipients.recipients.some((entry) => entry.deviceId === secondaryDevice.id), true);
    const revocationGroup = new ChannelGroup(revocationChannel.id);
    assert.equal((await revocationGroup.create(aliceMember, [secondaryMember, bobMember])).response!.status, 201);
    const revocationChannelKey = revocationGroup.key(1);
    // A device that only published a package is a pending addition: it
    // never stops writes, and after revocation it cannot be added at all.
    const pendingRevocationChannelResponse = await request(`/api/workspaces/${workspace.id}/channels`, {
      method: 'POST', cookie: alice.cookie, body: { name: 'pending-revocation-boundary' },
    });
    assert.equal(pendingRevocationChannelResponse.status, 201);
    const pendingRevocationChannel = await json<{ id: string }>(pendingRevocationChannelResponse);
    const pendingRevocationGroup = new ChannelGroup(pendingRevocationChannel.id);
    assert.equal((await pendingRevocationGroup.create(aliceMember, [bobMember])).response!.status, 201);
    assert.equal((await pendingRevocationGroup.publish(secondaryMember)).status, 201);
    assert.deepEqual((await pendingRevocationGroup.state(aliceMember)).pendingAddDeviceIds, [secondaryDevice.id]);
    assert.equal((await groupMessage(aliceMember, pendingRevocationChannel.id, pendingRevocationGroup.key(1), 1)).status, 201);

    // Bob's device is offline from here on: it must never hold up anyone.
    revocationGroup.offline.add(bobDevice.id);
    assert.equal((await request(`/api/devices/${secondaryDevice.id}`, {
      method: 'DELETE', cookie: alice.cookie,
    })).status, 200);
    assert.equal((await request('/api/devices', { cookie: secondaryCookie })).status, 401);
    const blockedAfterRecipientRevocation = await groupMessage(aliceMember, revocationChannel.id, revocationChannelKey, 1,
      'must not be accepted while a revoked device is in the group');
    assert.deepEqual(await refusal(blockedAfterRecipientRevocation), [400, 'KEY_ROTATION_REQUIRED']);
    const revocationState = await revocationGroup.state(aliceMember);
    assert.equal(revocationState.rotationRequired, true);
    assert.equal(revocationState.canRotate, true);
    assert.deepEqual(revocationState.requiredRemoveDeviceIds, [secondaryDevice.id]);
    assert.equal(revocationState.recipients.some((entry: { deviceId: string }) => entry.deviceId === secondaryDevice.id), false);
    // The revoked device can read neither the log nor any roster.
    const mlsGroupService = await import('../services/mls-group.service.js');
    await assert.rejects(mlsGroupService.listGroupCommits(revocationChannel.id, alice.user.id, secondaryDevice.id, 0, 16), /DEVICE_APPROVAL_REQUIRED/);
    await assert.rejects(mlsGroupService.listGroupMembers(revocationChannel.id, alice.user.id, secondaryDevice.id, 1), /DEVICE_APPROVAL_REQUIRED/);
    // Only a commit that removes it unblocks writes; adding nothing else is fine.
    const keepingRevoked = await revocationGroup.commit(aliceMember, {}, { post: false });
    assert.deepEqual(await refusal(await revocationGroup.send(aliceMember, keepingRevoked.envelope)), [409, 'MLS_CONFLICT'],
      'a commit that keeps a revoked device is refused');
    const revokedRemoved = await revocationGroup.commit(aliceMember, { remove: [secondaryMember] });
    assert.equal(revokedRemoved.response!.status, 201);
    assert.equal(revokedRemoved.outcomes.has(bobDevice.id), false, 'the offline device was not needed');
    const postRevocationKey = revocationGroup.key(2);
    assert.equal((await groupMessage(aliceMember, revocationChannel.id, postRevocationKey, 2,
      'accepted after bounded revocation recovery')).status, 201);
    assert.deepEqual(await refusal(await groupMessage(aliceMember, revocationChannel.id, revocationChannelKey, 1)), [400, 'KEY_VERSION_STALE']);
    // The offline device catches up from the log and writes with the same key.
    revocationGroup.offline.delete(bobDevice.id);
    assert.equal(await revocationGroup.sync(bobMember), 'current');
    assert.equal((await groupMessage(bobMember, revocationChannel.id, postRevocationKey, 2, 'caught up from the log')).status, 201);

    const afterPendingRevocation = await pendingRevocationGroup.state(aliceMember);
    assert.deepEqual(afterPendingRevocation.pendingAddDeviceIds, [], 'a revoked device is no longer waiting to be added');
    assert.deepEqual(afterPendingRevocation.requiredRemoveDeviceIds, []);
    assert.equal(afterPendingRevocation.rotationRequired, false);
    assert.equal((await groupMessage(aliceMember, pendingRevocationChannel.id, pendingRevocationGroup.key(1), 1)).status, 201);
    const revokedAddition = await pendingRevocationGroup.commit(aliceMember, { add: [secondaryMember] }, { post: false });
    assert.deepEqual(await refusal(await pendingRevocationGroup.send(aliceMember, revokedAddition.envelope)), [409, 'MLS_CONFLICT'],
      'a revoked device cannot be added');
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

    // Neither a delivery nor another envelope replaces an accepted version.
    const aliceRecipient = recipients.recipients.find((recipient) => recipient.deviceId === aliceDevice.id);
    assert.ok(aliceRecipient);
    const poisonEncryptedKey = wrapKey(randomBytes(32), aliceRecipient.identityKey);
    const poisonSignature = sign('sha256', Buffer.from(serializeChannelKeyWrap({
      channelId,
      keyVersion: 1,
      keyCommitment: mainGenesis.envelope.keyCommitment,
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
        keyCommitment: mainGenesis.envelope.keyCommitment,
        keys: [{ deviceId: aliceDevice.id, encryptedKey: poisonEncryptedKey, signature: poisonSignature }],
      },
    });
    assert.equal(confirmedWrapOverwrite.status, 400, 'a group version takes no per-device delivery');
    const { signature: _mainSignature, ...mainGenesisFields } = mainGenesis.envelope;
    assert.deepEqual(await refusal(await mainGroup.send(bobMember, mainGroup.sign(bobMember, {
      ...mainGenesisFields, committerDeviceId: bobDevice.id,
    }))), [409, 'MLS_CONFLICT'], 'another member cannot replace an accepted version');
    assert.equal((await mainGroup.record(aliceMember, 1)).transcript, groupTranscript(mainGenesis.envelope));

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
    const bobMessage = await json<{ id: string; idempotencyKey: string }>(bobMessageResponse);
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
        messageIdempotencyKey: bobMessage.idempotencyKey,
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
    assert.deepEqual(privateRecipients.recipients.map((recipient) => recipient.deviceId), [aliceDevice.id]);
    const privateGroup = new ChannelGroup(privateChannel.id);
    assert.equal((await privateGroup.create(aliceMember)).response!.status, 201);
    const rawPrivateChannelKey = privateGroup.key(1);
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

    // The workspace log shows activity inside a channel only to viewers who
    // can see that channel, and never shows anyone's own settings or bookmarks.
    type AuditRow = { action: string; actorId: string | null; targetId: string | null; details: Record<string, unknown> | null };
    const readWholeAuditLog = async (cookie: string) => {
      const rows: AuditRow[] = [];
      let cursor: string | null = null;
      for (let page = 0; page < 100; page += 1) {
        const body: { data: AuditRow[]; hasMore: boolean; cursor: string | null } = await json(await request(
          `/api/workspaces/${workspace.id}/audit-logs?limit=100${cursor ? `&cursor=${cursor}` : ''}`,
          { method: 'POST', cookie, body: {} },
        ));
        rows.push(...body.data);
        if (!body.hasMore) return rows;
        cursor = body.cursor;
      }
      throw new Error('audit log did not end');
    };
    const insidePrivateChannel = (row: AuditRow) => row.details?.channelId === privateChannel.id
      || (row.targetId === privateChannel.id && /^(channel\.key|channel\.member)\./.test(row.action));
    const personal = (row: AuditRow) => /^(channel\.preference|message\.bookmark)\./.test(row.action);
    const reviewerView = await readWholeAuditLog(bob.cookie);
    assert.equal(reviewerView.some((row) => row.action === 'channel.create' && row.targetId === privateChannel.id), true);
    assert.equal(reviewerView.some(insidePrivateChannel), false);
    assert.equal(reviewerView.some(personal), false);
    const ownerView = await readWholeAuditLog(alice.cookie);
    assert.equal(ownerView.some((row) => row.action === 'message.create' && row.details?.channelId === privateChannel.id), true);
    assert.equal(ownerView.some(personal), false);

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

    const messagePair = { authorId: alice.user.id, idempotencyKey: messageRequest.body.idempotencyKey };
    const bobDeleteEnvelope: SignedMessageEnvelope = {
      type: 'delete',
      channelId,
      authorId: bob.user.id,
      deviceId: bobDevice.id,
      keyVersion: 1,
      idempotencyKey: randomUUID(),
      refMessageId: message.id,
      refBinding: messagePair,
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

    const finalizeInput = {
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
        version: 1 as const,
        algorithm: 'AES-256-GCM' as const,
        nonceStrategy: 'prefix-counter-be32' as const,
        noncePrefix: noncePrefix.toString('base64'),
        aadVersion: 1 as const,
        plaintextSize: attachmentPlaintextSize,
      },
    };
    const finalizeBody = signedAttachmentFinalizeBody({
      ...finalizeInput,
      messageIdempotencyKey: messageRequest.body.idempotencyKey,
    });
    const forgedAttachmentFinalize = await request(`/api/files/uploads/${upload.uploadId}/finalize`, {
      method: 'POST', cookie: alice.cookie,
      body: { ...finalizeBody, signature: Buffer.alloc(64).toString('base64') },
    });
    assert.equal(forgedAttachmentFinalize.status, 400);
    const misboundAttachmentFinalize = await request(`/api/files/uploads/${upload.uploadId}/finalize`, {
      method: 'POST', cookie: alice.cookie,
      body: signedAttachmentFinalizeBody({ ...finalizeInput, messageIdempotencyKey: randomUUID() }),
    });
    assert.equal(misboundAttachmentFinalize.status, 400, 'a file signed for another message is refused');
    const unboundAttachmentFinalize = await request(`/api/files/uploads/${upload.uploadId}/finalize`, {
      method: 'POST', cookie: alice.cookie,
      body: signedAttachmentFinalizeBody({ ...finalizeInput, messageIdempotencyKey: null }),
    });
    assert.equal(unboundAttachmentFinalize.status, 400, 'a file in the older layout, which names its message by id only, is refused');
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
    const newerMessage = await json<{ id: string; idempotencyKey: string }>(newerMessageResponse);
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
    const [{ db: integrationDb }, schema, drizzle, S3, fileService] = await Promise.all([
      import('../db/index.js'),
      import('../db/schema.js'),
      import('drizzle-orm'),
      import('@aws-sdk/client-s3'),
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
    // An independent client confirms the object is gone from the store itself.
    const storageClient = new S3.S3Client({
      endpoint: `${process.env.S3_USE_SSL === 'true' ? 'https' : 'http'}://${process.env.S3_ENDPOINT || 'localhost'}:${Number(process.env.S3_PORT || 9000)}`,
      region: process.env.S3_REGION || 'us-east-1',
      forcePathStyle: true,
      credentials: { accessKeyId: process.env.S3_ACCESS_KEY!, secretAccessKey: process.env.S3_SECRET_KEY! },
    });
    await assert.rejects(
      storageClient.send(new S3.HeadObjectCommand({ Bucket: process.env.S3_BUCKET || 'alparts', Key: orphanChunkRow.storageKey })),
      (error: any) => error?.name === 'NotFound' || error?.$metadata?.httpStatusCode === 404,
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

    // An edit names its message only in v5: the older layout is refused.
    const olderEdit = encryptedCryptoEvent(
      'edit', channelId, message.id, alice.user.id, aliceDevice.id, aliceKeys.signingPrivateKey, rawChannelKey, 'edited plaintext',
    );
    const olderEditResponse = await request(`/api/messages/${message.id}`, {
      method: 'PUT', cookie: alice.cookie, body: olderEdit.body,
    });
    assert.deepEqual([olderEditResponse.status, (await json<{ error: string }>(olderEditResponse)).error], [400, 'INVALID_MESSAGE']);
    const editRequest = encryptedEdit(
      channelId,
      message.id,
      messagePair,
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
      refBinding: messagePair,
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
        messageIdempotencyKey: messageRequest.body.idempotencyKey,
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
      refBinding: { authorId: alice.user.id, idempotencyKey: unreadDeletedRequest.body.idempotencyKey },
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

    // Bob's device joins the channel's group but he deliberately creates no
    // message, read position, preference, or bookmark in this channel. The
    // group membership is the only durable evidence that he knows it.
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
    const keyOnlyGroup = new ChannelGroup(keyOnlyChannel.id);
    const keyOnlyGenesis = await keyOnlyGroup.create(aliceMember, [bobMember]);
    assert.equal(keyOnlyGenesis.response!.status, 201);
    assert.equal(keyOnlyGenesis.outcomes.get(bobDevice.id), 'current');

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

    // Bob's device is still in the channel's group but he no longer sees the
    // channel: writes stop until a commit removes the device, which can no
    // longer read the log.
    assert.deepEqual((await mainGroup.state(aliceMember)).requiredRemoveDeviceIds, [bobDevice.id]);
    assert.deepEqual(await refusal(await groupMessage(aliceMember, channelId, rawChannelKey, 1)), [400, 'KEY_ROTATION_REQUIRED']);
    assert.equal((await request(`/api/channels/${channelId}/mls/group/commits?after=0`, { cookie: bob.cookie })).status, 404);
    const bobLeftMain = await mainGroup.commit(aliceMember, { remove: [bobMember] });
    assert.equal(bobLeftMain.response!.status, 201);
    assert.equal(bobLeftMain.outcomes.get(bobDevice.id), 'gone');
    const removalWrite = await groupMessage(aliceMember, channelId, mainGroup.key(2), 2, 'written while bob is out');
    assert.equal(removalWrite.status, 201);
    const removalMessage = await json<{ id: string; idempotencyKey: string }>(removalWrite);
    // A file keeps the version of its message only while nobody left the group since.
    const finalizeAttachment = async (fileMessage: { id: string; idempotencyKey: string }, keyVersion: number) => {
      const messageId = fileMessage.id;
      const reservation = {
        idempotencyKey: randomUUID(),
        messageId,
        filenameEnc: Buffer.alloc(32, 0x5a).toString('base64'),
        mimeType: 'application/octet-stream',
      };
      const reserved = await request('/api/files/uploads', { method: 'POST', cookie: alice.cookie, body: reservation });
      assert.equal(reserved.status, 201);
      const { uploadId } = await json<{ uploadId: string }>(reserved);
      assert.equal((await request(`/api/files/uploads/${uploadId}/chunks/0`, {
        method: 'PUT', cookie: alice.cookie, body: Buffer.alloc(16, 0x35),
      })).status, 201);
      return request(`/api/files/uploads/${uploadId}/finalize`, {
        method: 'POST', cookie: alice.cookie,
        body: signedAttachmentFinalizeBody({
          uploadId,
          messageId,
          messageIdempotencyKey: fileMessage.idempotencyKey,
          channelId,
          authorId: alice.user.id,
          deviceId: aliceDevice.id,
          privateKey: aliceKeys.signingPrivateKey,
          filenameEnc: reservation.filenameEnc,
          mimeType: reservation.mimeType,
          keyVersion,
          chunkCount: 1,
          wrappedKey: wrapKey(randomBytes(32), aliceKeys.identityKey),
          cryptoManifest: {
            version: 1,
            algorithm: 'AES-256-GCM',
            nonceStrategy: 'prefix-counter-be32',
            noncePrefix: Buffer.alloc(8, 0x46).toString('base64'),
            aadVersion: 1,
            plaintextSize: 0,
          },
        }),
      });
    };
    assert.deepEqual(await refusal(await finalizeAttachment(newerMessage, 1)), [400, 'KEY_ROTATION_REQUIRED']);

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

    // Bob sees the channel again: his device publishes a package and a member
    // adds it. It joins at the new version and never gets the roster or key
    // of the version written while it was out.
    assert.equal(await mainGroup.sync(bobMember), 'waiting');
    assert.equal((await mainGroup.publish(bobMember)).status, 201);
    const bobBackInMain = await mainGroup.commit(aliceMember, { add: [bobMember] });
    assert.equal(bobBackInMain.response!.status, 201);
    assert.equal(bobBackInMain.outcomes.get(bobDevice.id), 'current');
    assert.equal(bobBackInMain.envelope.welcome === '', false);
    assert.deepEqual((await json<Array<{ version: number }>>(await request(`/api/channels/${channelId}/mls/group/commits?after=0`, { cookie: bob.cookie })))
      .map((record) => record.version), [1, 2, 3], 'the versions it was in, and the one that removed it');
    assert.equal((await request(`/api/channels/${channelId}/mls/group/members?version=2`, { cookie: bob.cookie })).status, 404);
    // An addition removes nobody, so the file of a version-2 message still finalizes.
    assert.equal((await finalizeAttachment(removalMessage, 2)).status, 201);
    const rotatedChannelKey = mainGroup.key(3);

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
        undefined,
        3,
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
      'membership in the channel\'s group is sufficient proof that the removed member knew the channel',
    );
    const recipientsAfterRemovalResponse = await request(`/api/channels/${channelId}/key-recipients`, { cookie: alice.cookie });
    assert.equal(recipientsAfterRemovalResponse.status, 200);
    const recipientsAfterRemoval = await json<{
      recipients: Array<{ deviceId: string; identityKey: string }>;
    }>(recipientsAfterRemovalResponse);
    assert.equal(recipientsAfterRemoval.recipients.some((recipient) => recipient.deviceId === bobDevice.id), false);
    assert.equal(recipientsAfterRemoval.recipients.some((recipient) => recipient.deviceId === attachmentOnlyDevice.id), false);
    // The device of the member who left is removed by the next commit.
    assert.deepEqual((await mainGroup.state(aliceMember)).requiredRemoveDeviceIds, [bobDevice.id]);
    const bobRemovedFromMain = await mainGroup.commit(aliceMember, { remove: [bobMember] });
    assert.equal(bobRemovedFromMain.response!.status, 201);
    assert.equal((await groupMessage(aliceMember, channelId, mainGroup.key(4), 4)).status, 201);
    assert.equal((await request(`/api/devices/${bobDevice.id}`, {
      method: 'DELETE', cookie: bob.cookie,
    })).status, 200);
    const afterFormerMemberRevoke = await json<{ rotationRequired: boolean }>(
      await request(`/api/channels/${channelId}/key-recipients`, { cookie: alice.cookie }),
    );
    assert.equal(
      afterFormerMemberRevoke.rotationRequired,
      false,
      'revoking a device that already left the group requires no commit',
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
    // Group versions are read from the commit log in bounded pages; the
    // per-device delivery list (kept for earlier history) has nothing for them.
    const firstPage = await json<Array<{ version: number }>>(
      await request(`/api/channels/${channelId}/mls/group/commits?after=0&limit=2`, { cookie: alice.cookie }),
    );
    assert.deepEqual(firstPage.map((record) => record.version), [1, 2]);
    const secondPage = await json<Array<{ version: number }>>(
      await request(`/api/channels/${channelId}/mls/group/commits?after=2&limit=16`, { cookie: alice.cookie }),
    );
    assert.deepEqual(secondPage.map((record) => record.version), [3, 4]);
    assert.equal((await request(`/api/channels/${channelId}/mls/group/commits?after=0&limit=17`, { cookie: alice.cookie })).status, 400);
    assert.equal((await request(`/api/channels/${channelId}/mls/group/commits?after=not-a-version`, { cookie: alice.cookie })).status, 400);
    assert.equal(await mainGroup.sync(aliceMember), 'current');
    const legacyKeyResponse = await request(`/api/channels/${channelId}/keys`, { cookie: alice.cookie });
    assert.equal(legacyKeyResponse.headers.get('deprecation'), 'true');
    assert.deepEqual(await json(legacyKeyResponse), []);
    assert.deepEqual(await json(await request(`/api/channels/${channelId}/keys?versions=1,2`, { cookie: alice.cookie })), []);
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

    // A flood of anonymous login challenges cannot use up identity
    // confirmation for a signed-in user (for example to revoke a stolen session).
    {
      const { authenticationChallenges } = await import('../db/schema.js');
      const { MAX_ANONYMOUS_CHALLENGES } = await import('../services/passkey.service.js');
      const floodIds = Array.from({ length: MAX_ANONYMOUS_CHALLENGES }, () => randomUUID());
      await db.insert(authenticationChallenges).values(floodIds.map((id) => ({
        id, purpose: 'login', challenge: 'flood', expiresAt: new Date(Date.now() + 60_000),
      })));
      try {
        assert.equal((await request('/api/auth/passkeys/login/options', { method: 'POST', body: {} })).status, 403);
        const purpose = `DELETE /api/devices/${ownerDevice.id} ${'A'.repeat(43)}`;
        assert.equal((await request('/api/auth/step-up/options', {
          method: 'POST', cookie: owner.cookie, body: { purpose },
        })).status, 200);
      } finally {
        await db.delete(authenticationChallenges).where(inArray(authenticationChallenges.id, floodIds));
      }
    }
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
    assert.deepEqual(recipients.recipients.map((recipient) => recipient.deviceId).sort(), [ownerDevice.id, memberDevice.id].sort());
    const forumGroup = new ChannelGroup(forum.id);
    const forumGenesis = await forumGroup.create(
      asGroupMember(owner.cookie, owner.user.id, ownerKeys, ownerDevice),
      [asGroupMember(member.cookie, member.user.id, memberKeys, memberDevice)],
    );
    assert.equal(forumGenesis.response!.status, 201);
    assert.equal(forumGenesis.outcomes.get(memberDevice.id), 'current');
    const forumKey = forumGroup.key(1);
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
    // Routes without a budget of their own are still under the global request
    // limiter (CodeQL cannot see this custom middleware).
    assert.equal(postResponse.headers.get('ratelimit-limit'), '300');
    const created = await json<{ message: { id: string; postId: string | null; createdAt: string }; state: { tagIds: string[]; replyCount: number } }>(postResponse);
    const postId = created.message.id;
    const postPair = { authorId: member.user.id, idempotencyKey: post.body.idempotencyKey };
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
    const secondPostPair = { authorId: owner.user.id, idempotencyKey: secondPost.body.idempotencyKey };
    const relocated = asOwner({ type: 'message', refMessageId: null, postId: secondPostId, postBinding: secondPostPair, plaintext: 'moved' });
    assert.equal((await request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie: owner.cookie, body: { ...relocated.body, postId },
    })).status, 400);
    const crossQuote = asOwner({
      type: 'message', refMessageId: secondPostId, refBinding: secondPostPair, postId, postBinding: postPair, plaintext: 'cross',
    });
    assert.equal((await request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie: owner.cookie, body: { ...crossQuote.body, refMessageId: secondPostId },
    })).status, 400);
    // Inside a post only v5 counts: a reply in the older layout is refused.
    const olderReply = encryptedForumEvent({
      type: 'message', channelId: forum.id, refMessageId: null, postId: null, authorId: owner.user.id, deviceId: ownerDevice.id,
      privateKey: ownerKeys.signingPrivateKey, key: forumKey, plaintext: 'An answer',
    });
    const olderReplyEnvelope: SignedMessageEnvelope = { ...olderReply.envelope, postId };
    const olderReplyResponse = await request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie: owner.cookie,
      body: { ...olderReply.body, postId, signature: signEnvelope(olderReplyEnvelope, ownerKeys.signingPrivateKey) },
    });
    assert.deepEqual([olderReplyResponse.status, (await json<{ error: string }>(olderReplyResponse)).error], [400, 'INVALID_MESSAGE']);
    const reply = asOwner({ type: 'message', refMessageId: null, postId, postBinding: postPair, plaintext: 'An answer' });
    const replyResponse = await request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie: owner.cookie, body: reply.body,
    });
    assert.equal(replyResponse.status, 201);
    const replyEvent = await json<{ id: string; postId: string; createdAt: string }>(replyResponse);
    const replyPair = { authorId: owner.user.id, idempotencyKey: reply.body.idempotencyKey };
    assert.equal(replyEvent.postId, postId);
    // Only the post itself can be pinned in a forum.
    assert.equal((await request(`/api/messages/${replyEvent.id}/pin`, { method: 'POST', cookie: owner.cookie })).status, 403);
    // A requested pin state is set, not toggled, so repeating a request whose
    // response was lost changes nothing; the response carries the list state.
    for (const pinned of [true, true, false, false]) {
      const pinResponse = await request(`/api/messages/${postId}/pin`, { method: 'POST', cookie: owner.cookie, body: { pinned } });
      assert.equal(pinResponse.status, 200);
      const pinResult = await json<{ pinned: boolean; forumPost?: { postId: string; isPinned: boolean } }>(pinResponse);
      assert.equal(pinResult.pinned, pinned);
      assert.deepEqual([pinResult.forumPost?.postId, pinResult.forumPost?.isPinned], [postId, pinned]);
    }
    assert.equal((await request(`/api/messages/${postId}/pin`, { method: 'POST', cookie: owner.cookie, body: { pinned: 'yes' } })).status, 400);

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
    // A read mark covers only the activity the viewer was shown: a reply that
    // arrived after the post was displayed stays unread.
    const shownBeforeReply = await request(`/api/forum/posts/${postId}/read`, {
      method: 'POST', cookie: member.cookie, body: { shownActivityAt: created.message.createdAt },
    });
    assert.equal(shownBeforeReply.status, 200);
    assert.equal((await json<{ lastReadActivityAt: string }>(shownBeforeReply)).lastReadActivityAt, created.message.createdAt);
    assert.equal((await json<{ state: { unread: boolean } }>(await request(`/api/forum/posts/${postId}`, { cookie: member.cookie }))).state.unread, true);
    // A time past the post's activity is never recorded.
    const shownFuture = await request(`/api/forum/posts/${postId}/read`, {
      method: 'POST', cookie: member.cookie, body: { shownActivityAt: '2999-01-01T00:00:00.000Z' },
    });
    assert.equal((await json<{ lastReadActivityAt: string }>(shownFuture)).lastReadActivityAt, replyEvent.createdAt);
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
    const lockedReply = asMember({
      type: 'message', refMessageId: replyEvent.id, refBinding: replyPair, postId, postBinding: postPair, plaintext: 'after lock',
    });
    const lockedResponse = await request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie: member.cookie, body: { ...lockedReply.body, refMessageId: replyEvent.id },
    });
    assert.equal(lockedResponse.status, 409);
    const moderatorReply = asOwner({ type: 'message', refMessageId: null, postId, postBinding: postPair, plaintext: 'locked by moderator' });
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
    const deniedViewer = await json<{ viewer: { canCreatePosts: boolean; canReply: boolean; canManage: boolean } }>(
      await request(`/api/channels/${forum.id}/forum/posts`, { cookie: member.cookie }),
    );
    assert.deepEqual(
      [deniedViewer.viewer.canCreatePosts, deniedViewer.viewer.canReply, deniedViewer.viewer.canManage],
      [false, true, false],
    );
    const deniedPost = asMember({ type: 'message', refMessageId: null, postId: null, plaintext: 'denied\npost' });
    assert.equal((await request(`/api/channels/${forum.id}/forum/posts`, {
      method: 'POST', cookie: member.cookie, body: deniedPost.body,
    })).status, 403);
    const allowedReply = asMember({
      type: 'message', refMessageId: null, postId: secondPostId, postBinding: secondPostPair, plaintext: 'still replying',
    });
    assert.equal((await request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie: member.cookie, body: allowedReply.body,
    })).status, 201);

    // Posts are invisible outside the workspace.
    assert.equal((await request(`/api/forum/posts/${postId}`, { cookie: outsider.cookie })).status, 404);
    assert.equal((await request(`/api/forum/posts/${postId}/messages`, { cookie: outsider.cookie })).status, 404);
    assert.equal((await request(`/api/forum/posts/${postId}/lock`, {
      method: 'PUT', cookie: outsider.cookie, body: { locked: false },
    })).status, 404);

    // A quote-reply racing the deletion of the quoted reply must resolve to
    // one order or the other, never a lock cycle.
    for (let round = 0; round < 5; round += 1) {
      const target = asOwner({ type: 'message', refMessageId: null, postId, postBinding: postPair, plaintext: `race target ${round}` });
      const targetEvent = await json<{ id: string }>(await request(`/api/channels/${forum.id}/messages`, {
        method: 'POST', cookie: owner.cookie, body: target.body,
      }));
      const targetPair = { authorId: owner.user.id, idempotencyKey: target.body.idempotencyKey };
      const quote = asOwner({
        type: 'message', refMessageId: targetEvent.id, refBinding: targetPair, postId, postBinding: postPair, plaintext: `race quote ${round}`,
      });
      const removal = asOwner({
        type: 'delete', refMessageId: targetEvent.id, refBinding: targetPair, postId, postBinding: postPair, plaintext: '',
      });
      const [quoted, removed] = await Promise.all([
        request(`/api/channels/${forum.id}/messages`, {
          method: 'POST', cookie: owner.cookie, body: { ...quote.body, refMessageId: targetEvent.id },
        }),
        request(`/api/messages/${targetEvent.id}`, {
          method: 'DELETE', cookie: owner.cookie,
          body: { deviceId: ownerDevice.id, keyVersion: 1, idempotencyKey: removal.envelope.idempotencyKey, signature: removal.body.signature, postId },
        }),
      ]);
      assert.ok([201, 400].includes(quoted.status), `quote status ${quoted.status}`);
      assert.equal(removed.status, 200);
    }

    // Deleting the post removes it from the list and closes it for replies.
    const deletion = asMember({ type: 'delete', refMessageId: postId, refBinding: postPair, postId, postBinding: postPair, plaintext: '' });
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
    const lateReply = asOwner({ type: 'message', refMessageId: null, postId, postBinding: postPair, plaintext: 'too late' });
    assert.equal((await request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie: owner.cookie, body: lateReply.body,
    })).status, 400);
    const stored = await db.query.forumPosts.findFirst({ where: eq(forumPostTable.messageId, postId) });
    assert.ok(stored?.deletedAt);
    // A reply deleted after its post sends no post state: one would put the
    // deleted post back into every client's list (formal model M7 FV1).
    const lateRemoval = asOwner({
      type: 'delete', refMessageId: replyEvent.id, refBinding: replyPair, postId, postBinding: postPair, plaintext: '',
    });
    const removedReply = await messageService.deleteMessage(replyEvent.id, owner.user.id, {
      deviceId: ownerDevice.id, keyVersion: 1, idempotencyKey: lateRemoval.envelope.idempotencyKey,
      signature: lateRemoval.body.signature, postId, encryptedContent: '', contentNonce: '', broadcastMention: false,
    });
    assert.equal(removedReply.isNewEvent, true);
    assert.equal(removedReply.forumPost, null);
    // A deleted post is not found for members and managers alike.
    for (const cookie of [member.cookie, owner.cookie]) {
      assert.equal((await request(`/api/forum/posts/${postId}/lock`, {
        method: 'PUT', cookie, body: { locked: false },
      })).status, 404);
    }

    // A privacy change that commits while a forum request waits for the
    // workspace lock is the state that request must be judged against. The
    // holder makes the change the way updateChannel does (workspace row FOR
    // UPDATE, then the channel and its private members) and commits only once
    // the request is observed waiting, so the race is exercised every time.
    const lockHolder = new pg.Client({ connectionString: process.env.DATABASE_URL });
    const observer = new pg.Client({ connectionString: process.env.DATABASE_URL });
    await lockHolder.connect();
    await observer.connect();
    try {
      const raceAgainstPrivacyChange = async (send: () => Promise<Response>) => {
        await lockHolder.query('begin');
        try {
          await lockHolder.query('select id from workspaces where id = $1 for update', [workspace.id]);
          await lockHolder.query('update channels set is_private = true where id = $1', [forum.id]);
          await lockHolder.query('insert into channel_members (channel_id, user_id) values ($1, $2)', [forum.id, owner.user.id]);
          const pending = send();
          let waiting = false;
          for (let attempt = 0; attempt < 100 && !waiting; attempt += 1) {
            const { rows } = await observer.query<{ waiting: number }>(`
              select count(*)::int as waiting from pg_stat_activity
              where datname = current_database() and wait_event_type = 'Lock' and pid <> $1
            `, [(lockHolder as unknown as { processID: number }).processID]);
            waiting = rows[0]!.waiting > 0;
            if (!waiting) await delay(20);
          }
          assert.equal(waiting, true, 'the forum request never waited for the workspace lock');
          await lockHolder.query('commit');
          return await pending;
        } catch (error) {
          await lockHolder.query('rollback').catch(() => undefined);
          throw error;
        }
      };
      const restorePublicForum = async () => {
        await lockHolder.query('update channels set is_private = false where id = $1', [forum.id]);
        await lockHolder.query('delete from channel_members where channel_id = $1', [forum.id]);
      };

      const listed = await raceAgainstPrivacyChange(() => request(`/api/channels/${forum.id}/forum/posts`, { cookie: member.cookie }));
      assert.equal(listed.status, 404);
      assert.equal((await request(`/api/channels/${forum.id}/forum/posts`, { cookie: owner.cookie })).status, 200);
      await restorePublicForum();
      assert.equal((await request(`/api/forum/posts/${secondPostId}`, { cookie: member.cookie })).status, 200);

      const opened = await raceAgainstPrivacyChange(() => request(`/api/forum/posts/${secondPostId}`, { cookie: member.cookie }));
      assert.equal(opened.status, 404);
      await restorePublicForum();
    } finally {
      await lockHolder.end();
      await observer.end();
    }

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

  it('binds edits, deletions, quotes and replies to the messages their authors signed (formal model M9)', async () => {
    const messageService = await import('../services/message.service.js');
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
    const ownerDevice = await registerDevice(owner, ownerKeys, 'Reference owner device');
    const workspace = await json<{ id: string }>(await request('/api/workspaces', {
      method: 'POST', cookie: owner.cookie, body: { name: 'Signed references' },
    }));
    const invitation = await createWorkspaceInvitation(workspace.id, owner.cookie, 'reference-member@example.test');
    const member = await createAccount('reference-member@example.test', 'Correct-Horse-Battery-33!', 'Reference Member', invitation.token);
    const memberKeys = deviceFixture();
    const memberDevice = await registerDevice(member, memberKeys, 'Reference member device');
    const groupMembers = () => [
      asGroupMember(owner.cookie, owner.user.id, ownerKeys, ownerDevice),
      asGroupMember(member.cookie, member.user.id, memberKeys, memberDevice),
    ] as const;
    const signedBy = (account: { user: { id: string } }, sent: { envelope: SignedMessageEnvelope }): SignedEventReference => ({
      authorId: account.user.id, idempotencyKey: sent.envelope.idempotencyKey,
    });

    // A text channel.
    const general = (await json<Array<{ id: string; type: string }>>(
      await request(`/api/workspaces/${workspace.id}/channels`, { cookie: owner.cookie }),
    )).find((channel) => channel.type === 'text');
    assert.ok(general);
    const textGroup = new ChannelGroup(general.id);
    const [textCreator, textMember] = groupMembers();
    assert.equal((await textGroup.create(textCreator, [textMember])).response!.status, 201);
    const textKey = textGroup.key(1);
    const ownerEvent = (input: Omit<Parameters<typeof encryptedBoundEvent>[0], 'channelId' | 'authorId' | 'deviceId' | 'privateKey' | 'key'>) => (
      encryptedBoundEvent({ ...input, channelId: general.id, authorId: owner.user.id, deviceId: ownerDevice.id, privateKey: ownerKeys.signingPrivateKey, key: textKey })
    );
    const memberEvent = (input: Omit<Parameters<typeof encryptedBoundEvent>[0], 'channelId' | 'authorId' | 'deviceId' | 'privateKey' | 'key'>) => (
      encryptedBoundEvent({ ...input, channelId: general.id, authorId: member.user.id, deviceId: memberDevice.id, privateKey: memberKeys.signingPrivateKey, key: textKey })
    );
    const send = async (cookie: string, body: Record<string, unknown>) => request(`/api/channels/${general.id}/messages`, {
      method: 'POST', cookie, body,
    });

    // Two messages by the same author: one v5, one from an older client.
    const first = ownerEvent({ type: 'message', refMessageId: null, refBinding: null, plaintext: 'first' });
    const firstResponse = await send(owner.cookie, first.body);
    assert.equal(firstResponse.status, 201, await firstResponse.clone().text());
    const firstEvent = await json<{ id: string; refBinding: SignedEventReference | null }>(firstResponse);
    assert.equal(firstEvent.refBinding, null);
    const second = encryptedMessage(general.id, owner.user.id, ownerDevice.id, ownerKeys.signingPrivateKey, textKey, 'second');
    const secondResponse = await send(owner.cookie, second.body);
    assert.equal(secondResponse.status, 201);
    const secondId = (await json<{ id: string }>(secondResponse)).id;
    const firstSigned = signedBy(owner, first);
    const secondSigned = signedBy(owner, second);

    // An edit signed for the second message is refused under the first one's
    // id; signed for the first, it is accepted and served with what it names.
    const misplacedEdit = ownerEvent({ type: 'edit', refMessageId: firstEvent.id, refBinding: secondSigned, plaintext: 'misplaced' });
    assert.equal((await request(`/api/messages/${firstEvent.id}`, {
      method: 'PUT', cookie: owner.cookie, body: misplacedEdit.body,
    })).status, 400);
    await assert.rejects(messageService.editMessage(firstEvent.id, owner.user.id, misplacedEdit.body), /INVALID_SIGNATURE/);
    const edit = ownerEvent({ type: 'edit', refMessageId: firstEvent.id, refBinding: firstSigned, plaintext: 'first, edited' });
    const editResponse = await request(`/api/messages/${firstEvent.id}`, {
      method: 'PUT', cookie: owner.cookie, body: edit.body,
    });
    assert.equal(editResponse.status, 200, await editResponse.clone().text());
    const editEvent = await json<{ id: string; refBinding: SignedEventReference | null }>(editResponse);
    assert.deepEqual(editEvent.refBinding, firstSigned);

    // A quote names the quoted message the same way.
    const misplacedQuote = memberEvent({ type: 'message', refMessageId: firstEvent.id, refBinding: secondSigned, plaintext: 'quote' });
    assert.equal((await send(member.cookie, misplacedQuote.body)).status, 400);
    const quote = memberEvent({ type: 'message', refMessageId: firstEvent.id, refBinding: firstSigned, plaintext: 'quote' });
    const quoteResponse = await send(member.cookie, quote.body);
    assert.equal(quoteResponse.status, 201, await quoteResponse.clone().text());
    const quoteEvent = await json<{ id: string; refBinding: SignedEventReference | null }>(quoteResponse);
    assert.deepEqual(quoteEvent.refBinding, firstSigned);

    // The older layouts name the target by server id only: an edit, a quote
    // or a deletion signed in them is refused, also for the right message.
    const olderEdit = encryptedCryptoEvent(
      'edit', general.id, secondId, owner.user.id, ownerDevice.id, ownerKeys.signingPrivateKey, textKey, 'second, edited',
    );
    const olderEditResponse = await request(`/api/messages/${secondId}`, { method: 'PUT', cookie: owner.cookie, body: olderEdit.body });
    assert.deepEqual([olderEditResponse.status, (await json<{ error: string }>(olderEditResponse)).error], [400, 'INVALID_MESSAGE']);
    const olderQuote = encryptedCryptoEvent(
      'message', general.id, firstEvent.id, member.user.id, memberDevice.id, memberKeys.signingPrivateKey, textKey, 'quote',
    );
    const olderQuoteResponse = await send(member.cookie, { ...olderQuote.body, refMessageId: firstEvent.id });
    assert.deepEqual([olderQuoteResponse.status, (await json<{ error: string }>(olderQuoteResponse)).error], [400, 'INVALID_MESSAGE']);
    const olderDelete: SignedMessageEnvelope = {
      type: 'delete', channelId: general.id, authorId: owner.user.id, deviceId: ownerDevice.id, keyVersion: 1,
      idempotencyKey: randomUUID(), refMessageId: secondId, encryptedContent: '', contentNonce: '', broadcastMention: false,
    };
    const olderDeleteResponse = await request(`/api/messages/${secondId}`, {
      method: 'DELETE', cookie: owner.cookie,
      body: { deviceId: ownerDevice.id, keyVersion: 1, idempotencyKey: olderDelete.idempotencyKey, signature: signEnvelope(olderDelete, ownerKeys.signingPrivateKey) },
    });
    assert.deepEqual([olderDeleteResponse.status, (await json<{ error: string }>(olderDeleteResponse)).error], [400, 'INVALID_MESSAGE']);

    // A deletion is bound like an edit.
    const misplacedDelete = ownerEvent({ type: 'delete', refMessageId: secondId, refBinding: firstSigned, plaintext: '' });
    const deleteBody = (sent: ReturnType<typeof ownerEvent>) => ({
      deviceId: sent.body.deviceId, keyVersion: 1, idempotencyKey: sent.body.idempotencyKey, signature: sent.body.signature,
    });
    assert.equal((await request(`/api/messages/${secondId}`, {
      method: 'DELETE', cookie: owner.cookie, body: deleteBody(misplacedDelete),
    })).status, 400);
    const removal = ownerEvent({ type: 'delete', refMessageId: secondId, refBinding: secondSigned, plaintext: '' });
    const removalResponse = await request(`/api/messages/${secondId}`, {
      method: 'DELETE', cookie: owner.cookie, body: deleteBody(removal),
    });
    assert.equal(removalResponse.status, 200, await removalResponse.clone().text());

    // Every reader gets each event with what its references name.
    const history = await json<{ data: Array<{ id: string; type: string; refMessageId: string | null; refBinding: SignedEventReference | null }> }>(
      await request(`/api/channels/${general.id}/messages`, { cookie: member.cookie }),
    );
    const served = new Map(history.data.map((event) => [event.id, event]));
    assert.equal(served.get(firstEvent.id)?.refBinding, null);
    assert.deepEqual(served.get(editEvent.id)?.refBinding, firstSigned);
    assert.deepEqual(served.get(quoteEvent.id)?.refBinding, firstSigned);
    assert.deepEqual(
      history.data.filter((event) => event.type === 'delete' && event.refMessageId === secondId).map((event) => event.refBinding),
      [secondSigned],
    );

    // A forum: a v5 reply names the post's first message.
    const forumResponse = await request(`/api/workspaces/${workspace.id}/channels`, {
      method: 'POST', cookie: owner.cookie, body: { name: 'signed-posts', type: 'forum' },
    });
    assert.equal(forumResponse.status, 201);
    const forum = await json<{ id: string }>(forumResponse);
    const forumGroup = new ChannelGroup(forum.id);
    const [forumCreator, forumMember] = groupMembers();
    assert.equal((await forumGroup.create(forumCreator, [forumMember])).response!.status, 201);
    const forumKey = forumGroup.key(1);
    const inForum = (account: typeof owner, keys: ReturnType<typeof deviceFixture>, device: { id: string }) => (
      input: Omit<Parameters<typeof encryptedBoundEvent>[0], 'channelId' | 'authorId' | 'deviceId' | 'privateKey' | 'key'>,
    ) => encryptedBoundEvent({ ...input, channelId: forum.id, authorId: account.user.id, deviceId: device.id, privateKey: keys.signingPrivateKey, key: forumKey });
    const ownerForumEvent = inForum(owner, ownerKeys, ownerDevice);
    const memberForumEvent = inForum(member, memberKeys, memberDevice);
    const startPost = async (cookie: string, sent: ReturnType<typeof ownerForumEvent>) => {
      const response = await request(`/api/channels/${forum.id}/forum/posts`, { method: 'POST', cookie, body: sent.body });
      assert.equal(response.status, 201, await response.clone().text());
      return (await json<{ message: { id: string } }>(response)).message.id;
    };
    const memberPost = memberForumEvent({ type: 'message', refMessageId: null, refBinding: null, post: { postId: null, postBinding: null }, plaintext: 'Question\nbody' });
    const memberPostId = await startPost(member.cookie, memberPost);
    const otherPost = memberForumEvent({ type: 'message', refMessageId: null, refBinding: null, post: { postId: null, postBinding: null }, plaintext: 'Other\nbody' });
    const otherPostId = await startPost(member.cookie, otherPost);
    const memberPostSigned = signedBy(member, memberPost);
    const otherPostSigned = signedBy(member, otherPost);
    const sendInForum = async (cookie: string, body: Record<string, unknown>) => request(`/api/channels/${forum.id}/messages`, {
      method: 'POST', cookie, body,
    });
    const misplacedReply = ownerForumEvent({
      type: 'message', refMessageId: null, refBinding: null, post: { postId: memberPostId, postBinding: otherPostSigned }, plaintext: 'answer',
    });
    assert.equal((await sendInForum(owner.cookie, misplacedReply.body)).status, 400);
    const reply = ownerForumEvent({
      type: 'message', refMessageId: null, refBinding: null, post: { postId: memberPostId, postBinding: memberPostSigned }, plaintext: 'answer',
    });
    const replyResponse = await sendInForum(owner.cookie, reply.body);
    assert.equal(replyResponse.status, 201, await replyResponse.clone().text());
    const replyEvent = await json<{ id: string; postBinding: SignedEventReference | null }>(replyResponse);
    assert.deepEqual(replyEvent.postBinding, memberPostSigned);
    const thread = await json<{ data: Array<{ id: string; postBinding: SignedEventReference | null }> }>(
      await request(`/api/forum/posts/${memberPostId}/messages`, { cookie: member.cookie }),
    );
    assert.deepEqual(thread.data.map((event) => [event.id, event.postBinding]), [[replyEvent.id, memberPostSigned]]);

    // Editing the post names it twice: as the edited message and as the post.
    const postEdit = memberForumEvent({
      type: 'edit', refMessageId: memberPostId, refBinding: memberPostSigned,
      post: { postId: memberPostId, postBinding: memberPostSigned }, plaintext: 'Question\nedited',
    });
    const postEditResponse = await request(`/api/messages/${memberPostId}`, { method: 'PUT', cookie: member.cookie, body: postEdit.body });
    assert.equal(postEditResponse.status, 200, await postEditResponse.clone().text());
    const listed = await json<{ data: Array<{ state: { postId: string }; latestEdit: { refBinding: SignedEventReference | null; postBinding: SignedEventReference | null } | null }> }>(
      await request(`/api/channels/${forum.id}/forum/posts`, { cookie: owner.cookie }),
    );
    const listedEdit = listed.data.find((entry) => entry.state.postId === memberPostId)?.latestEdit;
    assert.deepEqual([listedEdit?.refBinding, listedEdit?.postBinding], [memberPostSigned, memberPostSigned]);
    const misplacedPostEdit = memberForumEvent({
      type: 'edit', refMessageId: memberPostId, refBinding: memberPostSigned,
      post: { postId: memberPostId, postBinding: otherPostSigned }, plaintext: 'Question\nmisplaced',
    });
    assert.equal((await request(`/api/messages/${memberPostId}`, {
      method: 'PUT', cookie: member.cookie, body: misplacedPostEdit.body,
    })).status, 400);
    // Signed for the other post, the same kind of reply belongs there.
    const otherReply = ownerForumEvent({
      type: 'message', refMessageId: null, refBinding: null, post: { postId: otherPostId, postBinding: otherPostSigned }, plaintext: 'answer',
    });
    assert.equal((await sendInForum(owner.cookie, otherReply.body)).status, 201);
  });

  describe('continuous channel groups', () => {
    type Account = { cookie: string; user: { id: string }; password: string };
    interface GroupPackage { id: string; pub: KeyPackage; priv: PrivateKeyPackage; encoded: string; signature: string }
    interface GroupDevice {
      id: string;
      userId: string;
      identityKey: string;
      keys: ReturnType<typeof deviceFixture>;
      account: Account;
      /** The package this device last published, per channel. */
      packages: Map<string, GroupPackage>;
    }
    type CommitResult = Awaited<ReturnType<typeof createCommit>>;

    let suite: Awaited<ReturnType<typeof getCiphersuiteImpl>>;
    const clientConfig = {
      ...defaultClientConfig,
      keyRetentionConfig: { retainKeysForGenerations: 0, retainKeysForEpochs: 1, maximumForwardRatchetSteps: 1000 },
    };
    const textEncoder = new TextEncoder();
    const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');
    let owner: Account;
    let bob: Account;
    let carol: Account;
    let dave: Account;
    let workspaceId = '';
    let o1: GroupDevice;
    let b1: GroupDevice;
    let c1: GroupDevice;
    let d1: GroupDevice;

    before(async () => {
      suite = await getCiphersuiteImpl(getCiphersuiteFromName(MLS_CIPHERSUITE));
      // Invitations into this suite come from any existing account, through
      // the services: it may have no device left to confirm its identity
      // with. On its own, this suite registers the first account.
      const { db } = await import('../db/index.js');
      const inviterId = (await db.query.users.findFirst({ columns: { id: true } }))?.id
        ?? (await createAccount('group-admin@example.test', 'Correct-Horse-Battery-20!', 'Admin', process.env.REGISTRATION_INVITE_SECRET!)).user.id;
      const lobby = await (await import('../services/workspace.service.js')).createWorkspace('Group invitations', inviterId);
      const { createInvitation } = await import('../services/invitation.service.js');
      const ownerInvitation = await createInvitation(lobby.id, inviterId, { email: 'group-owner@example.test', expiresInSeconds: 3_600 });
      owner = await createAccount('group-owner@example.test', 'Correct-Horse-Battery-21!', 'Owner', ownerInvitation.token);
      o1 = await groupDevice(owner, 'O1');
      const workspaceResponse = await request('/api/workspaces', { method: 'POST', cookie: owner.cookie, body: { name: 'Groups' } });
      assert.equal(workspaceResponse.status, 201);
      workspaceId = (await json<{ id: string }>(workspaceResponse)).id;
      bob = await createAccount('group-bob@example.test', 'Correct-Horse-Battery-22!', 'Bob',
        (await createWorkspaceInvitation(workspaceId, owner.cookie, 'group-bob@example.test')).token);
      carol = await createAccount('group-carol@example.test', 'Correct-Horse-Battery-23!', 'Carol',
        (await createWorkspaceInvitation(workspaceId, owner.cookie, 'group-carol@example.test')).token);
      dave = await createAccount('group-dave@example.test', 'Correct-Horse-Battery-24!', 'Dave',
        (await createWorkspaceInvitation(workspaceId, owner.cookie, 'group-dave@example.test')).token);
      b1 = await groupDevice(bob, 'B1');
      c1 = await groupDevice(carol, 'C1');
      d1 = await groupDevice(dave, 'D1');
    });

    it('orders commits, answers retries and keeps writes on the current version', async () => {
      const { db } = await import('../db/index.js');
      const keyService = await import('../services/key.service.js');
      const channelId = await groupChannel('ordered');
      let state = await groupState(owner, channelId);
      assert.equal(state.group, null);
      assert.equal(state.canCreate, true);
      assert.equal(state.protocolVersion, 4);

      assert.equal((await publishPackage(o1, channelId)).status, 201);
      assert.equal((await publishPackage(o1, channelId, { pkg: o1.packages.get(channelId) })).status, 200, 'the same package again changes nothing');
      assert.equal((await publishPackage(b1, channelId)).status, 201);
      const pending = await json<Array<{ deviceId: string }>>(await request(`/api/channels/${channelId}/mls/group/packages`, { cookie: owner.cookie }));
      assert.deepEqual(pending.map((entry) => entry.deviceId).sort(), [o1.id, b1.id].sort());

      const group = new GroupRun(channelId);
      const genesis = await group.create(o1, [b1]);
      assert.equal(genesis.response.status, 201);
      assert.deepEqual(await json(genesis.response), { version: 1, epoch: 1 });
      // A lost response is retried with the same bytes, after its packages were consumed.
      const retried = await postCommit(o1, genesis.commit);
      assert.equal(retried.status, 200);
      assert.deepEqual(await json(retried), { version: 1, epoch: 1, replay: true });
      assert.equal((await db.execute(sql`select count(*)::int as count from audit_logs
        where action = 'channel.key.group.replay' and target_id = ${channelId}`)).rows[0].count, 1);
      assert.equal((await db.execute(sql`select count(*)::int as count from mls_member_packages where channel_id = ${channelId}`)).rows[0].count, 0);
      assert.deepEqual((await db.execute(sql`select device_id as "deviceId", leaf_index as "leafIndex" from mls_group_members
        where channel_id = ${channelId} and removed_version is null order by leaf_index`)).rows,
      [{ deviceId: o1.id, leafIndex: 0 }, { deviceId: b1.id, leafIndex: 1 }]);

      state = await groupState(bob, channelId);
      assert.equal(state.group.genesisVersion, 1);
      assert.equal(state.ownMembership.joinedVersion, 1);
      assert.equal(state.canCommit, true);
      assert.equal(state.rotationRequired, false);
      assert.equal(state.group.transcript, createHash('sha256').update(serializeMlsGroupCommit(genesis.commit)).digest('hex'));

      // Writes use exactly the active version; a device outside the group cannot write.
      const key = randomBytes(32);
      assert.equal((await postMessage(o1, channelId, key, 1)).status, 201);
      let response = await postMessage(o1, channelId, key, 2);
      assert.equal(response.status, 400);
      assert.deepEqual(pick(await json(response), ['code', 'currentVersion']), { code: 'KEY_VERSION_STALE', currentVersion: 1 });
      assert.equal((await publishPackage(c1, channelId)).status, 201);
      response = await postMessage(c1, channelId, key, 1);
      assert.equal(response.status, 400);
      assert.equal((await json<{ code: string }>(response)).code, 'INVALID_KEY_VERSION');

      // Per-device key deliveries never apply to a group version.
      const recipient = { deviceId: o1.id, identityKey: o1.identityKey };
      const wrap = signedChannelKeyWrap({
        channelId, version: 1, keyCommitment: genesis.commit.keyCommitment, rawKey: key, recipient, senderKeys: o1.keys,
      });
      response = await request(`/api/channels/${channelId}/keys`, {
        method: 'POST', cookie: owner.cookie, body: { version: 1, keyCommitment: genesis.commit.keyCommitment, keys: [wrap] },
      });
      assert.equal(response.status, 400);
      await assert.rejects(
        keyService.distributeChannelKeys(channelId, owner.user.id, o1.id, 1, genesis.commit.keyCommitment, [wrap]),
        /INVALID_KEY_VERSION/,
      );
      const nextWrap = signedChannelKeyWrap({
        channelId, version: 2, keyCommitment: 'n'.repeat(43), rawKey: key, recipient, senderKeys: o1.keys,
      });
      assert.equal((await request(`/api/channels/${channelId}/keys`, {
        method: 'POST', cookie: owner.cookie, body: { version: 2, keyCommitment: 'n'.repeat(43), keys: [nextWrap] },
      })).status, 409);
      await assert.rejects(
        keyService.distributeChannelKeys(channelId, owner.user.id, o1.id, 2, 'n'.repeat(43), [nextWrap]),
        /GROUP_PROTOCOL_REQUIRED/,
      );
      // The per-epoch read route serves only earlier protocols; a group
      // version is as unknown there as a version that does not exist.
      for (const version of [1, 99]) {
        const missing = await request(`/api/channels/${channelId}/mls/epochs/${version}`, { cookie: owner.cookie });
        assert.deepEqual([missing.status, (await json<{ error: string }>(missing)).error], [404, 'NOT_FOUND']);
      }

      // The log and rosters are for members only.
      assert.deepEqual(await json(await request(`/api/channels/${channelId}/mls/group/commits?after=0`, { cookie: carol.cookie })), []);
      assert.equal((await request(`/api/channels/${channelId}/mls/group/members?version=1`, { cookie: carol.cookie })).status, 404);
      const added = await group.commit(b1, { add: [c1] });
      assert.equal(added.response.status, 201);
      assert.equal((await db.execute(sql`select count(*)::int as count from mls_member_packages where channel_id = ${channelId}`)).rows[0].count, 0);
      assert.deepEqual(await json(await request(`/api/channels/${channelId}/mls/group/commits?after=0`, { cookie: carol.cookie })), []);
      assert.deepEqual((await json<Array<{ version: number }>>(await request(`/api/channels/${channelId}/mls/group/commits?after=1`, { cookie: carol.cookie })))
        .map((entry) => entry.version), [2]);
      assert.equal((await request(`/api/channels/${channelId}/mls/group/members?version=1`, { cookie: carol.cookie })).status, 404);
      assert.deepEqual((await json<Array<{ deviceId: string }>>(await request(`/api/channels/${channelId}/mls/group/members?version=2`, { cookie: carol.cookie })))
        .map((entry) => entry.deviceId), [o1.id, b1.id, c1.id]);

      // An empty commit refreshes the group key only when it is due.
      const early = await group.commit(o1, {}, { post: false });
      response = await postCommit(o1, early.commit);
      assert.equal(response.status, 409);
      assert.equal((await json<{ code: string }>(response)).code, 'KEY_ROTATION_NOT_REQUIRED');
      await db.execute(sql`update mls_groups set path_refreshed_at = now() - interval '25 hours' where channel_id = ${channelId}`);
      response = await postMessage(b1, channelId, key, 2);
      assert.equal(response.status, 400);
      assert.equal((await json<{ code: string }>(response)).code, 'KEY_ROTATION_REQUIRED');
      assert.equal((await groupState(bob, channelId)).updateRequired, true);
      const refresh = await group.commit(o1);
      assert.equal(refresh.response.status, 201);
      const path = refresh.result.commit as unknown as MlsPublicMessage;
      const leafKey = b64((path.publicMessage.content as any).commit.path.leafNode.hpkePublicKey);
      const row = (await db.execute(sql`select g.path_refreshed_at > now() - interval '1 minute' as "fresh", m.encryption_key as "encryptionKey"
        from mls_groups g join mls_group_members m on m.channel_id = g.channel_id and m.device_id = ${o1.id} and m.removed_version is null
        where g.channel_id = ${channelId}`)).rows[0] as { fresh: boolean; encryptionKey: string };
      assert.deepEqual(row, { fresh: true, encryptionKey: leafKey });
      assert.ok(Number((await db.execute(sql`select count(*)::int as count from mls_group_node_keys where channel_id = ${channelId}`)).rows[0].count) >= 2);
      assert.equal((await postMessage(c1, channelId, key, 3)).status, 201);
    });

    it('publishes each package once and keeps package keys unique', async () => {
      const { db } = await import('../db/index.js');
      const channelId = await groupChannel('packages');
      await publishPackage(o1, channelId);
      await publishPackage(b1, channelId);
      const group = new GroupRun(channelId);
      assert.equal((await group.create(o1, [b1])).response.status, 201);

      // A package id is used once, whatever bytes come with it.
      const first = await newGroupPackage(c1, channelId);
      assert.equal((await publishPackage(c1, channelId, { pkg: first })).status, 201);
      const other = await newGroupPackage(c1, channelId);
      let response = await publishPackage(c1, channelId, { pkg: signPackage(c1, channelId, first.id, other.pub, other.priv) });
      assert.deepEqual([response.status, (await json<{ code: string }>(response)).code], [409, 'PACKAGE_CONSUMED']);
      assert.equal((await publishPackage(c1, channelId)).status, 201, 'a new package replaces the first');
      response = await publishPackage(c1, channelId, { pkg: first });
      assert.deepEqual([response.status, (await json<{ code: string }>(response)).code], [409, 'PACKAGE_CONSUMED']);
      response = await publishPackage(c1, channelId, { pkg: await newGroupPackage(c1, channelId, { notAfter: 1800n }) });
      assert.deepEqual([response.status, (await json<{ code: string }>(response)).code], [403, 'INVALID_MLS'], 'never valid long enough to be added');

      // Keys stay unique against current leaves and every node key of the tree.
      response = await publishPackage(c1, channelId, { pkg: await packageWithLeafKey(c1, channelId, b1.packages.get(channelId)!.pub.leafNode.hpkePublicKey) });
      assert.deepEqual([response.status, (await json<{ code: string }>(response)).code], [409, 'PACKAGE_KEY_CONFLICT']);
      await db.execute(sql`update mls_groups set path_refreshed_at = now() - interval '25 hours' where channel_id = ${channelId}`);
      // An UpdatePath may not take a key of a package that waits to be added.
      const blocked = await group.commit(o1, {}, { post: false });
      const blockedLeaf = ((blocked.result.commit as unknown as MlsPublicMessage).publicMessage.content as any).commit.path.leafNode;
      assert.equal((await publishPackage(c1, channelId, { pkg: await packageWithLeafKey(c1, channelId, blockedLeaf.hpkePublicKey) })).status, 201);
      response = await postCommit(o1, blocked.commit);
      assert.deepEqual([response.status, (await json<{ code: string }>(response)).code], [409, 'PACKAGE_KEY_CONFLICT']);
      const refresh = await group.commit(o1);
      assert.equal(refresh.response.status, 201);
      const parentKey = (refresh.result.commit as unknown as MlsPublicMessage).publicMessage.content as any;
      response = await publishPackage(c1, channelId, { pkg: await packageWithLeafKey(c1, channelId, parentKey.commit.path.nodes[0].hpkePublicKey) });
      assert.deepEqual([response.status, (await json<{ code: string }>(response)).code], [409, 'PACKAGE_KEY_CONFLICT']);

      // A member publishes only to ask to be added again, a few times a day.
      response = await publishPackage(b1, channelId);
      assert.deepEqual([response.status, (await json<{ code: string }>(response)).code], [409, 'ALREADY_MEMBER']);
      for (const expected of [201, 201, 201, 409]) {
        response = await publishPackage(b1, channelId, { rejoin: true });
        assert.equal(response.status, expected);
      }
      assert.equal((await json<{ code: string }>(response)).code, 'REJOIN_LIMIT');
      await db.execute(sql`update mls_rejoin_requests set requested_at = requested_at - interval '25 hours' where channel_id = ${channelId}`);
      assert.equal((await publishPackage(b1, channelId, { rejoin: true })).status, 201);
      assert.equal((await db.execute(sql`select count(*)::int as count from mls_rejoin_requests
        where channel_id = ${channelId} and device_id = ${b1.id}`)).rows[0].count, 2, 'the oldest open request and the new one');
      assert.deepEqual((await groupState(owner, channelId)).pendingAddDeviceIds, [b1.id, c1.id].sort());

      // Waiting packages do not keep an unused channel from being deleted.
      const unused = await groupChannel('unused');
      await publishPackage(o1, unused);
      await publishPackage(c1, unused);
      assert.equal((await request(`/api/channels/${unused}`, { method: 'DELETE', cookie: owner.cookie })).status, 200);
      assert.equal((await db.execute(sql`select count(*)::int as count from mls_published_package_ids where channel_id = ${unused}`)).rows[0].count, 2);
    });

    it('stops writes while the group holds a device without access until a commit removes it', async () => {
      const { db } = await import('../db/index.js');
      const service = await import('../services/mls-group.service.js');
      const channelId = await groupChannel('access', true);
      for (const account of [bob, carol, dave]) {
        assert.equal((await request(`/api/channels/${channelId}/members`, {
          method: 'POST', cookie: owner.cookie, body: { userId: account.user.id },
        })).status, 201);
      }
      for (const device of [o1, b1, c1, d1]) await publishPackage(device, channelId);
      const group = new GroupRun(channelId);
      assert.equal((await group.create(o1, [b1, c1, d1])).response.status, 201);
      const key = randomBytes(32);
      assert.equal((await postMessage(o1, channelId, key, 1)).status, 201);
      await attachmentGate(o1, channelId, 1, 1);

      // A revoked member blocks writes until a commit removes it. The other
      // members hear at once that a commit is due.
      const { io } = await import('socket.io-client');
      const bobSocket = io(baseUrl, { transports: ['websocket'], extraHeaders: { Cookie: bob.cookie, Origin: 'http://localhost:5173' } });
      sockets.push(bobSocket);
      await onceConnected(bobSocket);
      await delay(200);
      const removeDue = onceSocketEventMatching<{ channelId: string }>(
        bobSocket, 'channel:key-rotation-required', (payload) => payload.channelId === channelId, 5_000,
      );
      assert.equal((await request(`/api/devices/${d1.id}`, { method: 'DELETE', cookie: dave.cookie })).status, 200);
      await removeDue;
      bobSocket.disconnect();
      let response = await postMessage(o1, channelId, key, 1);
      assert.deepEqual([response.status, (await json<{ code: string }>(response)).code], [400, 'KEY_ROTATION_REQUIRED']);
      assert.deepEqual((await groupState(owner, channelId)).requiredRemoveDeviceIds, [d1.id]);
      assert.ok((await json<{ needCommit: string[] }>(await request('/api/mls/group/pending', { cookie: bob.cookie }))).needCommit.includes(channelId));
      await assert.rejects(service.listGroupCommits(channelId, dave.user.id, d1.id, 0, 16), /DEVICE_APPROVAL_REQUIRED/);
      await assert.rejects(service.listGroupMembers(channelId, dave.user.id, d1.id, 1), /DEVICE_APPROVAL_REQUIRED/);
      assert.equal((await group.commit(b1, { remove: [d1] })).response.status, 201);
      assert.equal((await db.execute(sql`select removed_version as "removedVersion" from mls_group_members
        where channel_id = ${channelId} and device_id = ${d1.id}`)).rows[0].removedVersion, 2);
      assert.equal((await postMessage(o1, channelId, key, 2)).status, 201);

      // A file keeps its message's version only while nobody left since.
      await assert.rejects(attachmentGate(o1, channelId, 1, 1), /KEY_ROTATION_REQUIRED/);
      await attachmentGate(o1, channelId, 2, 2);
      await assert.rejects(attachmentGate(o1, channelId, 2, 1), /INVALID_KEY_VERSION/);
      // A rejoin removes and adds the same device in one commit.
      assert.equal((await publishPackage(c1, channelId, { rejoin: true })).status, 201);
      assert.equal((await group.commit(o1, { remove: [c1], add: [c1] })).response.status, 201);
      await attachmentGate(o1, channelId, 2, 2);
      assert.deepEqual((await json<Array<{ version: number }>>(await request(`/api/channels/${channelId}/mls/group/commits?after=1`, { cookie: carol.cookie })))
        .map((entry) => entry.version), [2, 3]);

      // A member whose user lost access blocks writes the same way.
      assert.equal((await request(`/api/channels/${channelId}/members/${bob.user.id}`, { method: 'DELETE', cookie: owner.cookie })).status, 200);
      const since = (await db.execute(sql`select remove_required_at as "since" from mls_groups where channel_id = ${channelId}`)).rows[0].since;
      assert.ok(since, 'the group records since when a remove is due');
      response = await postMessage(o1, channelId, key, 3);
      assert.deepEqual([response.status, (await json<{ code: string }>(response)).code], [400, 'KEY_ROTATION_REQUIRED']);
      assert.equal((await request(`/api/channels/${channelId}/mls/group/commits?after=0`, { cookie: bob.cookie })).status, 404);
      assert.equal((await group.commit(o1, { remove: [b1] })).response.status, 201);
      assert.equal((await db.execute(sql`select remove_required_at as "since" from mls_groups where channel_id = ${channelId}`)).rows[0].since, null);
      assert.equal((await postMessage(o1, channelId, key, 4)).status, 201);
    });

    it('restarts a group only when permitted and records who left', async () => {
      const { db } = await import('../db/index.js');
      const channelId = await groupChannel('restart');
      for (const device of [o1, b1, c1]) await publishPackage(device, channelId);
      const group = new GroupRun(channelId);
      assert.equal((await group.create(o1, [b1, c1])).response.status, 201);

      await publishPackage(b1, channelId, { rejoin: true });
      const restart = await group.create(b1, [], { post: false });
      let response = await postCommit(b1, restart.commit);
      assert.deepEqual([response.status, (await json<{ code: string }>(response)).code], [403, 'KEY_FRESH_START_REQUIRED']);
      response = await postCommit(b1, restart.commit, true);
      assert.deepEqual([response.status, (await json<{ code: string }>(response)).code], [409, 'KEY_FRESH_START_NOT_REQUIRED']);
      // Nobody usable has been online for three days.
      const idle = () => db.execute(sql`update mls_group_members set last_seen_at = now() - interval '73 hours' where channel_id = ${channelId}`);
      await idle();
      assert.equal((await groupState(bob, channelId)).historyRecoveryRequired, true);
      // A usable member that reads the state, or the commit log, is online again.
      const seenSeconds = async (device: GroupDevice) => Number((await db.execute(sql`select extract(epoch from now() - last_seen_at)::int as "age"
        from mls_group_members where channel_id = ${channelId} and device_id = ${device.id} and removed_version is null`)).rows[0].age);
      await groupState(owner, channelId);
      assert.ok(await seenSeconds(o1) < 60, 'reading the state records the member as online');
      assert.equal((await groupState(bob, channelId)).historyRecoveryRequired, false);
      response = await postCommit(b1, restart.commit, true);
      assert.deepEqual([response.status, (await json<{ code: string }>(response)).code], [409, 'KEY_FRESH_START_NOT_REQUIRED']);
      await idle();
      assert.equal((await request(`/api/channels/${channelId}/mls/group/commits?after=0`, { cookie: carol.cookie })).status, 200);
      assert.ok(await seenSeconds(c1) < 60, 'reading the commit log records the member as online');
      assert.equal((await groupState(bob, channelId)).historyRecoveryRequired, false);
      await idle();
      assert.equal((await groupState(bob, channelId)).historyRecoveryRequired, true);
      response = await postCommit(b1, restart.commit, true);
      assert.equal(response.status, 201);
      await group.adopt(restart);

      const removed = (await db.execute(sql`select device_id as "deviceId" from mls_group_members
        where channel_id = ${channelId} and removed_version = 2 order by device_id`)).rows.map((row: any) => row.deviceId);
      assert.deepEqual(removed, [o1.id, b1.id, c1.id].sort());
      const audit = (await db.execute(sql`select details from audit_logs
        where action = 'channel.key.group.fresh_start' and target_id = ${channelId}`)).rows[0] as { details: { removed: string[]; added: string[] } };
      assert.deepEqual(audit.details.removed, [o1.id, b1.id, c1.id].sort());
      assert.deepEqual(audit.details.added, [b1.id]);
      const state = await groupState(owner, channelId);
      assert.equal(state.group.genesisVersion, 2);
      assert.equal(state.ownMembership, null);
      assert.deepEqual((await json<Array<{ version: number }>>(await request(`/api/channels/${channelId}/mls/group/commits?after=1`, { cookie: owner.cookie })))
        .map((entry) => entry.version), [2], 'a former member sees the version that removed it');
      assert.equal((await postMessage(b1, channelId, randomBytes(32), 2)).status, 201);
    });

    it('lets a device start over only after its rejoin, or a manager only after a stalled change, has waited', async () => {
      const { db } = await import('../db/index.js');
      const ownerMember = asGroupMember(owner.cookie, owner.user.id, o1.keys, o1);
      const bobMember = asGroupMember(bob.cookie, bob.user.id, b1.keys, b1);
      const carolMember = asGroupMember(carol.cookie, carol.user.id, c1.keys, c1);

      // (b) A member that lost its group asked to be added again, and nobody
      // re-added it for 30 minutes although they could have.
      const rejoinChannel = await groupChannel('rejoin-wait');
      const rejoinGroup = new ChannelGroup(rejoinChannel);
      assert.equal((await rejoinGroup.create(ownerMember, [bobMember, carolMember])).response!.status, 201);
      rejoinGroup.local.delete(c1.id);
      assert.equal((await rejoinGroup.publish(carolMember, { rejoin: true, material: await earlierMemberPackage(c1.id, 3_600n) })).status, 201);
      let restart = await rejoinGroup.create(carolMember, [], { freshStart: true });
      assert.deepEqual(await refusal(restart.response!), [409, 'KEY_FRESH_START_NOT_REQUIRED']);
      assert.equal((await rejoinGroup.state(carolMember)).historyRecoveryRequired, false);
      await db.execute(sql`update mls_rejoin_requests set requested_at = requested_at - interval '31 minutes' where channel_id = ${rejoinChannel}`);
      await db.execute(sql`update mls_member_packages set created_at = created_at - interval '31 minutes' where channel_id = ${rejoinChannel}`);
      assert.equal((await rejoinGroup.state(carolMember)).historyRecoveryRequired, true);
      assert.equal((await rejoinGroup.state(bobMember)).historyRecoveryRequired, false, 'a usable member keeps committing instead');
      restart = await rejoinGroup.create(carolMember, [], { freshStart: true });
      assert.equal(restart.response!.status, 201);
      assert.deepEqual([restart.outcomes.get(o1.id), restart.outcomes.get(b1.id)], ['removed', 'removed'],
        'the other devices see the group replaced and leave it');
      assert.equal(await rejoinGroup.sync(bobMember), 'waiting');
      assert.equal((await rejoinGroup.publish(bobMember)).status, 201);
      const bobBack = await rejoinGroup.commit(carolMember, { add: [bobMember] });
      assert.equal(bobBack.response!.status, 201);
      assert.equal(bobBack.outcomes.get(b1.id), 'current');
      assert.equal((await groupMessage(bobMember, rejoinChannel, rejoinGroup.key(), rejoinGroup.version)).status, 201);

      // (c) A manager outside the group may start over once a change nobody
      // committed has waited 15 minutes; an ordinary member never on that ground.
      const carolLogin = await request('/api/auth/login', {
        method: 'POST', body: { email: 'group-carol@example.test', password: carol.password },
      });
      assert.equal(carolLogin.status, 200);
      const carolCookie = carolLogin.headers.get('set-cookie')!.split(';', 1)[0];
      const c2Keys = deviceFixture();
      const c2 = await registerDevice({ ...carol, cookie: carolCookie }, c2Keys, 'C2');
      const carolSecond = asGroupMember(carolCookie, carol.user.id, c2Keys, c2);
      const stallChannel = await groupChannel('stalled-change');
      const stallGroup = new ChannelGroup(stallChannel);
      assert.equal((await stallGroup.create(bobMember, [carolMember])).response!.status, 201);
      assert.equal((await stallGroup.publish(carolSecond, { material: await earlierMemberPackage(c2.id, 3_600n) })).status, 201);
      assert.equal((await stallGroup.publish(ownerMember, { material: await earlierMemberPackage(o1.id, 3_600n) })).status, 201);
      let managerRestart = await stallGroup.create(ownerMember, [carolSecond], { freshStart: true });
      assert.deepEqual(await refusal(managerRestart.response!), [409, 'KEY_FRESH_START_NOT_REQUIRED']);
      await db.execute(sql`update mls_member_packages set created_at = created_at - interval '16 minutes' where channel_id = ${stallChannel}`);
      await db.execute(sql`update channel_key_epochs set created_at = created_at - interval '16 minutes'
        where channel_id = ${stallChannel} and status = 'active'`);
      assert.equal((await stallGroup.state(carolSecond)).historyRecoveryRequired, false);
      assert.equal((await stallGroup.state(ownerMember)).historyRecoveryRequired, true);
      const memberRestart = await stallGroup.create(carolSecond, [], { freshStart: true, post: false });
      assert.deepEqual(await refusal(await stallGroup.send(carolSecond, memberRestart.envelope, true)), [409, 'KEY_FRESH_START_NOT_REQUIRED']);
      managerRestart = await stallGroup.create(ownerMember, [carolSecond], { freshStart: true });
      assert.equal(managerRestart.response!.status, 201);
      assert.deepEqual(
        [managerRestart.outcomes.get(c2.id), managerRestart.outcomes.get(b1.id), managerRestart.outcomes.get(c1.id)],
        ['current', 'removed', 'removed'],
      );
      assert.equal((await groupMessage(carolSecond, stallChannel, stallGroup.key(), stallGroup.version)).status, 201);
    });

    it('backs up history keys only for versions at which a device of the user was in the group', async () => {
      const { db } = await import('../db/index.js');
      const { directoryHead } = await import('../services/directory.service.js');
      const channelId = await groupChannel('recovery-history', true);
      assert.equal((await request(`/api/channels/${channelId}/members`, {
        method: 'POST', cookie: owner.cookie, body: { userId: bob.user.id },
      })).status, 201);
      const ownerMember = asGroupMember(owner.cookie, owner.user.id, o1.keys, o1);
      const bobMember = asGroupMember(bob.cookie, bob.user.id, b1.keys, b1);
      const history = new ChannelGroup(channelId);
      assert.equal((await history.create(ownerMember, [bobMember])).response!.status, 201);
      // Bob leaves for version 2 and is added again at version 3.
      assert.equal((await request(`/api/channels/${channelId}/members/${bob.user.id}`, { method: 'DELETE', cookie: owner.cookie })).status, 200);
      assert.equal((await history.commit(ownerMember, { remove: [bobMember] })).response!.status, 201);
      assert.equal((await request(`/api/channels/${channelId}/members`, {
        method: 'POST', cookie: owner.cookie, body: { userId: bob.user.id },
      })).status, 201);
      assert.equal((await history.publish(bobMember)).status, 201);
      const readded = await history.commit(ownerMember, { add: [bobMember] });
      assert.equal(readded.response!.status, 201);
      assert.equal(readded.outcomes.get(b1.id), 'current');
      assert.equal(history.version, 3);

      // An opaque archive: the server stores it and checks only who may add to it.
      const generation = randomUUID();
      const signingKey = JSON.stringify(generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }));
      const head = await directoryHead(db, bob.user.id);
      const decision = { kind: 'recovery-config' as const, deviceId: generation, identityKey: signingKey, actorDeviceId: b1.id };
      assert.equal((await request('/api/recovery/configure', {
        method: 'POST',
        cookie: bob.cookie,
        body: {
          generation,
          signingKey,
          encryptedSecret: randomBytes(96).toString('base64'),
          accessTokenHash: randomBytes(32).toString('hex'),
          head,
          signature: signDevicePayload(b1.keys, serializeDeviceDecision(head, decision)),
        },
      })).status, 200);
      const candidates = await json<{ candidates: Array<{ channelId: string; version: number }> }>(
        await request('/api/recovery/candidates', { cookie: bob.cookie }),
      );
      assert.deepEqual(candidates.candidates.filter((entry) => entry.channelId === channelId).map((entry) => entry.version), [1, 3]);
      const backup = (version: number, keyCommitment: string) => request('/api/recovery/keys', {
        method: 'POST',
        cookie: bob.cookie,
        body: { generation, channelId, version, keyCommitment, ciphertext: randomBytes(96).toString('base64') },
      });
      assert.equal((await backup(1, keyCommitmentOf(history.key(1)))).status, 200);
      assert.equal((await backup(2, keyCommitmentOf(history.key(2)))).status, 403, 'no device of the user was in the group at version 2');
      assert.equal((await backup(3, keyCommitmentOf(history.key(2)))).status, 403, 'the commitment must name the key of that version');
      assert.equal((await backup(3, keyCommitmentOf(history.key(3)))).status, 200);
      const stored = await json<{ keys: Array<{ channelId: string; version: number }> }>(await request('/api/recovery/keys', { cookie: bob.cookie }));
      assert.deepEqual(stored.keys.filter((entry) => entry.channelId === channelId).map((entry) => entry.version), [1, 3]);
    });

    it('waits for the earlier recipients of a migrated channel, then links its first group to the active v3 envelope', async () => {
      const { db } = await import('../db/index.js');
      const ownerMember = asGroupMember(owner.cookie, owner.user.id, o1.keys, o1);
      const bobMember = asGroupMember(bob.cookie, bob.user.id, b1.keys, b1);
      const carolMember = asGroupMember(carol.cookie, carol.user.id, c1.keys, c1);
      const channelId = await groupChannel('migrated');
      // What migration 0023 leaves of a group protocol 3 channel: the active
      // version with its signed envelope and recipients, an aborted successor,
      // and writes stopped until the first group.
      const legacyTranscript = randomBytes(32).toString('hex');
      await db.execute(sql`insert into channel_key_epochs
        (channel_id, version, protocol_version, status, key_commitment, distributor_device_id, activated_at, aborted_at)
        values (${channelId}, 1, 3, 'active', ${'L'.repeat(43)}, ${o1.id}, now(), null),
          (${channelId}, 2, 3, 'aborted', ${'M'.repeat(43)}, ${o1.id}, null, now())`);
      await db.execute(sql`insert into mls_epochs (channel_id, version, transcript, envelope)
        values (${channelId}, 1, ${legacyTranscript}, ${JSON.stringify({ channelId, version: 1 })}::jsonb)`);
      await db.execute(sql`insert into channel_key_epoch_recipients (channel_id, version, device_id, user_id)
        values (${channelId}, 1, ${o1.id}, ${owner.user.id}), (${channelId}, 1, ${b1.id}, ${bob.user.id}),
          (${channelId}, 1, ${c1.id}, ${carol.user.id})`);
      await db.execute(sql`update channels set key_rotation_required = true where id = ${channelId}`);
      const group = new ChannelGroup(channelId);
      let state = await group.state(ownerMember);
      assert.deepEqual(
        pick(state, ['group', 'protocolVersion', 'currentVersion', 'nextVersion', 'canCreate']),
        { group: null, protocolVersion: 3, currentVersion: 1, nextVersion: 3, canCreate: true },
      );
      assert.deepEqual(state.genesisWaiting, [o1.id, b1.id, c1.id].sort());
      assert.deepEqual(await refusal(await groupMessage(ownerMember, channelId, randomBytes(32), 1)), [400, 'KEY_ROTATION_REQUIRED']);

      // The wait starts with the first package and is not moved by later ones.
      const waitRow = async () => (await db.execute(sql`select genesis_requested_at as "requestedAt", genesis_version as "genesisVersion"
        from mls_groups where channel_id = ${channelId}`)).rows[0] as { requestedAt: Date | null; genesisVersion: number | null } | undefined;
      assert.equal(await waitRow(), undefined);
      assert.equal((await group.publish(ownerMember)).status, 201);
      const started = await waitRow();
      assert.ok(started?.requestedAt, 'the first package starts the wait');
      assert.equal(started.genesisVersion, null);
      assert.equal((await group.publish(bobMember)).status, 201);
      assert.deepEqual((await waitRow())!.requestedAt, started.requestedAt);
      state = await group.state(ownerMember);
      assert.deepEqual(state.genesisWaiting, [c1.id]);
      assert.equal(state.canCreate, true);

      // Carol's device was a recipient and has published nothing yet.
      let created = await group.create(ownerMember, [bobMember]);
      assert.deepEqual(
        [created.envelope.version, created.envelope.previousVersion, created.envelope.previousTranscript],
        [3, 1, legacyTranscript],
      );
      assert.deepEqual(await refusal(created.response!), [409, 'GENESIS_WAITING']);
      // After 24 hours the first group goes ahead without it.
      await db.execute(sql`update mls_groups set genesis_requested_at = genesis_requested_at - interval '24 hours'
        where channel_id = ${channelId}`);
      assert.deepEqual((await group.state(ownerMember)).genesisWaiting, []);
      created = await group.create(ownerMember, [bobMember]);
      assert.equal(created.response!.status, 201);
      assert.equal(created.outcomes.get(b1.id), 'current', 'Bob joins from the Welcome with the same key');
      assert.deepEqual((await db.execute(sql`select version, status, protocol_version as "protocolVersion"
        from channel_key_epochs where channel_id = ${channelId} order by version`)).rows, [
        { version: 1, status: 'retired', protocolVersion: 3 },
        { version: 2, status: 'aborted', protocolVersion: 3 },
        { version: 3, status: 'active', protocolVersion: 4 },
      ]);
      assert.equal((await waitRow())!.genesisVersion, 3);
      assert.equal((await groupMessage(bobMember, channelId, group.key(3), 3)).status, 201);
      assert.deepEqual(await refusal(await groupMessage(bobMember, channelId, group.key(3), 1)), [400, 'KEY_VERSION_STALE']);

      // Carol comes online later and is added like any new device.
      assert.equal((await group.publish(carolMember)).status, 201);
      const addition = await group.commit(bobMember, { add: [carolMember] });
      assert.equal(addition.response!.status, 201);
      assert.equal(addition.outcomes.get(c1.id), 'current');
      assert.equal((await groupMessage(carolMember, channelId, group.key(4), 4)).status, 201);
    });

    it('counts add-only and empty commits from the log for the hourly limit, but never delays a removal', async () => {
      const { db } = await import('../db/index.js');
      const ownerMember = asGroupMember(owner.cookie, owner.user.id, o1.keys, o1);
      const bobMember = asGroupMember(bob.cookie, bob.user.id, b1.keys, b1);
      const extra = await secondDevice(owner, 'group-owner@example.test', 'O-rate');
      const channelId = await groupChannel('commit-rate');
      const group = new ChannelGroup(channelId);
      assert.equal((await group.create(bobMember, [ownerMember, extra])).response!.status, 201);
      group.offline.add(extra.id);
      const due = () => db.execute(sql`update mls_groups set path_refreshed_at = now() - interval '25 hours' where channel_id = ${channelId}`);
      // Two committers stay below the per-device request limit.
      for (let index = 0; index < 60; index += 1) {
        await due();
        const refresh = await group.commit(index % 2 === 0 ? bobMember : ownerMember);
        assert.equal(refresh.response!.status, 201, `refresh ${index + 1}`);
      }
      await due();
      const limited = await group.commit(bobMember);
      assert.deepEqual(await refusal(limited.response!), [409, 'COMMIT_RATE_LIMITED']);
      // A removal goes through at once.
      assert.equal((await request(`/api/devices/${extra.id}`, { method: 'DELETE', cookie: extra.cookie })).status, 200);
      const removal = await group.commit(ownerMember, { remove: [extra] });
      assert.equal(removal.response!.status, 201);
      // Commits older than an hour no longer count.
      await db.execute(sql`update channel_key_epochs set created_at = created_at - interval '61 minutes' where channel_id = ${channelId}`);
      await due();
      assert.equal((await group.commit(bobMember)).response!.status, 201);
    });

    it('orders a write after a revocation that committed while the write waited, and one of two commits for a version', async () => {
      const { db } = await import('../db/index.js');
      const ownerMember = asGroupMember(owner.cookie, owner.user.id, o1.keys, o1);
      const bobMember = asGroupMember(bob.cookie, bob.user.id, b1.keys, b1);
      const extra = await secondDevice(owner, 'group-owner@example.test', 'O-race');
      const channelId = await groupChannel('revocation-race');
      const group = new ChannelGroup(channelId);
      assert.equal((await group.create(bobMember, [ownerMember, extra])).response!.status, 201);
      group.offline.add(extra.id);

      // Two members commit for the same version at once: one is accepted, the
      // other is a version conflict.
      await db.execute(sql`update mls_groups set path_refreshed_at = now() - interval '25 hours' where channel_id = ${channelId}`);
      const contenders = [await group.commit(bobMember, {}, { post: false }), await group.commit(ownerMember, {}, { post: false })];
      assert.equal(contenders[0].envelope.version, contenders[1].envelope.version);
      const responses = await Promise.all(contenders.map((contender) => group.send(contender.committer, contender.envelope)));
      const outcomes = await Promise.all(responses.map(refusal));
      assert.deepEqual(outcomes.map(([status]) => status).sort(), [201, 409]);
      assert.deepEqual(outcomes.find(([status]) => status === 409), [409, 'MLS_CONFLICT']);
      const winner = contenders[outcomes.findIndex(([status]) => status === 201)];
      await group.accepted(winner);
      assert.equal(group.version, 2);

      // A revocation holds the device row (as revokeDevice does) while a
      // member writes; the write waits for it and is judged after it.
      const holder = new pg.Client({ connectionString: process.env.DATABASE_URL });
      const observer = new pg.Client({ connectionString: process.env.DATABASE_URL });
      await holder.connect();
      await observer.connect();
      try {
        await holder.query('begin');
        try {
          await holder.query('select id from devices where id = $1 for update', [extra.id]);
          await holder.query('update devices set revoked_at = now() where id = $1', [extra.id]);
          const pending = groupMessage(bobMember, channelId, group.key(), group.version);
          let waiting = false;
          for (let attempt = 0; attempt < 100 && !waiting; attempt += 1) {
            const { rows } = await observer.query<{ waiting: number }>(`
              select count(*)::int as waiting from pg_stat_activity
              where datname = current_database() and wait_event_type = 'Lock' and pid <> $1
            `, [(holder as unknown as { processID: number }).processID]);
            waiting = rows[0]!.waiting > 0;
            if (!waiting) await delay(20);
          }
          assert.equal(waiting, true, 'the write never waited for the revoked device row');
          await holder.query('commit');
          assert.deepEqual(await refusal(await pending), [400, 'KEY_ROTATION_REQUIRED']);
        } catch (error) {
          await holder.query('rollback').catch(() => undefined);
          throw error;
        }
      } finally {
        await holder.end();
        await observer.end();
      }
      assert.deepEqual((await group.state(bobMember)).requiredRemoveDeviceIds, [extra.id]);
      assert.equal((await group.commit(bobMember, { remove: [extra] })).response!.status, 201);
      assert.equal((await groupMessage(bobMember, channelId, group.key(), group.version)).status, 201);
    });

    // === helpers ===

    /** Another device of `account`, with a session of its own. */
    async function secondDevice(account: Account, email: string, name: string): Promise<MemberDevice> {
      const login = await request('/api/auth/login', { method: 'POST', body: { email, password: account.password } });
      assert.equal(login.status, 200);
      const cookie = login.headers.get('set-cookie')!.split(';', 1)[0];
      const keys = deviceFixture();
      const device = await registerDevice({ ...account, cookie }, keys, name);
      return asGroupMember(cookie, account.user.id, keys, device);
    }

    async function groupDevice(account: Account, name: string): Promise<GroupDevice> {
      const keys = deviceFixture();
      const device = await registerDevice(account, keys, name);
      return { id: device.id, userId: account.user.id, identityKey: device.identityKey, keys, account, packages: new Map() };
    }

    async function groupChannel(name: string, isPrivate = false): Promise<string> {
      const response = await request(`/api/workspaces/${workspaceId}/channels`, {
        method: 'POST', cookie: owner.cookie, body: { name, isPrivate },
      });
      assert.equal(response.status, 201);
      return (await json<{ id: string }>(response)).id;
    }

    async function groupState(account: Account, channelId: string): Promise<any> {
      const response = await request(`/api/channels/${channelId}/key-recipients`, { cookie: account.cookie });
      assert.equal(response.status, 200);
      return response.json();
    }

    function signPackage(device: GroupDevice, channelId: string, id: string, pub: KeyPackage, priv: PrivateKeyPackage): GroupPackage {
      const encoded = b64(encodeMlsMessage({ version: 'mls10', wireformat: 'mls_key_package', keyPackage: pub }));
      const signature = sign('sha256', Buffer.from(serializeMlsMemberPackage(channelId, { deviceId: device.id, packageId: id, keyPackage: encoded })), {
        key: device.keys.signingPrivateKey, dsaEncoding: 'ieee-p1363',
      }).toString('base64');
      return { id, pub, priv, encoded, signature };
    }

    async function newGroupPackage(device: GroupDevice, channelId: string, lifetime: { notAfter?: bigint } = {}): Promise<GroupPackage> {
      const now = BigInt(Math.floor(Date.now() / 1000));
      const pair = await generateKeyPackage(
        { credentialType: 'basic', identity: textEncoder.encode(device.id) },
        { versions: ['mls10'], ciphersuites: [MLS_CIPHERSUITE], extensions: [], proposals: [], credentials: ['basic'] },
        { notBefore: now - 900n, notAfter: now + (lifetime.notAfter ?? 604800n) },
        [],
        suite,
      );
      return signPackage(device, channelId, randomUUID(), pair.publicPackage, pair.privatePackage);
    }

    /** A correctly signed package whose leaf reuses `hpkeKey`. */
    async function packageWithLeafKey(device: GroupDevice, channelId: string, hpkeKey: Uint8Array): Promise<GroupPackage> {
      const base = await newGroupPackage(device, channelId);
      const leafNode = await signLeafNodeKeyPackage({ ...base.pub.leafNode, hpkePublicKey: hpkeKey }, base.priv.signaturePrivateKey, suite.signature);
      const pub = await signKeyPackage({
        version: 'mls10', cipherSuite: suite.name, initKey: base.pub.initKey, leafNode, extensions: [],
      }, base.priv.signaturePrivateKey, suite.signature);
      return signPackage(device, channelId, randomUUID(), pub, base.priv);
    }

    async function publishPackage(device: GroupDevice, channelId: string, options: { pkg?: GroupPackage; rejoin?: boolean } = {}) {
      const pkg = options.pkg ?? await newGroupPackage(device, channelId);
      const response = await request(`/api/channels/${channelId}/mls/group/packages`, {
        method: 'POST',
        cookie: device.account.cookie,
        body: { packageId: pkg.id, keyPackage: pkg.encoded, signature: pkg.signature, ...(options.rejoin ? { rejoin: true } : {}) },
      });
      if (response.status === 201 || response.status === 200) device.packages.set(channelId, pkg);
      return response;
    }

    async function postCommit(device: GroupDevice, commit: MlsGroupCommit, freshStart = false) {
      const path = `/api/channels/${commit.channelId}/mls/group/${freshStart ? 'fresh-start' : 'commits'}`;
      const freshStartSignature = sign('sha256', Buffer.from(serializeChannelKeyFreshStart({
        channelId: commit.channelId, keyVersion: commit.version, keyCommitment: commit.keyCommitment, deviceId: device.id,
      })), { key: device.keys.signingPrivateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
      return request(path, {
        method: 'POST',
        cookie: device.account.cookie,
        body: freshStart ? { commit, freshStartSignature } : { commit },
      });
    }

    function postMessage(device: GroupDevice, channelId: string, key: Buffer, keyVersion: number) {
      const { body } = encryptedMessage(channelId, device.userId, device.id, device.keys.signingPrivateKey, key, 'hello', undefined, keyVersion);
      return request(`/api/channels/${channelId}/messages`, { method: 'POST', cookie: device.account.cookie, body });
    }

    /** The write gate as attachment finalization runs it. */
    async function attachmentGate(device: GroupDevice, channelId: string, keyVersion: number, parentKeyVersion: number) {
      const { db } = await import('../db/index.js');
      const { channels: channelTable } = await import('../db/schema.js');
      const { authorizeGroupWrite } = await import('../services/mls-group-gate.js');
      await db.transaction(async (tx) => {
        const channel = (await tx.query.channels.findFirst({ where: eq(channelTable.id, channelId) }))!;
        await authorizeGroupWrite(tx, { channel, userId: device.userId, deviceId: device.id, keyVersion, parentKeyVersion });
      });
    }

    /** One channel's group as its member devices hold it. */
    class GroupRun {
      states = new Map<string, ClientState>();
      leaves = new Map<string, number>();
      version = 0;
      transcript = '0'.repeat(64);
      genesis = 0;

      constructor(readonly channelId: string) {}

      async create(creator: GroupDevice, others: GroupDevice[], options: { post?: boolean } = {}) {
        const version = this.version + 1;
        const groupState = await createGroup(
          textEncoder.encode(mlsGroupId(this.channelId, version)),
          creator.packages.get(this.channelId)!.pub,
          creator.packages.get(this.channelId)!.priv,
          [],
          suite,
          clientConfig,
        );
        const result = await createCommit({ state: groupState, cipherSuite: suite }, {
          wireAsPublicMessage: true,
          ratchetTreeExtension: true,
          extraProposals: others.map((device) => ({ proposalType: 'add' as const, add: { keyPackage: device.packages.get(this.channelId)!.pub } })),
        });
        const commit = await this.envelope('create', version, version, creator, result, [creator, ...others], []);
        const created = { commit, result, creator, joined: others, removed: [] as GroupDevice[], response: undefined as unknown as Response };
        if (options.post === false) return created;
        created.response = await postCommit(creator, commit);
        if (created.response.status === 201) await this.adopt(created);
        return created;
      }

      async commit(
        committer: GroupDevice,
        change: { add?: GroupDevice[]; remove?: GroupDevice[] } = {},
        options: { post?: boolean } = {},
      ) {
        const result = await createCommit({ state: this.states.get(committer.id)!, cipherSuite: suite }, {
          wireAsPublicMessage: true,
          ratchetTreeExtension: true,
          extraProposals: [
            ...(change.remove ?? []).map((device) => ({ proposalType: 'remove' as const, remove: { removed: this.leaves.get(device.id)! } })),
            ...(change.add ?? []).map((device) => ({ proposalType: 'add' as const, add: { keyPackage: device.packages.get(this.channelId)!.pub } })),
          ],
        });
        const commit = await this.envelope('commit', this.version + 1, this.genesis, committer, result, change.add ?? [], change.remove ?? []);
        const made = { commit, result, creator: committer, joined: change.add ?? [], removed: change.remove ?? [], response: undefined as unknown as Response };
        if (options.post === false) return made;
        made.response = await postCommit(committer, commit);
        if (made.response.status === 201) await this.adopt(made);
        return made;
      }

      /** Every member processes an accepted commit; added devices join from its Welcome. */
      async adopt(accepted: { commit: MlsGroupCommit; result: CommitResult; creator: GroupDevice; joined: GroupDevice[]; removed: GroupDevice[] }) {
        if (accepted.commit.kind === 'create') {
          this.states.clear();
          this.genesis = accepted.commit.version;
        } else {
          const message = decodeMlsMessage(Buffer.from(accepted.commit.commit, 'base64'), 0)![0] as unknown as MlsPublicMessage;
          for (const [deviceId, state] of this.states) {
            if (deviceId === accepted.creator.id || accepted.removed.some((device) => device.id === deviceId)) continue;
            const processed = await processMessage(message, state, makePskIndex(state, {}), acceptAll, suite);
            assert.equal(processed.kind, 'newState');
            this.states.set(deviceId, processed.newState);
          }
          for (const device of accepted.removed) this.states.delete(device.id);
        }
        this.states.set(accepted.creator.id, accepted.result.newState);
        for (const device of accepted.joined) {
          const pkg = device.packages.get(this.channelId)!;
          this.states.set(device.id, await joinGroup(accepted.result.welcome!, pkg.pub, pkg.priv, emptyPskIndex, suite, undefined, undefined, clientConfig));
        }
        this.leaves = new Map(accepted.commit.members.map((member) => [member.deviceId, member.leafIndex]));
        this.version = accepted.commit.version;
        this.transcript = createHash('sha256').update(serializeMlsGroupCommit(accepted.commit)).digest('hex');
      }

      async envelope(
        kind: 'create' | 'commit',
        version: number,
        genesis: number,
        committer: GroupDevice,
        result: CommitResult,
        added: GroupDevice[],
        removed: GroupDevice[],
      ): Promise<MlsGroupCommit> {
        const { db } = await import('../db/index.js');
        const { directoryHead } = await import('../services/directory.service.js');
        const groupId = mlsGroupId(this.channelId, genesis);
        const raw = await mlsExporter(result.newState.keySchedule.exporterSecret, MLS_GROUP_EXPORTER_LABEL,
          textEncoder.encode(mlsExporterContext(groupId, version)), 32, suite);
        const members: MlsGroupCommit['members'] = [];
        for (let index = 0; index < result.newState.ratchetTree.length; index += 2) {
          const node = result.newState.ratchetTree[index];
          if (node?.nodeType !== 'leaf' || node.leaf.credential.credentialType !== 'basic') continue;
          const deviceId = new TextDecoder().decode(node.leaf.credential.identity);
          const device = [o1, b1, c1, d1].find((candidate) => candidate.id === deviceId)!;
          members.push({ deviceId, userId: device.userId, leafIndex: index / 2 });
        }
        const unsigned: Omit<MlsGroupCommit, 'signature'> = {
          channelId: this.channelId,
          version,
          previousVersion: this.version,
          previousTranscript: this.transcript,
          groupId,
          epoch: version - genesis + 1,
          kind,
          keyCommitment: createHash('sha256').update(raw).digest('base64url'),
          commit: b64(encodeMlsMessage(result.commit)),
          welcome: result.welcome ? b64(encodeMlsMessage({ version: 'mls10', wireformat: 'mls_welcome', welcome: result.welcome })) : '',
          added: added.map((device) => {
            const pkg = device.packages.get(this.channelId)!;
            return {
              deviceId: device.id,
              userId: device.userId,
              identityKey: device.identityKey,
              packageId: pkg.id,
              keyPackage: pkg.encoded,
              signature: pkg.signature,
            };
          }),
          removed: removed.map((device) => device.id).sort(),
          members,
          directoryHeads: await Promise.all([...new Set(members.map((member) => member.userId))].sort()
            .map((userId) => directoryHead(db, userId))),
          committerDeviceId: committer.id,
        };
        return {
          ...unsigned,
          signature: sign('sha256', Buffer.from(serializeMlsGroupCommit(unsigned)), {
            key: committer.keys.signingPrivateKey, dsaEncoding: 'ieee-p1363',
          }).toString('base64'),
        };
      }
    }
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
    assert.equal(await checkDatabaseSchema(), 24);
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

  /** Asks for a registration code and reads it from the development outbox. */
  async function emailCode(email: string, inviteToken: string): Promise<string> {
    const response = await request('/api/auth/register/code', { method: 'POST', body: { email, inviteToken } });
    assert.equal(response.status, 202);
    assert.deepEqual(await json(response), { required: true });
    const { developmentEmails } = await import('../services/email.service.js');
    const code = [...developmentEmails()].reverse().find((message) => message.to === email)?.text.match(/\b(\d{6})\b/)?.[1];
    assert.ok(code, `no code was mailed to ${email}`);
    return code;
  }

  async function createAccount(email: string, password: string, displayName: string, inviteToken: string) {
    const registration = await request('/api/auth/register', {
      method: 'POST', body: { email, password, displayName, inviteToken, emailCode: await emailCode(email, inviteToken) },
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

  // === Continuous channel groups (group protocol 4), driven like clients ===
  //
  // Groups, commits and Welcomes are made by the client's adapter
  // (packages/client/src/services/mls-crypto.ts) and checked with the
  // client's envelope rules (mls-group-model.ts); every exchange goes through
  // the server's HTTP routes with the device's own session.

  /** A device and the session bound to it. */
  interface MemberDevice {
    id: string;
    userId: string;
    identityKey: string;
    keys: ReturnType<typeof deviceFixture>;
    cookie: string;
  }

  interface MemberPackageMaterial {
    publicPackage: string;
    privatePackage: { initPrivateKey: string; hpkePrivateKey: string; signaturePrivateKey: string };
  }

  interface ClientCommitResult {
    newState: ClientState;
    commit: string;
    welcome: string;
  }

  interface ClientDecodedCommit {
    groupId: string;
    epoch: number;
    senderLeafIndex: number;
    addPackages: string[];
    removedLeaves: number[];
    hasPath: boolean;
  }

  /** What one device's client holds for a channel (`mls-group:{channelId}`). */
  interface LocalGroupView {
    genesisVersion: number;
    groupId: string;
    version: number;
    epoch: number;
    transcript: string;
    members: MlsGroupMember[];
    directoryHeads: DirectoryHead[];
    /** Encoded like the client stores it, so a refused commit leaves it untouched. */
    state: string;
  }

  interface ClientGroupModules {
    mls: {
      generateMemberPackage(deviceId: string): Promise<MemberPackageMaterial>;
      readMemberPackage(encoded: string): { identity: string | null; signatureKey: string };
      groupLeaves(state: ClientState): Array<{ leafIndex: number; deviceId: string; signatureKey: string }>;
      treeAuthMap(state: ClientState, excludeLeaves?: readonly number[]): Map<string, string>;
      createChannelGroup(
        groupId: string,
        own: MemberPackageMaterial,
        others: readonly string[],
        authMap: ReadonlyMap<string, string>,
      ): Promise<ClientCommitResult>;
      commitChannelGroup(
        state: ClientState,
        change: { add: readonly string[]; removeLeaves: readonly number[]; authMap: ReadonlyMap<string, string> },
      ): Promise<ClientCommitResult>;
      decodeChannelCommit(encoded: string): ClientDecodedCommit;
      processChannelCommit(
        state: ClientState,
        encoded: string,
        expected: { addPackages: readonly string[]; removedLeaves: readonly number[] },
        authMap: ReadonlyMap<string, string>,
      ): Promise<{ newState: ClientState }>;
      joinChannelGroup(welcome: string, own: MemberPackageMaterial, authMap: ReadonlyMap<string, string>): Promise<ClientState>;
      assertChannelGroup(state: ClientState, groupId: string, epoch: number): void;
      exportChannelKey(state: ClientState, groupId: string, version: number): Promise<Uint8Array>;
      encodeChannelGroupState(state: ClientState): string;
      decodeChannelGroupState(encoded: string): ClientState;
    };
    model: {
      assertEnvelopeStructure(channelId: string, envelope: MlsGroupCommit, decoded: ClientDecodedCommit, previous: LocalGroupView | null): void;
      assertTreeMatchesRoster(
        leaves: ReadonlyArray<{ leafIndex: number; deviceId: string; signatureKey: string }>,
        members: readonly MlsGroupMember[],
        authMap: ReadonlyMap<string, string>,
      ): void;
      nextRoster(
        current: readonly MlsGroupMember[],
        removed: readonly string[],
        added: ReadonlyArray<Pick<MlsGroupMember, 'deviceId' | 'userId'>>,
      ): MlsGroupMember[];
      genesisRoster(added: ReadonlyArray<Pick<MlsGroupMember, 'deviceId' | 'userId'>>): MlsGroupMember[];
      rosterUsers(members: ReadonlyArray<Pick<MlsGroupMember, 'userId'>>): string[];
    };
  }

  let clientGroupModules: Promise<ClientGroupModules> | null = null;
  function clientGroup(): Promise<ClientGroupModules> {
    clientGroupModules ??= Promise.all([
      import('../../../client/src/services/' + 'mls-crypto.ts'),
      import('../../../client/src/services/' + 'mls-group-model.ts'),
    ]).then(([mls, model]) => ({ mls, model }) as ClientGroupModules);
    return clientGroupModules;
  }

  /** `device` as the server returned it at registration: its identity key is the stored form. */
  function asGroupMember(
    cookie: string,
    userId: string,
    keys: ReturnType<typeof deviceFixture>,
    device: { id: string; identityKey: string },
  ): MemberDevice {
    return { id: device.id, userId, identityKey: device.identityKey, keys, cookie };
  }

  /** How a device's sync ended: up to date, not added yet, removed, unable to use what it got, or without access. */
  type GroupSyncOutcome = 'current' | 'waiting' | 'removed' | 'unreadable' | 'gone';

  interface GroupSubmission {
    envelope: MlsGroupCommit;
    committer: MemberDevice;
    raw: Buffer;
    local: LocalGroupView;
    freshStart: boolean;
    response: Response | null;
    /** How every other device's sync ended after the commit was accepted. */
    outcomes: Map<string, GroupSyncOutcome>;
  }

  /**
   * One channel's continuous group as its devices' clients see it. Every
   * device keeps its own local view, catches up from the server's commit log
   * and joins from the Welcome of the envelope that added it.
   */
  class ChannelGroup {
    readonly devices = new Map<string, MemberDevice>();
    readonly local = new Map<string, LocalGroupView>();
    /** The package each device last published and that no commit used yet. */
    readonly published = new Map<string, { packageId: string; material: MemberPackageMaterial; signature: string }>();
    /** Private material of every published package, by package id, for joining. */
    readonly materials = new Map<string, MemberPackageMaterial>();
    /** Devices that do not sync after a commit until a test syncs them. */
    readonly offline = new Set<string>();
    /** The key of each version; every device that derives it must agree. */
    readonly keys = new Map<number, Buffer>();
    /** Latest accepted version. */
    version = 0;

    constructor(readonly channelId: string) {}

    key(version = this.version): Buffer {
      const key = this.keys.get(version);
      assert.ok(key, `no device derived the key of version ${version}`);
      return key;
    }

    async state(device: MemberDevice): Promise<any> {
      const response = await request(`/api/channels/${this.channelId}/key-recipients`, { cookie: device.cookie });
      assert.equal(response.status, 200);
      return response.json();
    }

    /** POST /mls/group/packages with a package made by the client (or a given one). */
    async publish(device: MemberDevice, options: { rejoin?: boolean; material?: MemberPackageMaterial } = {}) {
      const { mls } = await clientGroup();
      this.devices.set(device.id, device);
      const material = options.material ?? await mls.generateMemberPackage(device.id);
      const packageId = randomUUID();
      const signature = signDevicePayload(device.keys, serializeMlsMemberPackage(this.channelId, {
        deviceId: device.id, packageId, keyPackage: material.publicPackage,
      }));
      const response = await request(`/api/channels/${this.channelId}/mls/group/packages`, {
        method: 'POST',
        cookie: device.cookie,
        body: { packageId, keyPackage: material.publicPackage, signature, ...(options.rejoin ? { rejoin: true } : {}) },
      });
      if (response.status === 201 || response.status === 200) {
        this.published.set(device.id, { packageId, material, signature });
        this.materials.set(packageId, material);
      }
      return response;
    }

    /** The entry a commit adds for this device's published package. */
    entry(device: MemberDevice): MlsMemberPackage {
      const pkg = this.published.get(device.id);
      assert.ok(pkg, `${device.id} has no unused package`);
      return {
        deviceId: device.id,
        userId: device.userId,
        identityKey: device.identityKey,
        packageId: pkg.packageId,
        keyPackage: pkg.material.publicPackage,
        signature: pkg.signature,
      };
    }

    /** Entries to add: as GET /mls/group/packages lists them, which must be what each device published. */
    async additions(viewer: MemberDevice, devices: readonly MemberDevice[]): Promise<MlsMemberPackage[]> {
      if (devices.length === 0) return [];
      const response = await request(`/api/channels/${this.channelId}/mls/group/packages`, { cookie: viewer.cookie });
      assert.equal(response.status, 200);
      const listed = await json<MlsMemberPackage[]>(response);
      return devices.map((device) => {
        this.devices.set(device.id, device);
        const own = this.entry(device);
        const entry = listed.find((candidate) => candidate.deviceId === device.id);
        if (entry) assert.deepEqual(entry, own);
        return entry ?? own;
      });
    }

    /**
     * A new group: the creator at leaf 0 and the given devices added by its
     * genesis commit. Devices without an unused package publish one first.
     */
    async create(
      creator: MemberDevice,
      others: readonly MemberDevice[] = [],
      options: { freshStart?: boolean; post?: boolean; welcome?: (welcome: string) => string } = {},
    ): Promise<GroupSubmission> {
      const { mls, model } = await clientGroup();
      for (const device of [creator, ...others]) {
        this.devices.set(device.id, device);
        if (!this.published.has(device.id)) assert.equal((await this.publish(device)).status, 201);
      }
      const state = await this.state(creator);
      const version: number = state.nextVersion;
      const added = await this.additions(creator, [creator, ...others]);
      const authMap = new Map(added.map((entry) => [entry.deviceId, mls.readMemberPackage(entry.keyPackage).signatureKey]));
      const groupId = mlsGroupId(this.channelId, version);
      const result = await mls.createChannelGroup(
        groupId,
        this.published.get(creator.id)!.material,
        added.slice(1).map((entry) => entry.keyPackage),
        authMap,
      );
      const members = model.genesisRoster(added);
      mls.assertChannelGroup(result.newState, groupId, 1);
      model.assertTreeMatchesRoster(mls.groupLeaves(result.newState), members, authMap);
      // As the client links a migrated channel's first group: to the signed
      // envelope of the active group protocol 3 version.
      let previousTranscript: string = state.group?.transcript ?? '0'.repeat(64);
      if (!state.group && state.protocolVersion === 3 && state.currentVersion > 0) {
        const legacy = await request(`/api/channels/${this.channelId}/mls/epochs/${state.currentVersion}`, { cookie: creator.cookie });
        assert.equal(legacy.status, 200);
        previousTranscript = (await json<{ transcript: string }>(legacy)).transcript;
      }
      return this.submit(creator, result, {
        channelId: this.channelId,
        version,
        previousVersion: state.currentVersion,
        previousTranscript,
        groupId,
        epoch: 1,
        kind: 'create',
        welcome: options.welcome ? options.welcome(result.welcome) : result.welcome,
        added,
        removed: [],
        members,
      }, version, options);
    }

    /** Add, remove (a removed and re-added device rejoins) or, with neither, refresh the group key. */
    async commit(
      committer: MemberDevice,
      change: { add?: readonly MemberDevice[]; remove?: readonly MemberDevice[] } = {},
      options: { post?: boolean } = {},
    ): Promise<GroupSubmission> {
      const { mls, model } = await clientGroup();
      assert.equal(await this.sync(committer), 'current');
      const local = this.local.get(committer.id)!;
      const added = await this.additions(committer, change.add ?? []);
      const removed = (change.remove ?? []).map((device) => device.id).sort();
      const leafOf = new Map(local.members.map((member) => [member.deviceId, member.leafIndex]));
      const removeLeaves = removed.map((deviceId) => {
        const leaf = leafOf.get(deviceId);
        assert.notEqual(leaf, undefined, `${deviceId} is not in the group`);
        return leaf!;
      });
      const state = mls.decodeChannelGroupState(local.state);
      const authMap = mls.treeAuthMap(state, removeLeaves);
      for (const entry of added) authMap.set(entry.deviceId, mls.readMemberPackage(entry.keyPackage).signatureKey);
      const result = await mls.commitChannelGroup(state, { add: added.map((entry) => entry.keyPackage), removeLeaves, authMap });
      const members = model.nextRoster(local.members, removed, added);
      mls.assertChannelGroup(result.newState, local.groupId, local.epoch + 1);
      model.assertTreeMatchesRoster(mls.groupLeaves(result.newState), members, authMap);
      return this.submit(committer, result, {
        channelId: this.channelId,
        version: local.version + 1,
        previousVersion: local.version,
        previousTranscript: local.transcript,
        groupId: local.groupId,
        epoch: local.epoch + 1,
        kind: 'commit',
        welcome: result.welcome,
        added,
        removed,
        members,
      }, local.genesisVersion, options);
    }

    /** Sign the envelope with the committer's device key and send it (unless `post: false`). */
    private async submit(
      committer: MemberDevice,
      result: ClientCommitResult,
      fields: Omit<MlsGroupCommit, 'keyCommitment' | 'commit' | 'directoryHeads' | 'committerDeviceId' | 'signature'>,
      genesisVersion: number,
      options: { freshStart?: boolean; post?: boolean },
    ): Promise<GroupSubmission> {
      const { mls, model } = await clientGroup();
      const raw = Buffer.from(await mls.exportChannelKey(result.newState, fields.groupId, fields.version));
      const { db } = await import('../db/index.js');
      const { directoryHead } = await import('../services/directory.service.js');
      const envelope = this.sign(committer, {
        ...fields,
        keyCommitment: keyCommitmentOf(raw),
        commit: result.commit,
        directoryHeads: await Promise.all(model.rosterUsers(fields.members).map((userId) => directoryHead(db, userId))),
        committerDeviceId: committer.id,
      });
      const submission: GroupSubmission = {
        envelope,
        committer,
        raw,
        freshStart: Boolean(options.freshStart),
        local: {
          genesisVersion,
          groupId: envelope.groupId,
          version: envelope.version,
          epoch: envelope.epoch,
          transcript: groupTranscript(envelope),
          members: envelope.members,
          directoryHeads: envelope.directoryHeads,
          state: mls.encodeChannelGroupState(result.newState),
        },
        response: null,
        outcomes: new Map(),
      };
      if (options.post === false) return submission;
      submission.response = await this.send(committer, envelope, submission.freshStart);
      if (submission.response.status === 201) await this.accepted(submission);
      return submission;
    }

    sign(committer: MemberDevice, unsigned: Omit<MlsGroupCommit, 'signature'>): MlsGroupCommit {
      return { ...unsigned, signature: signDevicePayload(committer.keys, serializeMlsGroupCommit(unsigned)) };
    }

    send(committer: MemberDevice, envelope: MlsGroupCommit, freshStart = false): Promise<Response> {
      const freshStartSignature = signDevicePayload(committer.keys, serializeChannelKeyFreshStart({
        channelId: envelope.channelId, keyVersion: envelope.version, keyCommitment: envelope.keyCommitment, deviceId: committer.id,
      }));
      return request(`/api/channels/${envelope.channelId}/mls/group/${freshStart ? 'fresh-start' : 'commits'}`, {
        method: 'POST',
        cookie: committer.cookie,
        body: freshStart ? { commit: envelope, freshStartSignature } : { commit: envelope },
      });
    }

    /** The committer adopts its own state; every other online device syncs. */
    async accepted(submission: GroupSubmission): Promise<void> {
      const { envelope } = submission;
      this.version = envelope.version;
      this.recordKey(envelope.version, submission.raw);
      this.local.set(submission.committer.id, submission.local);
      for (const entry of envelope.added) this.published.delete(entry.deviceId);
      for (const device of this.devices.values()) {
        if (device.id === submission.committer.id || this.offline.has(device.id)) continue;
        if (!this.local.has(device.id) && !envelope.members.some((member) => member.deviceId === device.id)) continue;
        submission.outcomes.set(device.id, await this.sync(device));
      }
    }

    recordKey(version: number, raw: Buffer): void {
      const known = this.keys.get(version);
      if (known) assert.deepEqual(raw, known, `every device derives the same key for version ${version}`);
      else this.keys.set(version, Buffer.from(raw));
    }

    /** One accepted envelope from the log, checked like a client checks it. */
    async record(device: MemberDevice, version: number): Promise<{ version: number; transcript: string; envelope: MlsGroupCommit }> {
      const response = await request(`/api/channels/${this.channelId}/mls/group/commits?after=${version - 1}&limit=1`, { cookie: device.cookie });
      assert.equal(response.status, 200);
      const records = await json<Array<{ version: number; transcript: string; envelope: MlsGroupCommit }>>(response);
      assert.deepEqual(records.map((record) => record.version), [version]);
      this.checkRecord(records[0]);
      return records[0];
    }

    checkRecord(record: { version: number; transcript: string; envelope: MlsGroupCommit }): void {
      const { signature, ...unsigned } = record.envelope;
      assert.equal(record.envelope.version, record.version);
      assert.equal(record.transcript, groupTranscript(record.envelope));
      const committer = this.devices.get(record.envelope.committerDeviceId);
      assert.ok(committer, 'the committer is a device of this channel');
      assert.equal(verifyDevicePayload(committer.identityKey, serializeMlsGroupCommit(unsigned), signature), true);
    }

    /** The signature key of a member package after checking who signed it. */
    async verifiedPackage(entry: Pick<MlsMemberPackage, 'deviceId' | 'identityKey' | 'packageId' | 'keyPackage' | 'signature'>): Promise<string> {
      const { mls } = await clientGroup();
      assert.equal(verifyDevicePayload(entry.identityKey, serializeMlsMemberPackage(this.channelId, entry), entry.signature), true);
      const known = this.devices.get(entry.deviceId);
      if (known) assert.equal(entry.identityKey, known.identityKey);
      const info = mls.readMemberPackage(entry.keyPackage);
      assert.equal(info.identity, entry.deviceId);
      return info.signatureKey;
    }

    /**
     * Join from the Welcome of the envelope that added the device, with the
     * roster of that version (GET /mls/group/members). False when the
     * Welcome cannot be used: the client then asks to be added again.
     */
    async joinAt(device: MemberDevice, record: { version: number; transcript: string; envelope: MlsGroupCommit }): Promise<boolean> {
      const { mls, model } = await clientGroup();
      const { envelope } = record;
      model.assertEnvelopeStructure(this.channelId, envelope, mls.decodeChannelCommit(envelope.commit), null);
      const index = envelope.added.findIndex((entry) => entry.deviceId === device.id);
      assert.ok(index >= 0, 'the envelope adds this device');
      // The creator has no Welcome; without its own state it starts over.
      if (envelope.kind === 'create' && index === 0) return false;
      const material = this.materials.get(envelope.added[index].packageId);
      assert.ok(material, 'the device keeps the package it was added with');
      const response = await request(`/api/channels/${this.channelId}/mls/group/members?version=${envelope.version}`, { cookie: device.cookie });
      assert.equal(response.status, 200);
      const rows = await json<Array<MlsMemberPackage & { leafIndex: number }>>(response);
      assert.deepEqual(
        rows.map((row) => [row.deviceId, row.userId, row.leafIndex]),
        envelope.members.map((member) => [member.deviceId, member.userId, member.leafIndex]),
      );
      const authMap = new Map<string, string>();
      for (const row of rows) authMap.set(row.deviceId, await this.verifiedPackage(row));
      let state: ClientState;
      try {
        state = await mls.joinChannelGroup(envelope.welcome, material, authMap);
        mls.assertChannelGroup(state, envelope.groupId, envelope.epoch);
        model.assertTreeMatchesRoster(mls.groupLeaves(state), envelope.members, authMap);
      } catch {
        return false;
      }
      const raw = Buffer.from(await mls.exportChannelKey(state, envelope.groupId, envelope.version));
      assert.equal(keyCommitmentOf(raw), envelope.keyCommitment);
      this.recordKey(envelope.version, raw);
      this.local.set(device.id, {
        genesisVersion: envelope.version - envelope.epoch + 1,
        groupId: envelope.groupId,
        version: envelope.version,
        epoch: envelope.epoch,
        transcript: record.transcript,
        members: envelope.members,
        directoryHeads: envelope.directoryHeads,
        state: mls.encodeChannelGroupState(state),
      });
      return true;
    }

    /** What a client does on reconnect: join if it was added, then process the log in order. */
    async sync(device: MemberDevice): Promise<GroupSyncOutcome> {
      const { mls, model } = await clientGroup();
      this.devices.set(device.id, device);
      for (let round = 0; round < 64; round++) {
        const start = this.local.get(device.id);
        if (!start) {
          const response = await request(`/api/channels/${this.channelId}/key-recipients`, { cookie: device.cookie });
          if (response.status !== 200) return 'gone';
          const state = await json<any>(response);
          if (!state.ownMembership) return 'waiting';
          if (!await this.joinAt(device, await this.record(device, state.ownMembership.joinedVersion))) return 'unreadable';
          continue;
        }
        const response = await request(`/api/channels/${this.channelId}/mls/group/commits?after=${start.version}`, { cookie: device.cookie });
        if (response.status === 401 || response.status === 404) {
          this.local.delete(device.id);
          return 'gone';
        }
        assert.equal(response.status, 200);
        const records = await json<Array<{ version: number; transcript: string; envelope: MlsGroupCommit }>>(response);
        if (records.length === 0) return 'current';
        for (const record of records) {
          const local = this.local.get(device.id)!;
          this.checkRecord(record);
          assert.equal(record.version, local.version + 1);
          const { envelope } = record;
          const decoded = mls.decodeChannelCommit(envelope.commit);
          model.assertEnvelopeStructure(this.channelId, envelope, decoded, local);
          if (envelope.kind === 'create' || envelope.removed.includes(device.id)) {
            // Removed, or the group was replaced: keys already derived stay.
            this.local.delete(device.id);
            if (!envelope.added.some((entry) => entry.deviceId === device.id)) return 'removed';
            if (!await this.joinAt(device, record)) return 'unreadable';
            break;
          }
          const state = mls.decodeChannelGroupState(local.state);
          const authMap = mls.treeAuthMap(state, decoded.removedLeaves);
          for (const entry of envelope.added) authMap.set(entry.deviceId, await this.verifiedPackage(entry));
          let next: ClientState;
          try {
            next = (await mls.processChannelCommit(state, envelope.commit, decoded, authMap)).newState;
            mls.assertChannelGroup(next, envelope.groupId, envelope.epoch);
          } catch {
            return 'unreadable';
          }
          model.assertTreeMatchesRoster(mls.groupLeaves(next), envelope.members, authMap);
          const raw = Buffer.from(await mls.exportChannelKey(next, envelope.groupId, envelope.version));
          assert.equal(keyCommitmentOf(raw), envelope.keyCommitment);
          this.recordKey(envelope.version, raw);
          this.local.set(device.id, {
            genesisVersion: local.genesisVersion,
            groupId: envelope.groupId,
            version: envelope.version,
            epoch: envelope.epoch,
            transcript: record.transcript,
            members: envelope.members,
            directoryHeads: envelope.directoryHeads,
            state: mls.encodeChannelGroupState(next),
          });
        }
      }
      throw new Error('the commit log did not end');
    }
  }

  /** A message write at a key version, as POST /messages takes it. */
  function groupMessage(device: MemberDevice, channelId: string, key: Buffer, keyVersion: number, text = 'group message') {
    return request(`/api/channels/${channelId}/messages`, {
      method: 'POST',
      cookie: device.cookie,
      body: encryptedMessage(channelId, device.userId, device.id, device.keys.signingPrivateKey, key, text, undefined, keyVersion).body,
    });
  }

  /** Status and refusal code of a response. */
  async function refusal(response: Response): Promise<[number, string | undefined]> {
    return [response.status, (await response.json().catch(() => ({})) as { code?: string }).code];
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
    const rawBody = Buffer.isBuffer(options.body) ? options.body : null;
    if (options.body !== undefined) headers['Content-Type'] = options.contentType ?? (rawBody ? 'application/octet-stream' : 'application/json');
    const send = () => fetch(`${baseUrl}${path}`, {
      method: options.method || 'GET',
      headers,
      body: options.body === undefined
        ? undefined
        : rawBody
          ? new Uint8Array(rawBody)
          : JSON.stringify(options.body),
    });
    let response = await send();
    if (response.status === 428 && options.cookie && credentials.has(options.cookie)) {
      // Like the app: confirm the identity for the purpose the server names, then resend.
      const required = await response.clone().json().catch(() => null) as { error?: string; purpose?: string } | null;
      if (required?.error === 'STEP_UP_REQUIRED' && required.purpose) {
        const purpose = required.purpose;
        const optionsResponse = await request('/api/auth/step-up/options', { method: 'POST', cookie: options.cookie, body: { purpose } });
        if (optionsResponse.status === 200) {
          const challenge = await json<any>(optionsResponse);
          const verified = await request('/api/auth/step-up/verify', {
            method: 'POST', cookie: options.cookie, body: { id: challenge.id, purpose, password: credentials.get(options.cookie)!.password },
          });
          assert.equal(verified.status, 200);
          headers['X-Alparts-Step-Up'] = (await json<any>(verified)).token;
          response = await send();
        }
      }
    }
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

/** An edit (v5): the edited message is named by its author and the idempotency key it was sent with. */
function encryptedEdit(
  channelId: string,
  messageId: string,
  target: SignedEventReference,
  authorId: string,
  deviceId: string,
  privateKey: import('node:crypto').KeyObject,
  key: Buffer,
  plaintext: string,
) {
  return encryptedBoundEvent({
    type: 'edit', channelId, refMessageId: messageId, refBinding: target, authorId, deviceId, privateKey, key, plaintext,
  });
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

/**
 * A forum event. The first message of a post keeps the v4 layout; every
 * event inside a post is v5, so it also names its post (and what it quotes,
 * edits or deletes) by author and signed idempotency key. Deletes carry no
 * ciphertext, like other deletes.
 */
function encryptedForumEvent(input: {
  type: 'message' | 'edit' | 'delete';
  channelId: string;
  refMessageId: string | null;
  postId: string | null;
  /** The signed pairs of what refMessageId and postId name (required when they are set). */
  refBinding?: SignedEventReference;
  postBinding?: SignedEventReference;
  authorId: string;
  deviceId: string;
  privateKey: import('node:crypto').KeyObject;
  key: Buffer;
  plaintext: string;
}) {
  if (input.refMessageId !== null || input.postId !== null) {
    if ((input.refMessageId !== null && !input.refBinding) || (input.postId !== null && !input.postBinding)) {
      throw new Error('a forum event inside a post needs the signed pairs of what it names');
    }
    return encryptedBoundEvent({
      ...input,
      refBinding: input.refMessageId !== null ? input.refBinding! : null,
      post: { postId: input.postId, postBinding: input.postId !== null ? input.postBinding! : null },
    });
  }
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

/**
 * A v5 event: what refMessageId and (in a forum) postId name is signed as
 * those events' authors signed them. Deletes carry no ciphertext.
 */
function encryptedBoundEvent(input: {
  type: 'message' | 'edit' | 'delete';
  channelId: string;
  refMessageId: string | null;
  refBinding: SignedEventReference | null;
  /** Forum events only; left out in other channels. */
  post?: { postId: string | null; postBinding: SignedEventReference | null };
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
    refBinding: input.refBinding,
    ...(input.post ? { postId: input.post.postId, postBinding: input.post.postBinding } : {}),
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
      ...(input.type === 'message' && input.refMessageId ? { refMessageId: input.refMessageId } : {}),
      ...(input.post?.postId ? { postId: input.post.postId } : {}),
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
  /** The message's signed idempotency key; null signs the older unbound layout, which the server refuses. */
  messageIdempotencyKey: string | null;
}) {
  const envelope: Omit<SignedAttachmentEnvelope, 'messageIdempotencyKey'> = {
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
  const signed = input.messageIdempotencyKey === null
    ? JSON.stringify([
      2, envelope.type, envelope.uploadId, envelope.messageId, envelope.channelId, envelope.authorId, envelope.deviceId,
      envelope.keyVersion, envelope.filenameEnc, envelope.mimeType, envelope.wrappedKey, envelope.noncePrefix,
      envelope.plaintextSize, envelope.chunkCount,
    ])
    : serializeAttachmentEnvelope({ ...envelope, messageIdempotencyKey: input.messageIdempotencyKey });
  const signature = sign('sha256', Buffer.from(signed), {
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

function signDevicePayload(keys: ReturnType<typeof deviceFixture>, payload: string): string {
  return sign('sha256', Buffer.from(payload), { key: keys.signingPrivateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
}

function verifyDevicePayload(identityKey: string, payload: string, signature: string): boolean {
  const key = createPublicKey({ key: JSON.parse(identityKey).signingKey, format: 'jwk' });
  return verify('sha256', Buffer.from(payload), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64'));
}

/** base64url(SHA-256(key)), as envelopes and recovery records name a key. */
function keyCommitmentOf(raw: Buffer): string {
  return createHash('sha256').update(raw).digest('base64url');
}

/** The transcript that names an accepted version. */
function groupTranscript(envelope: MlsGroupCommit): string {
  return createHash('sha256').update(serializeMlsGroupCommit(envelope)).digest('hex');
}

/**
 * A Welcome the server accepts (it names the right new members) whose
 * encrypted group information nobody can open. Only the committer chose it.
 */
function poisonWelcome(welcome: string): string {
  const message = decodeMlsMessage(Buffer.from(welcome, 'base64'), 0)![0];
  assert.equal(message.wireformat, 'mls_welcome');
  if (message.wireformat !== 'mls_welcome') throw new Error('not a Welcome');
  const encryptedGroupInfo = Uint8Array.from(message.welcome.encryptedGroupInfo);
  encryptedGroupInfo[0] ^= 0xff;
  return Buffer.from(encodeMlsMessage({ ...message, welcome: { ...message.welcome, encryptedGroupInfo } })).toString('base64');
}

/** A member package like the client's, but valid since `validFor` seconds ago (to stand in for a package published earlier). */
async function earlierMemberPackage(deviceId: string, validFor: bigint) {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const pair = await generateKeyPackage(
    { credentialType: 'basic', identity: new TextEncoder().encode(deviceId) },
    { versions: ['mls10'], ciphersuites: [MLS_CIPHERSUITE], extensions: [], proposals: [], credentials: ['basic'] },
    { notBefore: now - validFor, notAfter: now + 604800n },
    [],
    await getCiphersuiteImpl(getCiphersuiteFromName(MLS_CIPHERSUITE)),
  );
  const base64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');
  return {
    publicPackage: base64(encodeMlsMessage({ version: 'mls10', wireformat: 'mls_key_package', keyPackage: pair.publicPackage })),
    privatePackage: {
      initPrivateKey: base64(pair.privatePackage.initPrivateKey),
      hpkePrivateKey: base64(pair.privatePackage.hpkePrivateKey),
      signaturePrivateKey: base64(pair.privatePackage.signaturePrivateKey),
    },
  };
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
