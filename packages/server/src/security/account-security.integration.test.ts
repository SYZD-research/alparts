import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import {
  randomBytes,
  randomUUID,
  generateKeyPairSync,
  createHash,
  createPublicKey,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';
import { after, before, describe, it } from 'node:test';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  canonicalActionBody,
  mlsGroupId,
  serializeChannelKeyFreshStart,
  serializeDeviceChallengeProof,
  serializeDeviceDecision,
  serializeChannelKeyWrap,
  serializeMessageEnvelope,
  serializeMessageAad,
  serializeMlsGroupCommit,
  serializeMlsMemberPackage,
  type DirectoryHead,
  type MlsGroupCommit,
  type MlsGroupMember,
  type MlsMemberPackage,
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
/** Whether the device with this identity key signed `value`. */
const signedBy = (identityKey: string, value: string, signed: string) =>
  verify(
    'sha256',
    Buffer.from(value),
    { key: createPublicKey({ key: JSON.parse(identityKey).signingKey, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
    Buffer.from(signed, 'base64'),
  );
/** base64url(SHA-256(key)): how envelopes and recovery records name a key. */
const keyCommitmentOf = (raw: Uint8Array) => hash(raw).toString('base64url');
/** The transcript that names an accepted group version. */
const groupTranscript = (envelope: Omit<MlsGroupCommit, 'signature'>) =>
  hash(serializeMlsGroupCommit(envelope)).toString('hex');
// The client's own group adapter and envelope rules drive every group change.
const clientMls = () => import('../../../client/src/services/' + 'mls-crypto.ts');
const clientGroupModel = () => import('../../../client/src/services/' + 'mls-group-model.ts');
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
  // The channel's active group version, its key and that key's commitment.
  // Tests run in order and each continues from the version the last one left.
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
  // Group protocol 3 channels as 0023 (continuous groups) finds them.
  const migratedChannel = randomUUID();
  const pendingOnlyChannel = randomUUID();
  let legacyBeforeGroups: { epochs: unknown[]; keyRotationRequired: boolean };

  // === The channel's continuous group as each device's client holds it ===

  /** A device with its own session and signing key. */
  interface GroupDevice {
    id: string;
    userId: string;
    identityKey: string;
    signingKey: KeyObject;
    auth: string;
  }
  /** `mls-group:{channelId}` of one device, plus every key it derived. */
  interface LocalGroup {
    genesisVersion: number;
    groupId: string;
    version: number;
    epoch: number;
    transcript: string;
    members: MlsGroupMember[];
    directoryHeads: DirectoryHead[];
    state: string;
    keys: Map<number, Uint8Array>;
  }
  interface GroupRecord {
    version: number;
    transcript: string;
    envelope: MlsGroupCommit;
  }
  /** A signed envelope and what its committer keeps once the server accepts it. */
  interface SealedCommit {
    envelope: MlsGroupCommit;
    raw: Uint8Array;
    local: LocalGroup;
  }
  const localGroups = new Map<string, LocalGroup>();
  /** Each device's latest published, not yet used package (private material included). */
  const publishedPackages = new Map<string, { packageId: string; material: any }>();
  const identityKeys = new Map<string, string>();
  function groupDevice(device: { id: string; identityKey: string }, owner: string, keys: KeyObject, auth: string): GroupDevice {
    identityKeys.set(device.id, device.identityKey);
    return { id: device.id, userId: owner, identityKey: device.identityKey, signingKey: keys, auth };
  }
  const firstMember = () => groupDevice(first, userId, firstKeys.privateKey, cookie);
  const secondMember = () => groupDevice(second, userId, secondKeys.privateKey, secondCookie);
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
    return stepUpFor(`${method} ${path} ${hash(canonicalActionBody(body)).toString('base64url')}`, auth);
  }
  async function stepUpFor(purpose: string, auth = cookie) {
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
  /** Like the app: send, then confirm the identity for the purpose the server names. */
  async function confirmedRequest(path: string, body: unknown, method = 'POST', auth = cookie) {
    const first = await request(path, body, auth, method);
    if (first.status !== 428) return first;
    const { purpose } = await first.json() as { purpose: string };
    return request(path, body, auth, method, await stepUpFor(purpose, auth));
  }
  /** Asks for a registration code and reads it from the development outbox. */
  async function emailCode(email: string, inviteToken: string): Promise<string> {
    assert.deepEqual(await json(await request('/api/auth/register/code', { email, inviteToken }, ''), 202), { required: true });
    const { developmentEmails } = await import('../services/email.service.js');
    const code = [...developmentEmails()].reverse().find((message) => message.to === email)?.text.match(/\b(\d{6})\b/)?.[1];
    assert.ok(code, `no code was mailed to ${email}`);
    return code;
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
  /** A message from `device` (the first device by default) under the active version's key unless told otherwise. */
  async function encryptedMessage(
    options: { device?: GroupDevice; keyVersion?: number; rawKey?: Uint8Array } = {},
  ) {
    const device = options.device ?? firstMember();
    const envelope = {
      channelId,
      authorId: device.userId,
      deviceId: device.id,
      keyVersion: options.keyVersion ?? version,
      idempotencyKey: randomUUID(),
      refMessageId: null,
      broadcastMention: false,
      type: 'message' as const,
    };
    const nonce = randomBytes(12);
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      (options.rawKey ?? key) as Uint8Array<ArrayBuffer>,
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
      signature: signature(device.signingKey, serializeMessageEnvelope(body)),
    };
  }
  /** Status and refusal code of a response. */
  async function refusal(response: Response): Promise<[number, string | undefined]> {
    return [response.status, ((await response.json().catch(() => ({}))) as { code?: string }).code];
  }
  /** The body of POST /mls/group/packages: a package signed by its device for this channel. */
  function memberPackageBody(device: GroupDevice, keyPackage: string, packageId: string = randomUUID()) {
    return {
      packageId,
      keyPackage,
      signature: signature(
        device.signingKey,
        serializeMlsMemberPackage(channelId, { deviceId: device.id, packageId, keyPackage }),
      ),
    };
  }
  /** Publish a fresh package made by the client, so a member can add this device. */
  async function publishPackage(device: GroupDevice) {
    const material = await (await clientMls()).generateMemberPackage(device.id);
    const body = memberPackageBody(device, material.publicPackage);
    const response = await request(`/api/channels/${channelId}/mls/group/packages`, body, device.auth);
    if (response.status === 201) publishedPackages.set(device.id, { packageId: body.packageId, material });
    return response;
  }
  /** The signature key of a package, after checking that its device signed it for this channel. */
  async function verifiedPackageKey(
    entry: Pick<MlsMemberPackage, 'deviceId' | 'identityKey' | 'packageId' | 'keyPackage' | 'signature'>,
  ): Promise<string> {
    const known = identityKeys.get(entry.deviceId);
    if (known) assert.equal(entry.identityKey, known);
    assert.equal(signedBy(entry.identityKey, serializeMlsMemberPackage(channelId, entry), entry.signature), true);
    const info = (await clientMls()).readMemberPackage(entry.keyPackage);
    assert.equal(info.identity, entry.deviceId);
    return info.signatureKey;
  }
  /** Packages to add, as GET /mls/group/packages lists them: exactly what each device published. */
  async function listedPackages(viewer: GroupDevice, devices: readonly GroupDevice[]): Promise<MlsMemberPackage[]> {
    const listed = (await json(
      await request(`/api/channels/${channelId}/mls/group/packages`, undefined, viewer.auth),
    )) as MlsMemberPackage[];
    return devices.map((device) => {
      const entry = listed.find((candidate) => candidate.deviceId === device.id);
      assert.ok(entry, `${device.id} waits to be added`);
      assert.equal(entry.packageId, publishedPackages.get(device.id)?.packageId);
      return entry;
    });
  }
  /** Sign an envelope for a commit the committer made, and what it keeps once accepted. */
  async function sealCommit(
    committer: GroupDevice,
    result: { newState: unknown; commit: string; welcome: string },
    fields: Omit<MlsGroupCommit, 'keyCommitment' | 'commit' | 'welcome' | 'directoryHeads' | 'committerDeviceId' | 'signature'>,
    earlierKeys: ReadonlyMap<number, Uint8Array> = new Map(),
  ): Promise<SealedCommit> {
    const mls = await clientMls();
    const model = await clientGroupModel();
    const { db } = await import('../db/index.js');
    const { directoryHead } = await import('../services/directory.service.js');
    const raw = new Uint8Array(await mls.exportChannelKey(result.newState, fields.groupId, fields.version));
    const unsigned = {
      ...fields,
      keyCommitment: keyCommitmentOf(raw),
      commit: result.commit,
      welcome: result.welcome,
      directoryHeads: await Promise.all(model.rosterUsers(fields.members).map((id: string) => directoryHead(db, id))),
      committerDeviceId: committer.id,
    };
    const envelope = { ...unsigned, signature: signature(committer.signingKey, serializeMlsGroupCommit(unsigned)) };
    return {
      envelope,
      raw,
      local: {
        genesisVersion: envelope.version - envelope.epoch + 1,
        groupId: envelope.groupId,
        version: envelope.version,
        epoch: envelope.epoch,
        transcript: groupTranscript(envelope),
        members: envelope.members,
        directoryHeads: envelope.directoryHeads,
        state: mls.encodeChannelGroupState(result.newState),
        keys: new Map([...earlierKeys, [envelope.version, raw]]),
      },
    };
  }
  /** A commit by a member from its own state: add, remove, or with neither refresh the group key. */
  async function groupCommit(
    committer: GroupDevice,
    change: { add?: GroupDevice[]; remove?: string[] } = {},
  ): Promise<SealedCommit> {
    const mls = await clientMls();
    const model = await clientGroupModel();
    const own = localGroups.get(committer.id);
    assert.ok(own, 'the committer holds the group');
    const added = change.add?.length ? await listedPackages(committer, change.add) : [];
    const removed = [...(change.remove ?? [])].sort();
    const leafOf = new Map(own.members.map((member) => [member.deviceId, member.leafIndex]));
    const removeLeaves = removed.map((deviceId) => leafOf.get(deviceId)!);
    const state = mls.decodeChannelGroupState(own.state);
    const authMap = mls.treeAuthMap(state, removeLeaves);
    for (const entry of added) authMap.set(entry.deviceId, await verifiedPackageKey(entry));
    const result = await mls.commitChannelGroup(state, {
      add: added.map((entry) => entry.keyPackage),
      removeLeaves,
      authMap,
    });
    const members = model.nextRoster(own.members, removed, added);
    mls.assertChannelGroup(result.newState, own.groupId, own.epoch + 1);
    model.assertTreeMatchesRoster(mls.groupLeaves(result.newState), members, authMap);
    return sealCommit(committer, result, {
      channelId,
      version: own.version + 1,
      previousVersion: own.version,
      previousTranscript: own.transcript,
      groupId: own.groupId,
      epoch: own.epoch + 1,
      kind: 'commit',
      added,
      removed,
      members,
    }, own.keys);
  }
  /** Send a sealed commit with the committer's session; on acceptance it adopts its new state. */
  async function submitCommit(committer: GroupDevice, sealed: SealedCommit) {
    const response = await request(
      `/api/channels/${channelId}/mls/group/commits`,
      { commit: sealed.envelope },
      committer.auth,
    );
    if (response.status === 201) localGroups.set(committer.id, sealed.local);
    return response;
  }
  /** The active version moves to an accepted commit. */
  function activate(sealed: SealedCommit) {
    version = sealed.envelope.version;
    key = sealed.raw;
    commitment = sealed.envelope.keyCommitment;
  }
  /** A record from the commit log, checked like a client checks it before using it. */
  function assertAcceptedRecord(record: GroupRecord) {
    const { signature: signed, ...unsigned } = record.envelope;
    assert.equal(record.version, record.envelope.version);
    assert.equal(record.transcript, groupTranscript(unsigned));
    const committerKey = identityKeys.get(record.envelope.committerDeviceId);
    assert.ok(committerKey, 'the committer is a known device');
    assert.equal(signedBy(committerKey, serializeMlsGroupCommit(unsigned), signed), true);
  }
  /**
   * What a device that was added does: read the envelope that added it and
   * that version's roster, verify each member's package, join from the
   * Welcome and derive the version's key.
   */
  async function joinFromLog(device: GroupDevice): Promise<Uint8Array> {
    const mls = await clientMls();
    const model = await clientGroupModel();
    const state = await json(await request(`/api/channels/${channelId}/key-recipients`, undefined, device.auth));
    const joined: number = state.ownMembership.joinedVersion;
    const records = (await json(
      await request(`/api/channels/${channelId}/mls/group/commits?after=${joined - 1}&limit=1`, undefined, device.auth),
    )) as GroupRecord[];
    assert.deepEqual(records.map((record) => record.version), [joined]);
    const [record] = records;
    assertAcceptedRecord(record);
    const { envelope } = record;
    model.assertEnvelopeStructure(channelId, envelope, mls.decodeChannelCommit(envelope.commit), null);
    const rows = (await json(
      await request(`/api/channels/${channelId}/mls/group/members?version=${joined}`, undefined, device.auth),
    )) as Array<MlsMemberPackage & { leafIndex: number }>;
    assert.deepEqual(
      rows.map((row) => [row.deviceId, row.userId, row.leafIndex]),
      envelope.members.map((member) => [member.deviceId, member.userId, member.leafIndex]),
    );
    const authMap = new Map<string, string>();
    for (const row of rows) authMap.set(row.deviceId, await verifiedPackageKey(row));
    const material = publishedPackages.get(device.id)?.material;
    assert.equal(envelope.added.find((entry) => entry.deviceId === device.id)?.packageId, publishedPackages.get(device.id)?.packageId);
    const joinedState = await mls.joinChannelGroup(envelope.welcome, material, authMap);
    mls.assertChannelGroup(joinedState, envelope.groupId, envelope.epoch);
    model.assertTreeMatchesRoster(mls.groupLeaves(joinedState), envelope.members, authMap);
    const raw = new Uint8Array(await mls.exportChannelKey(joinedState, envelope.groupId, envelope.version));
    assert.equal(keyCommitmentOf(raw), envelope.keyCommitment);
    publishedPackages.delete(device.id);
    localGroups.set(device.id, {
      genesisVersion: envelope.version - envelope.epoch + 1,
      groupId: envelope.groupId,
      version: envelope.version,
      epoch: envelope.epoch,
      transcript: record.transcript,
      members: envelope.members,
      directoryHeads: envelope.directoryHeads,
      state: mls.encodeChannelGroupState(joinedState),
      keys: new Map([[envelope.version, raw]]),
    });
    return raw;
  }
  /** What a member that was offline does: process the log in order from its last version. */
  async function catchUp(device: GroupDevice): Promise<GroupRecord[]> {
    const mls = await clientMls();
    const model = await clientGroupModel();
    const start = localGroups.get(device.id);
    assert.ok(start, 'the device holds the group');
    const records = (await json(
      await request(`/api/channels/${channelId}/mls/group/commits?after=${start.version}`, undefined, device.auth),
    )) as GroupRecord[];
    for (const record of records) {
      const local = localGroups.get(device.id)!;
      assertAcceptedRecord(record);
      const { envelope } = record;
      const decoded = mls.decodeChannelCommit(envelope.commit);
      model.assertEnvelopeStructure(channelId, envelope, decoded, local);
      assert.equal(envelope.removed.includes(device.id), false);
      const state = mls.decodeChannelGroupState(local.state);
      const authMap = mls.treeAuthMap(state, decoded.removedLeaves);
      for (const entry of envelope.added) authMap.set(entry.deviceId, await verifiedPackageKey(entry));
      const { newState } = await mls.processChannelCommit(state, envelope.commit, decoded, authMap);
      mls.assertChannelGroup(newState, envelope.groupId, envelope.epoch);
      model.assertTreeMatchesRoster(mls.groupLeaves(newState), envelope.members, authMap);
      const raw = new Uint8Array(await mls.exportChannelKey(newState, envelope.groupId, envelope.version));
      assert.equal(keyCommitmentOf(raw), envelope.keyCommitment);
      localGroups.set(device.id, {
        ...local,
        version: envelope.version,
        epoch: envelope.epoch,
        transcript: record.transcript,
        members: envelope.members,
        directoryHeads: envelope.directoryHeads,
        state: mls.encodeChannelGroupState(newState),
        keys: new Map([...local.keys, [envelope.version, raw]]),
      });
    }
    return records;
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
        const entries = journal.entries;
        journal.entries = entries.slice(0, 14);
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
        // Through 0022, the last schema before continuous groups (0023).
        journal.entries = entries.slice(0, 23);
        assert.equal(journal.entries.at(-1).tag, '0022_email_verification');
        await writeFile(journalPath, JSON.stringify(journal));
        await migrate(drizzle(migrationClient), {
          migrationsFolder: oldBundle,
        });
        legacyBeforeGroups = {
          epochs: (await migrationClient.query(
            'SELECT version, status, protocol_version FROM channel_key_epochs WHERE channel_id = $1 ORDER BY version',
            [legacyChannel],
          )).rows,
          keyRotationRequired: (await migrationClient.query(
            'SELECT key_rotation_required FROM channels WHERE id = $1',
            [legacyChannel],
          )).rows[0].key_rotation_required,
        };
        // Group protocol 3 state: an active epoch with a pending successor
        // that one recipient already acknowledged, and a channel whose only
        // epoch is still pending. Neither channel is flagged yet.
        await migrationClient.query('INSERT INTO workspace_members (workspace_id,user_id) VALUES ($1,$2)', [
          legacyWorkspace,
          legacyUser,
        ]);
        await migrationClient.query(
          'INSERT INTO channels (id,workspace_id,name,key_rotation_required) VALUES ($1,$3,$4,false), ($2,$3,$5,false)',
          [migratedChannel, pendingOnlyChannel, legacyWorkspace, '移行中', '準備中'],
        );
        await migrationClient.query(
          "INSERT INTO channel_key_epochs (channel_id,version,protocol_version,status,key_commitment,distributor_device_id,activated_at) VALUES ($1,1,3,'active',$3,$4,now()), ($1,2,3,'pending',$3,$4,NULL), ($2,1,3,'pending',$3,$4,NULL)",
          [migratedChannel, pendingOnlyChannel, 'b'.repeat(43), legacyDevice],
        );
        await migrationClient.query(
          'INSERT INTO channel_key_epoch_recipients (channel_id,version,device_id,user_id) VALUES ($1,1,$3,$4), ($1,2,$3,$4), ($2,1,$3,$4)',
          [migratedChannel, pendingOnlyChannel, legacyDevice, legacyUser],
        );
        const deliveries = await migrationClient.query(
          "INSERT INTO channel_keys (channel_id,version,device_id,encrypted_key,distributor_device_id,signature) VALUES ($1,1,$3,'test-fixture',$3,'test-fixture'), ($1,2,$3,'test-fixture',$3,'test-fixture'), ($2,1,$3,'test-fixture',$3,'test-fixture') RETURNING id, channel_id, version",
          [migratedChannel, pendingOnlyChannel, legacyDevice],
        );
        for (const delivery of deliveries.rows) {
          await migrationClient.query(
            "UPDATE channel_key_epoch_recipients SET accepted_delivery_id = $1, acknowledgement_signature = 'test-fixture', acknowledged_at = now() WHERE channel_id = $2 AND version = $3 AND device_id = $4",
            [delivery.id, delivery.channel_id, delivery.version, legacyDevice],
          );
        }
      } finally {
        await rm(oldBundle, { recursive: true, force: true });
      }
      await migrate(drizzle(migrationClient), { migrationsFolder });
    } finally {
      await migrationClient.end();
    }
    assert.ok(process.env.S3_ACCESS_KEY && process.env.S3_SECRET_KEY,
      'Account integration tests require a disposable object store for the durable audit head');
    process.env.AUDIT_INTEGRITY_KEY = 'account-security-test-audit-key-32-bytes';
process.env.PASSWORD_PEPPER ||= 'test-only-password-pepper-at-least-32-bytes';
    process.env.JWT_SECRET = 'account-security-test-session-key-32-bytes';
    process.env.REGISTRATION_INVITE_SECRET = 'account-security-test-bootstrap-32-bytes';
    auditDirectory = await mkdtemp(join(tmpdir(), 'alparts-account-security-'));
    process.env.AUDIT_CHECKPOINT_PATH = join(auditDirectory, 'checkpoint');
    process.env.AUDIT_CHECKPOINT_REQUIRED = 'true';
    process.env.AUDIT_HEAD_OBJECT_KEY = `test-${randomUUID()}`;
    const database = await import('../db/index.js');
    closeDb = database.closeDb;
    assert.equal(await database.checkDatabaseSchema(), 24);
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
    // The account-security migrations did this; later ones keep it.
    assert.deepEqual(legacyBeforeGroups, {
      epochs: [
        { version: 1, status: 'active', protocol_version: 2 },
        { version: 2, status: 'aborted', protocol_version: 2 },
      ],
      keyRotationRequired: true,
    });
    const epochs = await db.execute(
      sql`SELECT version, status, protocol_version FROM channel_key_epochs WHERE channel_id = ${legacyChannel} ORDER BY version`,
    );
    assert.deepEqual(epochs.rows, legacyBeforeGroups.epochs);
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
  it('aborts pending epochs and requires a continuous group where an earlier key is active', async () => {
    const { db } = await import('../db/index.js');
    const { sql } = await import('drizzle-orm');
    const epochs = async (id: string) => (await db.execute(sql`SELECT version, status, protocol_version,
      activated_at IS NOT NULL AS activated, aborted_at IS NOT NULL AS aborted
      FROM channel_key_epochs WHERE channel_id = ${id} ORDER BY version`)).rows;
    assert.deepEqual(await epochs(migratedChannel), [
      { version: 1, status: 'active', protocol_version: 3, activated: true, aborted: false },
      { version: 2, status: 'aborted', protocol_version: 3, activated: false, aborted: true },
    ]);
    assert.deepEqual(await epochs(pendingOnlyChannel), [
      { version: 1, status: 'aborted', protocol_version: 3, activated: false, aborted: true },
    ]);
    // Same cleanup as an abort at runtime: an aborted epoch keeps no
    // acknowledgement, delivery or recipient row. The active one keeps all.
    const recipients = await db.execute(sql`SELECT channel_id, version, accepted_delivery_id IS NOT NULL AS accepted
      FROM channel_key_epoch_recipients WHERE channel_id IN (${migratedChannel}, ${pendingOnlyChannel})`);
    assert.deepEqual(recipients.rows, [{ channel_id: migratedChannel, version: 1, accepted: true }]);
    const deliveries = await db.execute(sql`SELECT channel_id, version FROM channel_keys
      WHERE channel_id IN (${migratedChannel}, ${pendingOnlyChannel})`);
    assert.deepEqual(deliveries.rows, [{ channel_id: migratedChannel, version: 1 }]);
    // A channel with an earlier active key needs a continuous group before
    // anyone writes; a channel that never had one starts its group directly.
    const flags = await db.execute(sql`SELECT id, key_rotation_required FROM channels
      WHERE id IN (${migratedChannel}, ${pendingOnlyChannel})`);
    assert.deepEqual(
      Object.fromEntries(flags.rows.map((row) => [row.id, row.key_rotation_required])),
      { [migratedChannel]: true, [pendingOnlyChannel]: false },
    );
    assert.equal((await db.execute(sql`SELECT count(*)::int AS count FROM mls_groups
      WHERE channel_id IN (${migratedChannel}, ${pendingOnlyChannel})`)).rows[0].count, 0);
    const keyService = await import('../services/key.service.js');
    const migrated = await keyService.getKeyRecipients(migratedChannel, legacyUser, legacyDevice);
    assert.equal(migrated.group, null);
    assert.equal(migrated.protocolVersion, 3);
    assert.equal(migrated.currentVersion, 1);
    assert.equal(migrated.nextVersion, 3, 'an aborted version is never used again');
    assert.equal(migrated.rotationRequired, true);
    assert.equal(migrated.canCreate, true);
    assert.deepEqual(migrated.genesisWaiting, [legacyDevice], 'the first group waits for the earlier recipient');
    const unused = await keyService.getKeyRecipients(pendingOnlyChannel, legacyUser, legacyDevice);
    assert.equal(unused.currentVersion, 0);
    assert.equal(unused.nextVersion, 2);
    assert.equal(unused.canCreate, true);
    assert.deepEqual(unused.genesisWaiting, []);
    const { authorizeGroupWrite } = await import('../services/mls-group-gate.js');
    await assert.rejects(
      db.transaction(async (tx) => {
        const channel = await tx.query.channels.findFirst({ where: (c, { eq }) => eq(c.id, migratedChannel) });
        assert.ok(channel);
        await authorizeGroupWrite(tx, { channel, userId: legacyUser, deviceId: legacyDevice, keyVersion: 1 });
      }),
      /KEY_ROTATION_REQUIRED/,
      'the earlier key stays readable but takes no new writes',
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
          emailCode: await emailCode(email, registrationInvitation),
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
    const unapprovedPackage = await (await clientMls()).generateMemberPackage(second.id);
    assert.equal(
      (
        await request(
          `/api/channels/${channelId}/mls/group/packages`,
          memberPackageBody(secondMember(), unapprovedPackage.publicPackage),
          secondCookie,
        )
      ).status,
      403,
      'an unapproved device cannot offer itself to the group',
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
    for (const retired of ['mls/packages', 'mls/epochs'])
      assert.equal((await request(`/api/channels/${channelId}/${retired}`, {})).status, 410);
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
    const path = `/api/channels/${channelId}/mls/group/fresh-start`;
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
  it('starts a continuous MLS group whose accepted commit is usable at once', async () => {
    const mls = await clientMls();
    const model = await clientGroupModel();
    const groupService = await import('../services/mls-group.service.js');
    const keyService = await import('../services/key.service.js');
    const { authorizeGroupWrite } = await import('../services/mls-group-gate.js');
    const { db } = await import('../db/index.js');
    const { sql } = await import('drizzle-orm');
    const firstDevice = firstMember();
    const secondDevice = secondMember();
    let state = await json(await request(`/api/channels/${channelId}/key-recipients`));
    assert.equal(state.group, null);
    assert.equal(state.canCreate, true);
    assert.equal(state.rotationRequired, true, 'nothing can be written before the group exists');
    const genesisVersion: number = state.nextVersion;
    for (const device of [firstDevice, secondDevice])
      assert.equal((await publishPackage(device)).status, 201);
    const own = publishedPackages.get(first.id)!;
    const resigned = memberPackageBody(firstDevice, own.material.publicPackage, own.packageId);
    assert.deepEqual(
      await groupService.publishMemberPackage(channelId, userId, first.id, resigned),
      { created: false },
      're-signing the same package must not emit another roster change',
    );
    assert.equal((await request(`/api/channels/${channelId}/mls/group/packages`, resigned)).status, 200);

    // The creator adds every device that published a package; each package
    // is checked against the device that signed it.
    const added = await listedPackages(firstDevice, [firstDevice, secondDevice]);
    const authMap = new Map<string, string>();
    for (const entry of added) authMap.set(entry.deviceId, await verifiedPackageKey(entry));
    const groupId = mlsGroupId(channelId, genesisVersion);
    const genesis = await mls.createChannelGroup(groupId, own.material, added.slice(1).map((entry) => entry.keyPackage), authMap);
    const members = model.genesisRoster(added);
    mls.assertChannelGroup(genesis.newState, groupId, 1);
    model.assertTreeMatchesRoster(mls.groupLeaves(genesis.newState), members, authMap);
    const created = await sealCommit(firstDevice, genesis, {
      channelId,
      version: genesisVersion,
      previousVersion: 0,
      previousTranscript: '0'.repeat(64),
      groupId,
      epoch: 1,
      kind: 'create',
      added,
      removed: [],
      members,
    });
    const response = await submitCommit(firstDevice, created);
    assert.deepEqual(await json(response, 201), { version: genesisVersion, epoch: 1 });
    publishedPackages.delete(first.id);
    activate(created);
    // Accepted means usable: no device has to confirm anything first.
    await json(await request(`/api/channels/${channelId}/messages`, await encryptedMessage()), 201);
    // The other device joins from the server's log and derives the same key.
    assert.deepEqual(await joinFromLog(secondDevice), key);
    state = await json(await request(`/api/channels/${channelId}/key-recipients`, undefined, secondCookie));
    assert.equal(state.currentVersion, version);
    assert.equal(state.rotationRequired, false);
    assert.equal(state.canCommit, true);
    assert.deepEqual(state.ownMembership, { joinedVersion: version, leafIndex: 1, rejoinRequested: false });
    assert.equal(state.group.transcript, created.local.transcript);

    // Every member must still be an approved, unrevoked device of a viewer.
    const gate = async (tx: any) => {
      const channel = await tx.query.channels.findFirst({ where: (c: any, { eq }: any) => eq(c.id, channelId) });
      await authorizeGroupWrite(tx, { channel, userId, deviceId: first.id, keyVersion: version });
    };
    await assert.rejects(
      db.transaction(async (tx) => {
        await gate(tx);
        await tx.execute(sql`UPDATE devices SET approved_at = NULL WHERE id = ${second.id}`);
        await assert.rejects(gate(tx), /KEY_ROTATION_REQUIRED/, 'a member that is not approved blocks writes');
        let current = await keyService.getKeyRecipientsFromStore(tx as any, channelId, userId, first.id);
        assert.deepEqual(current.requiredRemoveDeviceIds, [second.id]);
        assert.equal(current.recipients.some((r) => r.deviceId === second.id), false);
        await tx.execute(sql`UPDATE devices SET approved_at = now(), revoked_at = now() WHERE id = ${second.id}`);
        await assert.rejects(gate(tx), /KEY_ROTATION_REQUIRED/, 'a revoked member blocks writes');
        current = await keyService.getKeyRecipientsFromStore(tx as any, channelId, userId, first.id);
        assert.deepEqual(current.requiredRemoveDeviceIds, [second.id]);
        assert.equal(current.rotationRequired, true);
        throw new Error('ROLLBACK_FIXTURE');
      }),
      /ROLLBACK_FIXTURE/,
    );
    await db.transaction(gate);

    // A group key not refreshed by a path for 24 hours takes no writes, even
    // through a raw API request. Before that, a refresh is not accepted.
    const refresh = await groupCommit(firstDevice);
    assert.deepEqual(await refusal(await submitCommit(firstDevice, refresh)), [409, 'KEY_ROTATION_NOT_REQUIRED']);
    await db.execute(
      sql`UPDATE mls_groups SET path_refreshed_at = now() - interval '25 hours' WHERE channel_id = ${channelId}`,
    );
    assert.deepEqual(
      await refusal(await request(`/api/channels/${channelId}/messages`, await encryptedMessage())),
      [400, 'KEY_ROTATION_REQUIRED'],
      'a group key older than a day cannot be used through a raw API request',
    );
    state = await json(await request(`/api/channels/${channelId}/key-recipients`));
    assert.equal(state.updateRequired, true);
    assert.equal(state.rotationRequired, true);
    assert.ok((await json(await request('/api/mls/group/pending'))).needCommit.includes(channelId));
    // One member refreshes it while the other device is offline.
    assert.deepEqual(await json(await submitCommit(firstDevice, refresh), 201), { version: version + 1, epoch: 2 });
    const earlierKey = key;
    activate(refresh);
    assert.equal(
      (await db.execute(sql`SELECT path_refreshed_at > now() - interval '1 minute' AS fresh FROM mls_groups WHERE channel_id = ${channelId}`)).rows[0].fresh,
      true,
    );
    await json(await request(`/api/channels/${channelId}/messages`, await encryptedMessage()), 201);
    const stale = await request(
      `/api/channels/${channelId}/messages`,
      await encryptedMessage({ keyVersion: version - 1, rawKey: earlierKey }),
    );
    const staleBody = await json(stale, 400);
    assert.deepEqual([staleBody.code, staleBody.currentVersion], ['KEY_VERSION_STALE', version]);

    // Per-device key deliveries never apply to a group version, and the
    // per-device proposal of a new version is gone.
    const delivery = (keyVersion: number) => {
      const encryptedKey = Buffer.from(JSON.stringify({ mls: 1, version: keyVersion, transcript: refresh.local.transcript })).toString('base64');
      return {
        version: keyVersion,
        keyCommitment: commitment,
        keys: [{
          deviceId: first.id,
          encryptedKey,
          signature: signature(firstKeys.privateKey, serializeChannelKeyWrap({
            channelId,
            keyVersion,
            keyCommitment: commitment,
            recipientDeviceId: first.id,
            encryptedKey,
          })),
        }],
      };
    };
    assert.equal((await request(`/api/channels/${channelId}/keys`, delivery(version))).status, 400);
    assert.equal(
      (await request(`/api/channels/${channelId}/keys`, delivery(version + 1))).status,
      409,
      'legacy group proposal is disabled',
    );
  });
  it('lets an offline member catch up from the commit log and keep the keys it already had', async () => {
    const secondDevice = secondMember();
    const before = localGroups.get(second.id)!;
    assert.equal(before.version, version - 1, 'the second device missed the refresh');
    const earlierKey = before.keys.get(before.version)!;
    const stale = await request(
      `/api/channels/${channelId}/messages`,
      await encryptedMessage({ device: secondDevice, keyVersion: before.version, rawKey: earlierKey }),
      secondCookie,
    );
    const staleBody = await json(stale, 400);
    assert.deepEqual([staleBody.code, staleBody.currentVersion], ['KEY_VERSION_STALE', version]);
    assert.deepEqual((await catchUp(secondDevice)).map((record) => record.version), [version]);
    const caughtUp = localGroups.get(second.id)!;
    assert.deepEqual(caughtUp.keys.get(version), key, 'both devices derive the same key');
    assert.deepEqual(caughtUp.keys.get(version - 1), earlierKey, 'keys derived earlier stay');
    assert.deepEqual(await json(await request(
      `/api/channels/${channelId}/mls/group/commits?after=${version}`,
      undefined,
      secondCookie,
    )), []);
    await json(await request(
      `/api/channels/${channelId}/messages`,
      await encryptedMessage({ device: secondDevice }),
      secondCookie,
    ), 201);
    // Reading the log changes nothing on the server.
    const state = await json(await request(`/api/channels/${channelId}/key-recipients`));
    assert.equal(state.currentVersion, version);
    assert.equal(state.keyCommitment, commitment);
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
    const path = `/api/channels/${channelId}/mls/group/fresh-start`;
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
    const earlierKey = localGroups.get(first.id)!.keys.get(version - 1)!;
    assert.equal(
      (
        await request(
          '/api/recovery/keys',
          {
            generation,
            channelId,
            version,
            keyCommitment: keyCommitmentOf(earlierKey),
            ciphertext: encryptedHistory,
          },
          replacementCookie,
        )
      ).status,
      403,
      'the commitment must name the key of that version',
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
    assert.deepEqual(
      await refusal(await request(`/api/channels/${channelId}/messages`, await encryptedMessage())),
      [400, 'KEY_ROTATION_REQUIRED'],
      'revocation blocks writes until the device leaves the group',
    );
    const recipients = await json(await request(`/api/channels/${channelId}/key-recipients`));
    assert.equal(recipients.rotationRequired, true);
    assert.deepEqual(recipients.requiredRemoveDeviceIds, [second.id]);
    assert.equal(
      recipients.recipients.some((r: any) => r.deviceId === second.id),
      false,
    );
    assert.ok((await json(await request('/api/mls/group/pending'))).needCommit.includes(channelId));
    // The revoked device reads nothing more of the group.
    const groupService = await import('../services/mls-group.service.js');
    await assert.rejects(groupService.listGroupCommits(channelId, userId, second.id, 0, 16), /DEVICE_APPROVAL_REQUIRED/);
    await assert.rejects(groupService.listGroupMembers(channelId, userId, second.id, version), /DEVICE_APPROVAL_REQUIRED/);
    // A remaining member removes it, and writes continue under the new key.
    const removal = await groupCommit(firstMember(), { remove: [second.id] });
    assert.deepEqual(await json(await submitCommit(firstMember(), removal), 201), { version: version + 1, epoch: removal.envelope.epoch });
    activate(removal);
    assert.deepEqual(removal.envelope.members.map((member) => member.deviceId), [first.id]);
    await json(await request(`/api/channels/${channelId}/messages`, await encryptedMessage()), 201);
    assert.equal((await json(await request(`/api/channels/${channelId}/key-recipients`))).rotationRequired, false);
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
  it('asks members to add a visible member’s first device and starts over only when confirmed and needed', async () => {
    const { db } = await import('../db/index.js');
    const { sql } = await import('drizzle-orm');
    const mls = await clientMls();
    const groupService = await import('../services/mls-group.service.js');
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
          emailCode: await emailCode(email, invitation.token),
        },
        '',
      ),
      201,
    );
    const login = await request('/api/auth/login', { email, password }, '');
    await json(login);
    const auth = login.headers.get('set-cookie')!.split(';')[0];
    // The account sees the channel but has no device yet: nothing waits.
    assert.deepEqual((await json(await request(`/api/channels/${channelId}/key-recipients`))).pendingAddDeviceIds, []);
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
    const newcomer = groupDevice(device, account.id, keys.privateKey, auth);
    // The new device is asked to offer itself, and once it has, every member
    // sees that it waits: it is not silently left out of the group.
    assert.ok((await json(await request('/api/mls/group/pending', undefined, auth))).needPackage.includes(channelId));
    assert.equal((await publishPackage(newcomer)).status, 201);
    let state = await json(await request(`/api/channels/${channelId}/key-recipients`));
    assert.deepEqual(state.pendingAddDeviceIds, [device.id], 'a newly eligible first device must be added');
    assert.equal(state.rotationRequired, false, 'a device waiting to be added does not stop writes');
    assert.ok((await json(await request('/api/mls/group/pending'))).needCommit.includes(channelId));
    await json(await request(`/api/channels/${channelId}/messages`, await encryptedMessage()), 201);
    const waiting = await json(await request(`/api/channels/${channelId}/key-recipients`, undefined, auth));
    assert.equal(waiting.ownMembership, null);
    assert.equal(waiting.canCommit, false);
    assert.equal(waiting.historyRecoveryRequired, false, 'a usable member can add it');

    // Starting the channel over replaces the group without its history. It
    // takes a confirmed request on its own route, and only when no member
    // can add this device.
    const [entry] = await listedPackages(firstMember(), [newcomer]);
    const restartVersion = version + 1;
    const restartGroupId = mlsGroupId(channelId, restartVersion);
    const restart = await mls.createChannelGroup(
      restartGroupId,
      publishedPackages.get(device.id)!.material,
      [],
      new Map([[device.id, await verifiedPackageKey(entry)]]),
    );
    const restarted = await sealCommit(newcomer, restart, {
      channelId,
      version: restartVersion,
      previousVersion: version,
      previousTranscript: waiting.group.transcript,
      groupId: restartGroupId,
      epoch: 1,
      kind: 'create',
      added: [entry],
      removed: [],
      members: [{ deviceId: device.id, userId: account.id, leafIndex: 0 }],
    });
    assert.deepEqual(
      await refusal(await submitCommit(newcomer, restarted)),
      [403, 'KEY_FRESH_START_REQUIRED'],
      'the ordinary route never replaces an existing group',
    );
    const freshStartPath = `/api/channels/${channelId}/mls/group/fresh-start`;
    const freshStart = {
      commit: restarted.envelope,
      freshStartSignature: signature(keys.privateKey, serializeChannelKeyFreshStart({
        channelId,
        keyVersion: restartVersion,
        keyCommitment: restarted.envelope.keyCommitment,
        deviceId: device.id,
      })),
    };
    assert.equal((await request(freshStartPath, freshStart, auth)).status, 428);
    await assert.rejects(
      groupService.admitGroupCommit(account.id, device.id, restarted.envelope, { signature: freshStart.freshStartSignature }),
      /AUTHENTICATION_FAILED/,
      'MLS fresh start cannot be called without a server-created step-up receipt',
    );
    const session = (await db.execute(sql`SELECT id FROM sessions WHERE device_id = ${device.id}`)).rows[0];
    const { actionPurpose } = await import('./action-purpose.js');
    await assert.rejects(
      groupService.admitGroupCommit(account.id, device.id, restarted.envelope, {
        signature: freshStart.freshStartSignature,
        stepUpProof: {
          sessionId: session.id as string,
          userId: account.id,
          purpose: actionPurpose('POST', freshStartPath, freshStart),
          expiresAt: Date.now() + 60_000,
        },
      }),
      /AUTHENTICATION_FAILED/,
      'a receipt-shaped object is not a receipt',
    );
    assert.deepEqual(
      await refusal(await sensitive(freshStartPath, freshStart, 'POST', auth)),
      [409, 'KEY_FRESH_START_NOT_REQUIRED'],
      'a confirmed fresh start is still refused while a member can add the device',
    );

    // A member adds it; it joins from the Welcome and writes at once.
    const addition = await groupCommit(firstMember(), { add: [newcomer] });
    assert.deepEqual(await json(await submitCommit(firstMember(), addition), 201), { version: restartVersion, epoch: addition.envelope.epoch });
    activate(addition);
    assert.deepEqual(addition.envelope.members.map((member) => member.deviceId), [first.id, device.id]);
    assert.deepEqual(await joinFromLog(newcomer), key);
    state = await json(await request(`/api/channels/${channelId}/key-recipients`));
    assert.deepEqual(state.pendingAddDeviceIds, []);
    await json(await request(`/api/channels/${channelId}/messages`, await encryptedMessage({ device: newcomer }), auth), 201);
    // It reads from the version that added it, never an earlier one.
    assert.deepEqual(await json(await request(`/api/channels/${channelId}/mls/group/commits?after=0`, undefined, auth)), []);
    assert.equal((await request(`/api/channels/${channelId}/mls/group/members?version=${version - 1}`, undefined, auth)).status, 404);
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
  it('changes the password, turns password login off and recovers through an operator reset', { timeout: 30_000 }, async () => {
    const { db } = await import('../db/index.js');
    const auth = await import('../services/auth.service.js');
    const { spawn } = await import('node:child_process');
    const { fileURLToPath } = await import('node:url');
    const user = await db.query.users.findFirst({ where: (u, { eq }) => eq(u.id, userId) });
    assert.ok(user);
    const { config } = await import('../config/index.js');
    // The service is called directly where possible; HTTP logins share a small per-account budget.
    const login = async (secret: string) => `${config.auth.cookieName}=${(await auth.login(user.email, secret)).token}`;
    const reset = (secret: string) => new Promise<{ code: number | null; stderr: string }>((resolve, reject) => {
      const child = spawn(process.execPath, ['--import', 'tsx',
        fileURLToPath(new URL('../scripts/reset-password.ts', import.meta.url)), userId], { stdio: ['pipe', 'ignore', 'pipe'], timeout: 20_000 });
      let stderr = '';
      child.stderr.on('data', (chunk) => { stderr += chunk; });
      child.once('error', reject);
      child.once('close', (code) => resolve({ code, stderr }));
      child.stdin.end(`${secret}\n`);
    });

    // A password change needs a confirmation and ends every other login.
    const other = await login(password);
    const newPassword = 'Changed-Account-Security-Password!';
    assert.equal((await request('/api/auth/password', { newPassword }, cookie, 'PUT')).status, 428);
    assert.equal((await confirmedRequest('/api/auth/password', { newPassword: 'short' }, 'PUT')).status, 400);
    assert.ok((await json(await confirmedRequest('/api/auth/password', { newPassword }, 'PUT'))).revoked >= 1);
    assert.equal((await request('/api/auth/me', undefined, other)).status, 401);
    assert.equal((await request('/api/auth/me')).status, 200, 'the login that changed it stays');
    await assert.rejects(login(password), /INVALID_CREDENTIALS/);
    const changed = await login(newPassword);

    // Password login can be turned off only with a passkey; it ends password logins.
    await assert.rejects(auth.setPasswordLogin(legacyUser, randomUUID(), false), /PASSKEY_REQUIRED/);
    assert.deepEqual(await json(await request('/api/auth/password-login')), { enabled: true });
    assert.equal((await json(await sensitive('/api/auth/password-login', { enabled: false }, 'PUT'))).enabled, false);
    assert.equal((await request('/api/auth/me', undefined, changed)).status, 401);
    assert.deepEqual(await json(await request('/api/auth/password-login')), { enabled: false });
    const refused = await request('/api/auth/login', { email: user.email, password: newPassword }, '');
    assert.equal(refused.status, 401, 'the right password no longer signs in');

    // An operator reset sets a new password, turns password login back on and ends every login.
    assert.notEqual((await reset('too-short')).code, 0);
    const restored = await reset(password);
    assert.equal(restored.code, 0, restored.stderr);
    assert.equal((await request('/api/auth/me')).status, 401);
    cookie = await login(password);
    assert.deepEqual(await json(await request('/api/auth/password-login')), { enabled: true });
    // The new login proves the existing device key again before it can use the device.
    const challenge = (await json(await request('/api/devices/challenge', {}, cookie))).challenge;
    const rebound = await json(await request('/api/devices', {
      name: 'First',
      identityKey: firstKeys.identityKey,
      challenge,
      proof: signature(firstKeys.privateKey, serializeDeviceChallengeProof(userId, challenge)),
      currentPassword: password,
    }, cookie));
    assert.equal(rebound.id, first.id);
    assert.equal((await (await import('../middleware/audit.js')).verifyAuditChain()).valid, true);
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
