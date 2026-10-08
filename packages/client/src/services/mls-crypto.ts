import {
  createCommit,
  createGroup,
  joinGroup,
  getCiphersuiteImpl,
  getCiphersuiteFromName,
  generateKeyPackage,
  mlsExporter,
  encodeMlsMessage,
  decodeMlsMessage,
  decodeGroupState,
  encodeGroupState,
  emptyPskIndex,
  makePskIndex,
  processMessage,
  type KeyPackage,
  type PrivateKeyPackage,
  type ClientState,
  type Credential,
  type Decoder,
  type IncomingMessageCallback,
} from 'ts-mls';
import { defaultClientConfig } from 'ts-mls/clientConfig.js';
import { MLS_CIPHERSUITE, MLS_GROUP_EXPORTER_LABEL, mlsExporterContext } from '@alparts/shared';
import { fromBase64, toBase64 } from './security-storage';
const encoder = new TextEncoder();
export interface EpochKeyPackage {
  publicPackage: string;
  privatePackage: {
    initPrivateKey: string;
    hpkePrivateKey: string;
    signaturePrivateKey: string;
  };
}
const suite = () => getCiphersuiteImpl(getCiphersuiteFromName(MLS_CIPHERSUITE));
function decode<T>(decoder: Decoder<T>, data: Uint8Array): T {
  const result = decoder(data, 0);
  if (!result || result[1] !== data.length) throw new Error('INVALID_MLS_ENCODING');
  return result[0];
}
export function decodePublicPackage(encoded: string): KeyPackage {
  const message = decode(decodeMlsMessage, fromBase64(encoded));
  if (
    message.wireformat !== 'mls_key_package' ||
    message.version !== 'mls10' ||
    message.keyPackage.cipherSuite !== MLS_CIPHERSUITE
  )
    throw new Error('INVALID_MLS_PACKAGE');
  return message.keyPackage;
}
function privatePackage(value: EpochKeyPackage): PrivateKeyPackage {
  return {
    initPrivateKey: fromBase64(value.privatePackage.initPrivateKey),
    hpkePrivateKey: fromBase64(value.privatePackage.hpkePrivateKey),
    signaturePrivateKey: fromBase64(value.privatePackage.signaturePrivateKey),
  };
}
export function eraseMlsSecrets(value: unknown, seen = new Set<unknown>()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return;
  seen.add(value);
  if (value instanceof Uint8Array) value.fill(0);
  else if (value instanceof Map) for (const item of value.values()) eraseMlsSecrets(item, seen);
  else for (const item of Object.values(value)) eraseMlsSecrets(item, seen);
}
export async function generateEpochKeyPackage(deviceId: string): Promise<EpochKeyPackage> {
  return generatePackage(deviceId, 300n);
}
async function generatePackage(deviceId: string, validBeforeNow: bigint): Promise<EpochKeyPackage> {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const pair = await generateKeyPackage(
    { credentialType: 'basic', identity: encoder.encode(deviceId) },
    {
      versions: ['mls10'],
      ciphersuites: [MLS_CIPHERSUITE],
      extensions: [],
      proposals: [],
      credentials: ['basic'],
    },
    { notBefore: now - validBeforeNow, notAfter: now + 604800n },
    [],
    await suite(),
  );
  try {
    return {
      publicPackage: toBase64(
        encodeMlsMessage({
          version: 'mls10',
          wireformat: 'mls_key_package',
          keyPackage: pair.publicPackage,
        }),
      ),
      privatePackage: {
        initPrivateKey: toBase64(pair.privatePackage.initPrivateKey),
        hpkePrivateKey: toBase64(pair.privatePackage.hpkePrivateKey),
        signaturePrivateKey: toBase64(pair.privatePackage.signaturePrivateKey),
      },
    };
  } finally {
    eraseMlsSecrets(pair);
  }
}
function clientConfig(packages: KeyPackage[]) {
  const keys = new Map(
    packages.map((p) => {
      if (p.leafNode.credential.credentialType !== 'basic')
        throw new Error('INVALID_MLS_CREDENTIAL');
      return [
        new TextDecoder().decode(p.leafNode.credential.identity),
        toBase64(p.leafNode.signaturePublicKey),
      ];
    }),
  );
  if (keys.size !== packages.length) throw new Error('INVALID_MLS_ROSTER');
  return {
    ...defaultClientConfig,
    keyRetentionConfig: {
      retainKeysForGenerations: 0,
      retainKeysForEpochs: 0,
      maximumForwardRatchetSteps: 1000,
    },
    authService: {
      async validateCredential(
        credential: KeyPackage['leafNode']['credential'],
        signingKey: Uint8Array,
      ) {
        return (
          credential.credentialType === 'basic' &&
          keys.get(new TextDecoder().decode(credential.identity)) === toBase64(signingKey)
        );
      },
    },
  };
}
function assertGroup(state: ClientState, groupId: string, packages: KeyPackage[]) {
  if (
    new TextDecoder().decode(state.groupContext.groupId) !== groupId ||
    state.groupContext.epoch !== 1n ||
    state.groupContext.cipherSuite !== MLS_CIPHERSUITE
  )
    throw new Error('INVALID_MLS_GROUP');
  const actual = state.ratchetTree.flatMap((node) =>
    node?.nodeType === 'leaf' ? [node.leaf] : [],
  );
  if (actual.length !== packages.length) throw new Error('INVALID_MLS_ROSTER');
  for (const p of packages) {
    if (p.leafNode.credential.credentialType !== 'basic') throw new Error('INVALID_MLS_ROSTER');
    const id = toBase64(p.leafNode.credential.identity);
    const leaf = actual.find(
      (l) => l.credential.credentialType === 'basic' && toBase64(l.credential.identity) === id,
    );
    if (!leaf || toBase64(leaf.signaturePublicKey) !== toBase64(p.leafNode.signaturePublicKey))
      throw new Error('INVALID_MLS_ROSTER');
  }
}
export async function createEpochGroup(groupId: string, own: EpochKeyPackage, members: string[]) {
  const cs = await suite();
  const packages = members.map(decodePublicPackage);
  const ownPublic = decodePublicPackage(own.publicPackage);
  const secret = privatePackage(own);
  let initial: ClientState | undefined;
  let next: ClientState | undefined;
  try {
    initial = await createGroup(
      encoder.encode(groupId),
      ownPublic,
      secret,
      [],
      cs,
      clientConfig(packages),
    );
    const result = await createCommit(
      { state: initial, cipherSuite: cs },
      {
        ratchetTreeExtension: true,
        extraProposals: packages
          .filter((p) => toBase64(p.initKey) !== toBase64(ownPublic.initKey))
          .map((keyPackage) => ({
            proposalType: 'add' as const,
            add: { keyPackage },
          })),
      },
    );
    next = result.newState;
    assertGroup(next, groupId, packages);
    const raw = await mlsExporter(
      next.keySchedule.exporterSecret,
      'alparts-channel-epoch-v1',
      encoder.encode(groupId),
      32,
      cs,
    );
    const welcome = result.welcome
      ? toBase64(
          encodeMlsMessage({
            version: 'mls10',
            wireformat: 'mls_welcome',
            welcome: result.welcome,
          }),
        )
      : '';
    const commit = toBase64(encodeMlsMessage(result.commit));
    result.consumed.forEach((bytes) => eraseMlsSecrets(bytes));
    return { raw, welcome, commit };
  } finally {
    eraseMlsSecrets(initial);
    eraseMlsSecrets(next);
    eraseMlsSecrets(secret);
  }
}
export async function joinEpochGroup(
  groupId: string,
  own: EpochKeyPackage,
  members: string[],
  welcome: string,
) {
  const cs = await suite();
  const packages = members.map(decodePublicPackage);
  const secret = privatePackage(own);
  let state: ClientState | undefined;
  try {
    const message = decode(decodeMlsMessage, fromBase64(welcome));
    if (message.version !== 'mls10' || message.wireformat !== 'mls_welcome')
      throw new Error('INVALID_MLS_WELCOME');
    state = await joinGroup(
      message.welcome,
      decodePublicPackage(own.publicPackage),
      secret,
      emptyPskIndex,
      cs,
      undefined,
      undefined,
      clientConfig(packages),
    );
    assertGroup(state, groupId, packages);
    return await mlsExporter(
      state.keySchedule.exporterSecret,
      'alparts-channel-epoch-v1',
      encoder.encode(groupId),
      32,
      cs,
    );
  } finally {
    eraseMlsSecrets(state);
    eraseMlsSecrets(secret);
  }
}

// === Continuous channel groups (group protocol 4) ===

/** Device id -> base64 MLS signature key of every leaf this device trusts. */
export type ChannelGroupAuthMap = ReadonlyMap<string, string>;

export interface ChannelGroupLeaf {
  leafIndex: number;
  deviceId: string;
  signatureKey: string;
  encryptionKey: string;
}

/** What a PublicMessage commit says, read without group secrets. */
export interface DecodedChannelCommit {
  groupId: string;
  /** Epoch the commit was made in (the envelope's epoch minus one). */
  epoch: number;
  senderLeafIndex: number;
  /** Canonical base64 of each Add's KeyPackage, in proposal order. */
  addPackages: string[];
  removedLeaves: number[];
  hasPath: boolean;
}

export interface ChannelGroupCommitResult {
  newState: ClientState;
  commit: string;
  welcome: string;
  /**
   * Secrets of the state the commit was made from. Erase them only after the
   * server accepted the commit: a losing commit must still process the winner.
   */
  consumed: Uint8Array[];
}

const fatalDecoder = new TextDecoder('utf-8', { fatal: true });

function credentialIdentity(credential: Credential): string | null {
  if (credential.credentialType !== 'basic') return null;
  try {
    return fatalDecoder.decode(credential.identity);
  } catch {
    return null;
  }
}

function groupClientConfig(authMap: ChannelGroupAuthMap) {
  return {
    ...defaultClientConfig,
    // ts-mls 1.6.4 keeps every epoch for 0. One is kept while processing and
    // the history is dropped before a state is saved.
    keyRetentionConfig: {
      retainKeysForGenerations: 0,
      retainKeysForEpochs: 1,
      maximumForwardRatchetSteps: 1000,
    },
    authService: {
      async validateCredential(credential: Credential, signingKey: Uint8Array) {
        const identity = credentialIdentity(credential);
        return identity !== null && authMap.get(identity) === toBase64(signingKey);
      },
    },
  };
}

/** A package for joining a channel group; valid from 15 minutes ago so slower clocks accept it. */
export async function generateMemberPackage(deviceId: string): Promise<EpochKeyPackage> {
  return generatePackage(deviceId, 900n);
}

export interface MemberPackageInfo {
  identity: string | null;
  initKey: string;
  encryptionKey: string;
  signatureKey: string;
  notBefore: number;
  notAfter: number;
}

/**
 * Keys and lifetime of a published package. Only a canonical encoding is
 * accepted: an Add re-encodes its package, and other bytes would not match.
 */
export function readMemberPackage(encoded: string): MemberPackageInfo {
  const pkg = decodePublicPackage(encoded);
  if (
    toBase64(encodeMlsMessage({ version: 'mls10', wireformat: 'mls_key_package', keyPackage: pkg })) !== encoded
    || pkg.leafNode.leafNodeSource !== 'key_package'
  ) throw new Error('INVALID_MLS_PACKAGE');
  return {
    identity: credentialIdentity(pkg.leafNode.credential),
    initKey: toBase64(pkg.initKey),
    encryptionKey: toBase64(pkg.leafNode.hpkePublicKey),
    signatureKey: toBase64(pkg.leafNode.signaturePublicKey),
    notBefore: Number(pkg.leafNode.lifetime.notBefore),
    notAfter: Number(pkg.leafNode.lifetime.notAfter),
  };
}

/** Occupied leaves of the ratchet tree, by leaf index. */
export function groupLeaves(state: ClientState): ChannelGroupLeaf[] {
  const leaves: ChannelGroupLeaf[] = [];
  for (let index = 0; index < state.ratchetTree.length; index += 2) {
    const node = state.ratchetTree[index];
    if (node?.nodeType !== 'leaf') continue;
    const deviceId = credentialIdentity(node.leaf.credential);
    if (deviceId === null) throw new Error('INVALID_MLS_ROSTER');
    leaves.push({
      leafIndex: index / 2,
      deviceId,
      signatureKey: toBase64(node.leaf.signaturePublicKey),
      encryptionKey: toBase64(node.leaf.hpkePublicKey),
    });
  }
  return leaves;
}

/** Every HPKE and signature key in the tree; a new leaf must use none of them. */
function treeKeys(state: ClientState): Set<string> {
  const keys = new Set<string>();
  for (const node of state.ratchetTree) {
    if (node?.nodeType === 'leaf') {
      keys.add(toBase64(node.leaf.hpkePublicKey));
      keys.add(toBase64(node.leaf.signaturePublicKey));
    } else if (node?.nodeType === 'parent') {
      keys.add(toBase64(node.parent.hpkePublicKey));
    }
  }
  return keys;
}

/**
 * The authentication map of a tree: each leaf's identity and signature key.
 * Leaves were authenticated when they entered the tree.
 */
export function treeAuthMap(state: ClientState, excludeLeaves: readonly number[] = []): Map<string, string> {
  const excluded = new Set(excludeLeaves);
  const map = new Map<string, string>();
  for (const leaf of groupLeaves(state)) {
    if (excluded.has(leaf.leafIndex)) continue;
    if (map.has(leaf.deviceId)) throw new Error('INVALID_MLS_ROSTER');
    map.set(leaf.deviceId, leaf.signatureKey);
  }
  return map;
}

/**
 * Packages that can join this tree now: unique keys that no leaf or parent
 * node uses (ts-mls accepts a duplicate and then fails every later commit),
 * and a lifetime that includes this device's clock.
 */
export function addablePackages(state: ClientState | null, packages: readonly string[], now = Date.now()): string[] {
  const used = state ? treeKeys(state) : new Set<string>();
  const seconds = Math.floor(now / 1000);
  const result: string[] = [];
  for (const encoded of packages) {
    let info: MemberPackageInfo;
    try {
      info = readMemberPackage(encoded);
    } catch {
      continue;
    }
    const keys = [info.initKey, info.encryptionKey, info.signatureKey];
    if (
      new Set(keys).size !== keys.length
      || keys.some((key) => used.has(key))
      || info.notBefore > seconds
      || info.notAfter < seconds
    ) continue;
    keys.forEach((key) => used.add(key));
    result.push(encoded);
  }
  return result;
}

function encodeWelcome(welcome: CreateCommitWelcome | undefined): string {
  return welcome
    ? toBase64(encodeMlsMessage({ version: 'mls10', wireformat: 'mls_welcome', welcome }))
    : '';
}
type CreateCommitWelcome = NonNullable<Awaited<ReturnType<typeof createCommit>>['welcome']>;

/**
 * A new group with this device at leaf 0 and every other package added by
 * one commit. Alone, the genesis is an empty commit that carries a path.
 */
export async function createChannelGroup(
  groupId: string,
  own: EpochKeyPackage,
  others: readonly string[],
  authMap: ChannelGroupAuthMap,
): Promise<ChannelGroupCommitResult> {
  const cs = await suite();
  // The new state keeps these private keys (its leaf and signing key).
  const initial = await createGroup(
    encoder.encode(groupId),
    decodePublicPackage(own.publicPackage),
    privatePackage(own),
    [],
    cs,
    groupClientConfig(authMap),
  );
  const result = await createCommit(
    { state: initial, cipherSuite: cs },
    {
      wireAsPublicMessage: true,
      ratchetTreeExtension: true,
      extraProposals: others.map((encoded) => ({
        proposalType: 'add' as const,
        add: { keyPackage: decodePublicPackage(encoded) },
      })),
    },
  );
  return {
    newState: result.newState,
    commit: toBase64(encodeMlsMessage(result.commit)),
    welcome: encodeWelcome(result.welcome),
    consumed: result.consumed,
  };
}

/**
 * Add, remove or (with neither) refresh this device's own path. Removes and
 * empty commits always carry an UpdatePath; Add-only commits cannot.
 */
export async function commitChannelGroup(
  state: ClientState,
  change: { add: readonly string[]; removeLeaves: readonly number[]; authMap: ChannelGroupAuthMap },
): Promise<ChannelGroupCommitResult> {
  const cs = await suite();
  const result = await createCommit(
    { state: { ...state, clientConfig: groupClientConfig(change.authMap) }, cipherSuite: cs },
    {
      wireAsPublicMessage: true,
      ratchetTreeExtension: true,
      extraProposals: [
        ...change.removeLeaves.map((removed) => ({ proposalType: 'remove' as const, remove: { removed } })),
        ...change.add.map((encoded) => ({
          proposalType: 'add' as const,
          add: { keyPackage: decodePublicPackage(encoded) },
        })),
      ],
    },
  );
  return {
    newState: result.newState,
    commit: toBase64(encodeMlsMessage(result.commit)),
    welcome: encodeWelcome(result.welcome),
    consumed: result.consumed,
  };
}

/** Read a commit envelope's MLSMessage: by-value Add and Remove proposals from a member only. */
export function decodeChannelCommit(encoded: string): DecodedChannelCommit {
  const message = decode(decodeMlsMessage, fromBase64(encoded));
  if (
    message.version !== 'mls10'
    || message.wireformat !== 'mls_public_message'
    || message.publicMessage.senderType !== 'member'
  ) throw new Error('INVALID_MLS_COMMIT');
  const content = message.publicMessage.content;
  if (
    content.sender.senderType !== 'member'
    || content.contentType !== 'commit'
    || content.authenticatedData.length !== 0
  ) throw new Error('INVALID_MLS_COMMIT');
  const addPackages: string[] = [];
  const removedLeaves: number[] = [];
  for (const entry of content.commit.proposals) {
    if (entry.proposalOrRefType !== 'proposal') throw new Error('INVALID_MLS_COMMIT');
    const proposal = entry.proposal;
    if (proposal.proposalType === 'add') {
      addPackages.push(toBase64(encodeMlsMessage({
        version: 'mls10',
        wireformat: 'mls_key_package',
        keyPackage: proposal.add.keyPackage,
      })));
    } else if (proposal.proposalType === 'remove') {
      removedLeaves.push(proposal.remove.removed);
    } else {
      throw new Error('INVALID_MLS_COMMIT');
    }
  }
  let groupId: string;
  try {
    groupId = fatalDecoder.decode(content.groupId);
  } catch {
    throw new Error('INVALID_MLS_COMMIT');
  }
  const epoch = content.epoch;
  if (epoch < 0n || epoch > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('INVALID_MLS_COMMIT');
  return {
    groupId,
    epoch: Number(epoch),
    senderLeafIndex: content.sender.leafIndex,
    addPackages,
    removedLeaves,
    hasPath: content.commit.path !== undefined,
  };
}

/**
 * Apply another member's commit. The caller has verified the signed envelope
 * and that it does not remove this device; the callback rejects a commit whose
 * proposals differ from it or remove this device's leaf anyway.
 */
export async function processChannelCommit(
  state: ClientState,
  encoded: string,
  expected: { addPackages: readonly string[]; removedLeaves: readonly number[] },
  authMap: ChannelGroupAuthMap,
): Promise<{ newState: ClientState; consumed: Uint8Array[] }> {
  const cs = await suite();
  const message = decode(decodeMlsMessage, fromBase64(encoded));
  if (message.wireformat !== 'mls_public_message') throw new Error('INVALID_MLS_COMMIT');
  if (message.publicMessage.content.epoch !== state.groupContext.epoch) throw new Error('INVALID_MLS_EPOCH');
  const ownLeaf = state.privatePath.leafIndex;
  const expectedRemoved = [...expected.removedLeaves].sort((left, right) => left - right).join();
  const callback: IncomingMessageCallback = (incoming) => {
    if (incoming.kind !== 'commit') return 'reject';
    const adds: string[] = [];
    const removed: number[] = [];
    for (const { proposal } of incoming.proposals) {
      if (proposal.proposalType === 'add') {
        adds.push(toBase64(encodeMlsMessage({
          version: 'mls10',
          wireformat: 'mls_key_package',
          keyPackage: proposal.add.keyPackage,
        })));
      } else if (proposal.proposalType === 'remove') {
        removed.push(proposal.remove.removed);
      } else {
        return 'reject';
      }
    }
    return removed.includes(ownLeaf)
      || adds.join() !== expected.addPackages.join()
      || [...removed].sort((left, right) => left - right).join() !== expectedRemoved
      ? 'reject'
      : 'accept';
  };
  const result = await processMessage(
    message,
    { ...state, clientConfig: groupClientConfig(authMap) },
    makePskIndex(state, {}),
    callback,
    cs,
  );
  if (
    result.kind !== 'newState'
    || result.actionTaken !== 'accept'
    || result.newState.groupActiveState.kind !== 'active'
  ) throw new Error('INVALID_MLS_COMMIT');
  // `consumed` holds secrets of the state processed from; erase them once the new state is kept.
  return { newState: result.newState, consumed: result.consumed };
}

/** Join from a Welcome whose GroupInfo carries the ratchet tree. */
export async function joinChannelGroup(
  welcome: string,
  own: EpochKeyPackage,
  authMap: ChannelGroupAuthMap,
): Promise<ClientState> {
  const cs = await suite();
  const message = decode(decodeMlsMessage, fromBase64(welcome));
  if (message.version !== 'mls10' || message.wireformat !== 'mls_welcome') throw new Error('INVALID_MLS_WELCOME');
  // The joined state keeps the package's leaf and signing keys.
  return joinGroup(
    message.welcome,
    decodePublicPackage(own.publicPackage),
    privatePackage(own),
    emptyPskIndex,
    cs,
    undefined,
    undefined,
    groupClientConfig(authMap),
  );
}

/** The fixed suite and protocol, the expected group and epoch, and no group extensions. */
export function assertChannelGroup(state: ClientState, groupId: string, epoch: number): void {
  const context = state.groupContext;
  let actualGroupId: string;
  try {
    actualGroupId = fatalDecoder.decode(context.groupId);
  } catch {
    throw new Error('INVALID_MLS_GROUP');
  }
  if (
    context.version !== 'mls10'
    || context.cipherSuite !== MLS_CIPHERSUITE
    || context.extensions.length !== 0
    || actualGroupId !== groupId
    || context.epoch !== BigInt(epoch)
    || state.groupActiveState.kind !== 'active'
  ) throw new Error('INVALID_MLS_GROUP');
}

/** The channel key of one version: the epoch's exporter for (group, version). */
export async function exportChannelKey(state: ClientState, groupId: string, version: number): Promise<Uint8Array> {
  return mlsExporter(
    state.keySchedule.exporterSecret,
    MLS_GROUP_EXPORTER_LABEL,
    encoder.encode(mlsExporterContext(groupId, version)),
    32,
    await suite(),
  );
}

/** Saved state without earlier epochs; application keys come from the exporter. */
export function encodeChannelGroupState(state: ClientState): string {
  return toBase64(encodeGroupState({ ...state, historicalReceiverData: new Map() }));
}

/** A saved state, authenticating later commits against its own tree. */
export function decodeChannelGroupState(encoded: string): ClientState {
  const state = decode(decodeGroupState, fromBase64(encoded));
  const decoded = { ...state, clientConfig: groupClientConfig(new Map()) };
  return { ...decoded, clientConfig: groupClientConfig(treeAuthMap(decoded)) };
}
