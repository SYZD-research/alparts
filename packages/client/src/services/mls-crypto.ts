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
  emptyPskIndex,
  type KeyPackage,
  type PrivateKeyPackage,
  type ClientState,
  type Decoder,
} from 'ts-mls';
import { defaultClientConfig } from 'ts-mls/clientConfig.js';
import { MLS_CIPHERSUITE } from '@alparts/shared';
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
    { notBefore: now - 300n, notAfter: now + 604800n },
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
