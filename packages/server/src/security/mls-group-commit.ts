import {
  decodeMlsMessage,
  encodeMlsMessage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  type KeyPackage,
} from 'ts-mls';
import { makeKeyPackageRef } from 'ts-mls/keyPackage.js';
import { verifyLeafNodeSignature } from 'ts-mls/leafNode.js';
import { MLS_CIPHERSUITE } from '@alparts/shared';
import { validateMlsKeyPackage } from './mls-package.js';

const suite = getCiphersuiteImpl(getCiphersuiteFromName(MLS_CIPHERSUITE));
const base64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');

/** Public keys and lifetime of a validated member package. */
export interface MemberPackageKeys {
  initKey: string;
  encryptionKey: string;
  signatureKey: string;
  notBefore: Date;
  notAfter: Date;
  /** KeyPackageRef, as a Welcome names the new member. */
  reference: string;
}

/** What the server can read from a PublicMessage commit without group secrets. */
export interface DecodedGroupCommit {
  groupId: Uint8Array;
  epoch: bigint;
  senderLeafIndex: number;
  /** Canonical base64 of each Add's KeyPackage, in proposal order. */
  addPackages: string[];
  /** Leaf of each Remove, in proposal order. */
  removedLeaves: number[];
  path: {
    identity: string;
    signatureKey: string;
    encryptionKey: string;
    /** HPKE keys the UpdatePath gives the parent nodes above the leaf. */
    nodeKeys: string[];
  } | null;
}

function decodeWhole(encoded: string) {
  const bytes = Buffer.from(encoded, 'base64');
  if (!encoded || bytes.toString('base64') !== encoded) throw new Error('INVALID_MLS');
  const decoded = decodeMlsMessage(bytes, 0);
  if (!decoded || decoded[1] !== bytes.length || decoded[0].version !== 'mls10') {
    throw new Error('INVALID_MLS');
  }
  return decoded[0];
}

/** KeyPackageRef of a package's canonical encoding, as a Welcome names it. */
async function packageReference(pkg: KeyPackage): Promise<string> {
  return base64(await makeKeyPackageRef(pkg, (await suite).hash));
}

/** validateMlsKeyPackage, plus the keys the server compares across leaves. */
export async function readMemberPackage(
  encoded: string,
  deviceId: string,
  now = Date.now(),
): Promise<MemberPackageKeys> {
  const pkg = await validateMlsKeyPackage(encoded, deviceId, now);
  const leaf = pkg.leafNode;
  if (leaf.leafNodeSource !== 'key_package') throw new Error('INVALID_MLS');
  return {
    initKey: base64(pkg.initKey),
    encryptionKey: base64(leaf.hpkePublicKey),
    signatureKey: base64(leaf.signaturePublicKey),
    notBefore: new Date(Number(leaf.lifetime.notBefore) * 1000),
    notAfter: new Date(Number(leaf.lifetime.notAfter) * 1000),
    reference: await packageReference(pkg),
  };
}

/**
 * The keys of a stored member package. It was fully validated when it was
 * published, so only its KeyPackageRef is computed here.
 */
export async function storedMemberPackageKeys(
  row: Omit<MemberPackageKeys, 'reference'> & { keyPackage: string },
): Promise<MemberPackageKeys> {
  const message = decodeWhole(row.keyPackage);
  if (message.wireformat !== 'mls_key_package') throw new Error('INVALID_MLS');
  return {
    initKey: row.initKey,
    encryptionKey: row.encryptionKey,
    signatureKey: row.signatureKey,
    notBefore: row.notBefore,
    notAfter: row.notAfter,
    reference: await packageReference(message.keyPackage),
  };
}

/** The add-time init key of a stored member package (reserved while it is a member). */
export function storedPackageInitKey(encoded: string): string {
  const message = decodeWhole(encoded);
  if (message.wireformat !== 'mls_key_package') throw new Error('INVALID_MLS');
  return base64(message.keyPackage.initKey);
}

/**
 * Import alone accepts low-order X25519 points; a trial encapsulation fails
 * for them. A low-order key in the tree would make later commits fail.
 */
async function usableHpkeKey(key: Uint8Array): Promise<boolean> {
  const cs = await suite;
  try {
    await cs.hpke.seal(await cs.hpke.importPublicKey(key), new Uint8Array(), new Uint8Array());
    return true;
  } catch {
    return false;
  }
}

/**
 * Decode a commit envelope's MLSMessage. Only by-value Add and Remove
 * proposals from a member, with no authenticated data, are accepted. An
 * UpdatePath leaf must carry a basic credential and a valid leaf signature,
 * and the path's HPKE keys must be distinct, usable X25519 keys.
 */
export async function decodeGroupCommit(encoded: string): Promise<DecodedGroupCommit> {
  let message;
  try {
    message = decodeWhole(encoded);
  } catch {
    throw new Error('INVALID_MLS');
  }
  if (message.wireformat !== 'mls_public_message') throw new Error('INVALID_MLS');
  const publicMessage = message.publicMessage;
  const content = publicMessage.content;
  if (
    publicMessage.senderType !== 'member'
    || content.sender.senderType !== 'member'
    || content.contentType !== 'commit'
    || content.authenticatedData.length !== 0
  ) throw new Error('INVALID_MLS');
  const senderLeafIndex = content.sender.leafIndex;
  const addPackages: string[] = [];
  const removedLeaves: number[] = [];
  for (const entry of content.commit.proposals) {
    if (entry.proposalOrRefType !== 'proposal') throw new Error('INVALID_MLS');
    const proposal = entry.proposal;
    if (proposal.proposalType === 'add') {
      addPackages.push(base64(encodeMlsMessage({
        version: 'mls10',
        wireformat: 'mls_key_package',
        keyPackage: proposal.add.keyPackage,
      })));
    } else if (proposal.proposalType === 'remove') {
      removedLeaves.push(proposal.remove.removed);
    } else {
      throw new Error('INVALID_MLS');
    }
  }
  let path: DecodedGroupCommit['path'] = null;
  const updatePath = content.commit.path;
  if (updatePath) {
    const leaf = updatePath.leafNode;
    if (
      leaf.leafNodeSource !== 'commit'
      || leaf.credential.credentialType !== 'basic'
      || leaf.hpkePublicKey.length !== 32
      || leaf.signaturePublicKey.length !== 32
      || !await verifyLeafNodeSignature(leaf, content.groupId, senderLeafIndex, (await suite).signature)
    ) throw new Error('INVALID_MLS');
    let identity: string;
    try {
      identity = new TextDecoder('utf-8', { fatal: true }).decode(leaf.credential.identity);
    } catch {
      throw new Error('INVALID_MLS');
    }
    // Every HPKE key of the path enters the ratchet tree, where ts-mls
    // requires all keys to differ.
    const nodeKeys = updatePath.nodes.map((node) => node.hpkePublicKey);
    const keys = [leaf.hpkePublicKey, ...nodeKeys];
    if (
      nodeKeys.some((key) => key.length !== 32)
      || new Set(keys.map(base64)).size !== keys.length
    ) throw new Error('INVALID_MLS');
    for (const key of keys) {
      if (!await usableHpkeKey(key)) throw new Error('INVALID_MLS');
    }
    path = {
      identity,
      signatureKey: base64(leaf.signaturePublicKey),
      encryptionKey: base64(leaf.hpkePublicKey),
      nodeKeys: nodeKeys.map(base64),
    };
  }
  return {
    groupId: content.groupId,
    epoch: content.epoch,
    senderLeafIndex,
    addPackages,
    removedLeaves,
    path,
  };
}

/** KeyPackageRefs of a Welcome's new members, in order. */
export function decodeGroupWelcome(encoded: string): string[] {
  let message;
  try {
    message = decodeWhole(encoded);
  } catch {
    throw new Error('INVALID_MLS');
  }
  if (message.wireformat !== 'mls_welcome' || message.welcome.cipherSuite !== MLS_CIPHERSUITE) {
    throw new Error('INVALID_MLS');
  }
  return message.welcome.secrets.map((secret) => base64(secret.newMember));
}
