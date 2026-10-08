import { z } from 'zod';
import {
  MAX_KEY_RECIPIENTS,
  MAX_MLS_COMMIT_LENGTH,
  MAX_MLS_KEY_PACKAGE_LENGTH,
  MAX_MLS_WELCOME_LENGTH,
  MAX_WORKSPACE_MEMBERS,
} from '@alparts/shared';
import { MAX_MLS_GROUP_COMMIT_PAGE } from '../security/limits.js';

/** Signed group proposals carry every member's public package and the Welcome. */
export const MLS_EPOCH_BODY_BYTES = 2 * 1024 * 1024;

const encoded = z
  .string()
  .min(1)
  .regex(/^[A-Za-z0-9+/]+={0,2}$/);
export const mlsSignature = encoded.length(88);
export const mlsVersion = z.number().int().min(1).max(1_000_000);
export const mlsPackage = z
  .object({
    packageId: z.string().uuid(),
    keyPackage: encoded.max(MAX_MLS_KEY_PACKAGE_LENGTH),
    signature: mlsSignature,
  })
  .strict();
const member = mlsPackage
  .extend({
    deviceId: z.string().uuid(),
    userId: z.string().uuid(),
    identityKey: z.string().max(16_384),
  })
  .strict();
export const mlsEpoch = z
  .object({
    channelId: z.string().uuid(),
    version: mlsVersion,
    previousVersion: z.number().int().min(0).max(1_000_000),
    previousTranscript: z.string().regex(/^[a-f0-9]{64}$/),
    keyCommitment: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    welcome: z.string().max(MAX_MLS_WELCOME_LENGTH),
    commit: encoded.max(MAX_MLS_COMMIT_LENGTH),
    roster: z.array(member).min(1).max(MAX_KEY_RECIPIENTS),
    directoryHeads: z
      .array(
        z
          .object({
            userId: z.string().uuid(),
            sequence: z.number().int().min(1).max(8192),
            hash: z.string().regex(/^[a-f0-9]{64}$/),
          })
          .strict(),
      )
      .min(1)
      .max(MAX_WORKSPACE_MEMBERS),
    distributorDeviceId: z.string().uuid(),
    signature: mlsSignature,
  })
  .strict();
export const mlsEpochProposal = z
  .object({
    epoch: mlsEpoch,
    freshStartSignature: mlsSignature.optional(),
    keys: z
      .array(
        z
          .object({
            deviceId: z.string().uuid(),
            encryptedKey: encoded.max(2048),
            signature: mlsSignature,
          })
          .strict(),
      )
      .min(1)
      .max(MAX_KEY_RECIPIENTS),
  })
  .strict();

// === Continuous channel groups (group protocol 4) ===

export const mlsMemberPackageRequest = mlsPackage.extend({ rejoin: z.boolean().optional() }).strict();
export const mlsGroupCommit = z
  .object({
    channelId: z.string().uuid(),
    version: mlsVersion,
    previousVersion: z.number().int().min(0).max(1_000_000),
    previousTranscript: z.string().regex(/^[a-f0-9]{64}$/),
    groupId: z.string().min(1).max(256),
    epoch: z.number().int().min(1).max(1_000_000),
    kind: z.enum(['create', 'commit']),
    keyCommitment: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    commit: encoded.max(MAX_MLS_COMMIT_LENGTH),
    welcome: z.union([z.literal(''), encoded.max(MAX_MLS_WELCOME_LENGTH)]),
    added: z.array(member).max(MAX_KEY_RECIPIENTS),
    removed: z.array(z.string().uuid()).max(MAX_KEY_RECIPIENTS),
    // Adds fill the lowest free leaf, so no leaf index reaches the roster bound.
    members: z
      .array(
        z
          .object({
            deviceId: z.string().uuid(),
            userId: z.string().uuid(),
            leafIndex: z.number().int().min(0).max(MAX_KEY_RECIPIENTS - 1),
          })
          .strict(),
      )
      .min(1)
      .max(MAX_KEY_RECIPIENTS),
    directoryHeads: z
      .array(
        z
          .object({
            userId: z.string().uuid(),
            sequence: z.number().int().min(1).max(8192),
            hash: z.string().regex(/^[a-f0-9]{64}$/),
          })
          .strict(),
      )
      .min(1)
      .max(MAX_WORKSPACE_MEMBERS),
    committerDeviceId: z.string().uuid(),
    signature: mlsSignature,
  })
  .strict();
export const mlsGroupCommitRequest = z.object({ commit: mlsGroupCommit }).strict();
export const mlsGroupFreshStartRequest = z
  .object({ commit: mlsGroupCommit, freshStartSignature: mlsSignature })
  .strict();
export const mlsGroupCommitsQuery = z
  .object({
    after: z.coerce.number().int().min(0).max(1_000_000),
    limit: z.coerce.number().int().min(1).max(MAX_MLS_GROUP_COMMIT_PAGE).default(MAX_MLS_GROUP_COMMIT_PAGE),
  })
  .strict();
export const mlsGroupMembersQuery = z
  .object({ version: z.coerce.number().int().min(1).max(1_000_000) })
  .strict();
export const mlsGroupPendingQuery = z.object({ cursor: z.string().uuid().optional() }).strict();
