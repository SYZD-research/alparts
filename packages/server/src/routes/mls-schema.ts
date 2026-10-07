import { z } from 'zod';
import {
  MAX_KEY_RECIPIENTS,
  MAX_MLS_COMMIT_LENGTH,
  MAX_MLS_KEY_PACKAGE_LENGTH,
  MAX_MLS_WELCOME_LENGTH,
  MAX_WORKSPACE_MEMBERS,
} from '@alparts/shared';

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
