import { channelKeyScopes } from './channel-key-scope';
import { serializeDeviceDecision, serializeHistoryKeyBackup } from '@alparts/shared';
import { api, ApiError } from './api';
import {
  getActiveDevice,
  signDevicePayload,
  saveRecoveredChannelKey,
  exportHistoryKey,
} from './crypto.service';
import { verifiedDirectory } from './directory.service';
import { deriveArchiveKey, wrapArchiveKey, unwrapArchiveKey, parsePasskeyWrap, type PasskeyWrap } from './passkey-vault';
import {
  readSecurityState,
  writeSecurityState,
  deleteSecurityState,
  listSecurityStateNames,
  toBase64,
  fromBase64,
} from './security-storage';
interface RecoveryConfig {
  userId: string;
  generation: string;
  signingKey: string;
  encryptedSecret: string;
  createdAt: string;
  accessConfigured: boolean;
  passkeyWrap?: PasskeyWrap;
}
interface LocalRecovery {
  generation: string;
  key: string;
}
interface RecoveryRecord {
  generation: string;
  channelId: string;
  version: number;
  keyCommitment: string;
  ciphertext: string;
}
/** A record as uploaded. The archive keeps the record itself, not the signature. */
interface SignedRecoveryRecord extends RecoveryRecord {
  signature: string;
}
interface Cursor {
  channelId: string;
  version: number;
}
import { aad, aes, seal, open, recoveryAccess } from './recovery-crypto';
const encoder = new TextEncoder();
/** base64url(SHA-256(bytes)): how records name a key and how a signature names a record. */
async function sha256Base64Url(bytes: Uint8Array): Promise<string> {
  return toBase64(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
function assertRecoveryOwner(owner: { userId: string; deviceId: string }) {
  const current = getActiveDevice();
  if (current.userId !== owner.userId || current.deviceId !== owner.deviceId)
    throw new Error('RECOVERY_SESSION_CHANGED');
}
async function recoveryPage<T>(path: string, body?: unknown): Promise<T> {
  const owner = getActiveDevice();
  for (let attempt = 0; ; attempt++) {
    assertRecoveryOwner(owner);
    try {
      return await api.securityRequest<T>(path, body);
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 429 || attempt >= 2) throw error;
      await new Promise((resolve) =>
        setTimeout(resolve, Math.min(60, Math.max(1, error.retryAfterSeconds ?? 5)) * 1000 + 100),
      );
    }
  }
}
/** onPasskeyPrompt runs just before the browser asks for a passkey, if it does. */
export async function createRecoveryPlan(onPasskeyPrompt?: () => void) {
  const owner = getActiveDevice();
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const generation = crypto.randomUUID();
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const signingKey = JSON.stringify({
    kty: publicJwk.kty,
    crv: publicJwk.crv,
    x: publicJwk.x,
    y: publicJwk.y,
  });
  const privateJwk = encoder.encode(
    JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey)),
  );
  try {
    const encryptedSecret = await seal(
      await aes(raw),
      privateJwk,
      aad(owner.userId, `secret:${generation}:${signingKey}`),
    );
    const passkeys = await api.securityRequest<Array<{ id: string }>>('/auth/passkeys');
    const options = await api.securityRequest<{ rpId: string }>('/auth/passkeys/vault');
    let passkeyWrap: PasskeyWrap | undefined;
    if (passkeys.length > 0) {
      // The passkey keeps only the history key; approving a device takes the code.
      const archive = await deriveArchiveKey(raw, owner.userId, generation);
      try {
        passkeyWrap = await wrapArchiveKey(archive, owner.userId, generation, passkeys.map((key) => key.id), options.rpId, onPasskeyPrompt);
      } catch (error) {
        // A passkey that cannot be used, or one the user declines, must not
        // block a plan that the code alone restores.
        if (
          !(error instanceof Error && error.message === 'PASSKEY_VAULT_UNAVAILABLE')
          && !(error instanceof DOMException && error.name === 'NotAllowedError')
        ) throw error;
      } finally {
        archive.fill(0);
      }
    }
    assertRecoveryOwner(owner);
    const code = Array.from(raw, (b) => b.toString(16).padStart(2, '0'))
      .join('')
      .match(/.{8}/g)!
      .join('-');
    return {
      code,
      generation,
      signingKey,
      encryptedSecret: JSON.stringify({ version: 2, codeSecret: encryptedSecret, ...(passkeyWrap ? { passkeyWrap } : {}) }),
      accessTokenHash: (await recoveryAccess(raw, owner.userId, generation)).accessTokenHash,
      passkeyProtected: passkeyWrap !== undefined,
    };
  } finally {
    raw.fill(0);
    privateJwk.fill(0);
  }
}
function decodeCode(code: string) {
  const hex = code.replace(/[\s-]/g, '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(hex)) throw new Error('INVALID_RECOVERY_CODE');
  return Uint8Array.from(hex.match(/../g)!, (b) => parseInt(b, 16));
}
export async function enableHistoryRecovery(plan: Awaited<ReturnType<typeof createRecoveryPlan>>) {
  const owner = getActiveDevice();
  const directory = await verifiedDirectory(owner.userId);
  const event = {
    kind: 'recovery-config' as const,
    deviceId: plan.generation,
    identityKey: plan.signingKey,
    actorDeviceId: owner.deviceId,
  };
  const signature = await signDevicePayload(serializeDeviceDecision(directory.head, event));
  assertRecoveryOwner(owner);
  await api.securityRequest('/recovery/configure', {
    generation: plan.generation,
    signingKey: plan.signingKey,
    encryptedSecret: plan.encryptedSecret,
    accessTokenHash: plan.accessTokenHash,
    head: directory.head,
    signature,
  });
  const raw = decodeCode(plan.code);
  const archive = await deriveArchiveKey(raw, owner.userId, plan.generation);
  try {
    assertRecoveryOwner(owner);
    await writeSecurityState(owner, 'recovery', {
      generation: plan.generation,
      key: toBase64(archive),
    });
  } finally {
    raw.fill(0);
    archive.fill(0);
  }
  return 0; // Configuration is durable; uploading is separately retryable.
}
export async function getHistoryRecoveryConfiguration() {
  const owner = getActiveDevice();
  const config = await api.securityRequest<Pick<
    RecoveryConfig,
    'generation' | 'signingKey' | 'accessConfigured' | 'passkeyWrap'
  > | null>('/recovery/metadata');
  const directory = await verifiedDirectory(owner.userId);
  if (
    Boolean(config) !== Boolean(directory.recovery) ||
    (config &&
      (directory.recovery?.generation !== config.generation ||
        directory.recovery.signingKey !== config.signingKey))
  )
    throw new Error('DIRECTORY_INVALID');
  return config;
}
export async function disableHistoryRecovery() {
  const owner = getActiveDevice();
  const directory = await verifiedDirectory(owner.userId);
  if (!directory.recovery) throw new Error('RECOVERY_NOT_CONFIGURED');
  const signature = await signDevicePayload(
    serializeDeviceDecision(directory.head, {
      kind: 'recovery-disable',
      deviceId: directory.recovery.generation,
      identityKey: directory.recovery.signingKey,
      actorDeviceId: owner.deviceId,
    }),
  );
  await api.securityRequest('/recovery', { head: directory.head, signature }, 'DELETE');
  await deleteSecurityState(owner, 'recovery');
}
async function encryptedHistoryKey(
  channelId: string,
  version: number,
  raw: Uint8Array,
  local: LocalRecovery,
): Promise<SignedRecoveryRecord> {
  const owner = getActiveDevice();
  const commitment = await sha256Base64Url(raw);
  const encoded = fromBase64(local.key);
  try {
    const ciphertext = await seal(
      await aes(encoded),
      raw,
      aad(owner.userId, `${local.generation}:${channelId}:${version}:${commitment}`),
    );
    // The server cannot read a record, so it accepts one only if this device signed it.
    const signature = await signDevicePayload(
      serializeHistoryKeyBackup({
        userId: owner.userId,
        generation: local.generation,
        channelId,
        version,
        keyCommitment: commitment,
        ciphertextHash: await sha256Base64Url(encoder.encode(ciphertext)),
      }),
    );
    return {
      generation: local.generation,
      channelId,
      version,
      keyCommitment: commitment,
      ciphertext,
      signature,
    };
  } finally {
    encoded.fill(0);
  }
}
const backupKey = (channelId: string, version: number) => `${channelId}:${version}`;
/**
 * Uploads records and returns the versions the archive holds afterwards:
 * those it stored now and those it already had a record of.
 */
async function uploadHistoryRecords(records: SignedRecoveryRecord[]): Promise<Set<string>> {
  const response = await recoveryPage<{ results?: Array<{ channelId: string; version: number; status: string }> }>(
    '/recovery/keys',
    { keys: records },
  );
  const held = new Set<string>();
  if (!Array.isArray(response?.results)) return held;
  for (const result of response.results)
    if (result?.status === 'stored' || result?.status === 'present')
      held.add(backupKey(result.channelId, result.version));
  return held;
}
export async function backupRawHistoryKey(channelId: string, version: number, raw: Uint8Array) {
  const scope = channelKeyScopes.capture(channelId);
  const owner = getActiveDevice();
  const local = await readSecurityState<LocalRecovery>(owner, 'recovery');
  if (!local) return;
  const name = `recovery-sent:${channelId}:${version}`;
  if ((await readSecurityState<string>(owner, name)) === local.generation) {
    await deleteSecurityState(owner, `recovery-backup-pending:${channelId}:${version}`);
    return;
  }
  const record = await encryptedHistoryKey(channelId, version, raw, local);
  channelKeyScopes.assertCurrent(scope);
  if (!(await uploadHistoryRecords([record])).has(backupKey(channelId, version)))
    throw new Error('RECOVERY_BACKUP_UNCONFIRMED');
  await writeSecurityState(owner, name, local.generation, scope);
  await deleteSecurityState(owner, `recovery-backup-pending:${channelId}:${version}`);
}
/** Retries history backups that failed when their key was first accepted. */
export async function retryPendingHistoryBackups(limit = 64): Promise<number> {
  const owner = getActiveDevice();
  if (!await readSecurityState<LocalRecovery>(owner, 'recovery')) return 0;
  let completed = 0;
  for (const name of await listSecurityStateNames(owner, 'recovery-backup-pending:', limit)) {
    const match = /^recovery-backup-pending:([a-f0-9-]{36}):([1-9]\d{0,6})$/.exec(name);
    if (!match) {
      await deleteSecurityState(owner, name);
      continue;
    }
    const [, channelId, versionText] = match;
    const version = Number(versionText);
    try {
      const raw = await exportHistoryKey(channelId, version);
      if (!raw) {
        // The key is no longer available on this device; nothing to back up.
        await deleteSecurityState(owner, name);
        continue;
      }
      try {
        await backupRawHistoryKey(channelId, version, raw);
        completed++;
      } finally {
        raw.fill(0);
      }
    } catch {
      // Keep the marker; the next retry gets another chance.
    }
  }
  return completed;
}
export async function backupAvailableHistory() {
  const owner = getActiveDevice();
  const local = await readSecurityState<LocalRecovery>(owner, 'recovery');
  const config = await getHistoryRecoveryConfiguration();
  if (!local || local.generation !== config?.generation) throw new Error('RECOVERY_CODE_REQUIRED');
  let cursor: Cursor | null = null;
  let count = 0;
  for (let page = 0; page < 1563; page++) {
    const result: { candidates: Cursor[]; cursor: Cursor | null } = await recoveryPage(
      `/recovery/candidates${cursor ? `?channelId=${encodeURIComponent(cursor.channelId)}&version=${encodeURIComponent(String(cursor.version))}` : ''}`,
    );
    const records: SignedRecoveryRecord[] = [];
    const scopes = [];
    for (const candidate of result.candidates) {
      if (
        (await readSecurityState<string>(
          owner,
          `recovery-sent:${candidate.channelId}:${candidate.version}`,
        )) === local.generation
      )
        continue;
      const scope = channelKeyScopes.capture(candidate.channelId);
      const raw = await exportHistoryKey(candidate.channelId, candidate.version);
      if (!raw) continue;
      try {
        records.push(await encryptedHistoryKey(candidate.channelId, candidate.version, raw, local));
        scopes.push(scope);
      } finally {
        raw.fill(0);
      }
    }
    scopes.forEach((scope) => channelKeyScopes.assertCurrent(scope));
    const held = records.length ? await uploadHistoryRecords(records) : new Set<string>();
    for (let i = 0; i < records.length; i++) {
      const record = records[i];
      if (!held.has(backupKey(record.channelId, record.version))) continue;
      await writeSecurityState(
        owner,
        `recovery-sent:${record.channelId}:${record.version}`,
        local.generation,
        scopes[i],
      );
      count++;
    }
    cursor = result.cursor;
    if (!cursor) return count;
  }
  throw new Error('RECOVERY_LIMIT');
}
async function saveRecoveredChannelKeyIfAllowed(channelId: string, version: number, plain: Uint8Array): Promise<boolean> {
  try {
    await saveRecoveredChannelKey(channelId, version, plain);
    return true;
  } catch (error) {
    if (error instanceof Error && /^Channel key scope (is revoked|changed during operation)$/.test(error.message)) return false;
    throw error;
  }
}
/**
 * The key a downloaded record holds, or null when it is not a genuine backup
 * of the version it names. The server stores records it cannot read, so a
 * damaged or foreign record must not stop the others from being restored.
 */
async function openHistoryRecord(
  key: CryptoKey,
  userId: string,
  generation: string,
  record: RecoveryRecord,
): Promise<Uint8Array | null> {
  let plain: Uint8Array | undefined;
  try {
    if (record.generation !== generation) return null;
    plain = await open(
      key,
      record.ciphertext,
      aad(userId, `${record.generation}:${record.channelId}:${record.version}:${record.keyCommitment}`),
    );
    if (plain.length === 32 && (await sha256Base64Url(plain)) === record.keyCommitment) return plain;
  } catch {
    // Falls through: the record counts as one that could not be restored.
  }
  plain?.fill(0);
  return null;
}
/** Restores every record of the archive with its key, then keeps the key for later backups. */
async function restoreRecords(
  owner: { userId: string; deviceId: string },
  generation: string,
  archiveBytes: Uint8Array,
): Promise<{ restored: number; failed: number }> {
  const key = await aes(archiveBytes);
  let cursor: Cursor | null = null;
  let restored = 0;
  let failed = 0;
  for (let page = 0; page < 1563; page++) {
    const result: { keys: RecoveryRecord[]; cursor: Cursor | null } = await recoveryPage(
      `/recovery/keys${cursor ? `?channelId=${encodeURIComponent(cursor.channelId)}&version=${encodeURIComponent(String(cursor.version))}` : ''}`,
    );
    if (result.keys.length > 64) throw new Error('RECOVERY_LIMIT');
    assertRecoveryOwner(owner);
    for (const record of result.keys) {
      const plain = await openHistoryRecord(key, owner.userId, generation, record);
      if (!plain) {
        failed++;
        continue;
      }
      try {
        assertRecoveryOwner(owner);
        // A channel this device may no longer use must not abort the rest
        // of an otherwise valid archive; the archive itself was verified.
        if (await saveRecoveredChannelKeyIfAllowed(record.channelId, record.version, plain)) restored++;
      } finally {
        plain.fill(0);
      }
    }
    cursor = result.cursor;
    if (!cursor) {
      await writeSecurityState(owner, 'recovery', {
        generation,
        key: toBase64(archiveBytes),
      });
      return { restored, failed };
    }
  }
  throw new Error('RECOVERY_LIMIT');
}
/**
 * Restores history on this device, already approved, with the passkey the
 * history key was wrapped with. The passkey cannot approve a device.
 */
export async function restoreHistoryWithPasskey(): Promise<{ restored: number; failed: number }> {
  const owner = getActiveDevice();
  if (!owner.approved) throw new Error('RECOVERY_CODE_REQUIRED');
  const metadata = await getHistoryRecoveryConfiguration();
  if (!metadata) throw new Error('RECOVERY_NOT_CONFIGURED');
  const archiveBytes = await unwrapArchiveKey(metadata.passkeyWrap, owner.userId, metadata.generation);
  try {
    return await restoreRecords(owner, metadata.generation, archiveBytes);
  } finally {
    archiveBytes.fill(0);
  }
}
/**
 * Wraps the history key this device keeps for the current plan with a
 * passkey, so that approved devices can restore history with it. A wrap made
 * earlier, possibly with a passkey since deleted, is replaced.
 */
export async function protectHistoryWithPasskey(onPasskeyPrompt?: () => void) {
  const owner = getActiveDevice();
  const [local, config, directory, passkeys, options] = await Promise.all([
    readSecurityState<LocalRecovery>(owner, 'recovery'),
    api.securityRequest<RecoveryConfig | null>('/recovery'),
    verifiedDirectory(owner.userId),
    api.securityRequest<Array<{ id: string }>>('/auth/passkeys'),
    api.securityRequest<{ rpId: string }>('/auth/passkeys/vault'),
  ]);
  if (
    !config ||
    directory.recovery?.generation !== config.generation ||
    directory.recovery.signingKey !== config.signingKey
  )
    throw new Error('DIRECTORY_INVALID');
  // Before the archive key existed, the archive was sealed with the code itself:
  // only a new code can be wrapped.
  if (!config.encryptedSecret.startsWith('{')) throw new Error('RECOVERY_PLAN_OUTDATED');
  if (!local || local.generation !== config.generation) throw new Error('RECOVERY_CODE_REQUIRED');
  if (!passkeys.length) throw new Error('PASSKEY_REQUIRED');
  const archive = fromBase64(local.key);
  try {
    const passkeyWrap = await wrapArchiveKey(archive, owner.userId, config.generation, passkeys.map((key) => key.id), options.rpId, onPasskeyPrompt);
    assertRecoveryOwner(owner);
    await api.securityRequest('/recovery/passkey', { generation: config.generation, passkeyWrap });
  } finally {
    archive.fill(0);
  }
}
/**
 * Restores history with the recovery code, approving this device first if it
 * is not yet approved. Returns how many keys were restored, and how many
 * records could not be.
 */
export async function restoreHistory(code: string): Promise<{ restored: number; failed: number }> {
  const owner = getActiveDevice();
  const metadata = await api.securityRequest<Pick<
    RecoveryConfig,
    'generation' | 'signingKey' | 'accessConfigured' | 'passkeyWrap'
  > | null>('/recovery/metadata');
  if (!metadata) throw new Error('RECOVERY_NOT_CONFIGURED');
  const directory = await verifiedDirectory(owner.userId);
  if (
    directory.recovery?.generation !== metadata.generation ||
    directory.recovery.signingKey !== metadata.signingKey
  )
    throw new Error('DIRECTORY_INVALID');
  const raw = decodeCode(code);
  let privateBytes: Uint8Array | undefined;
  let archiveBytes: Uint8Array | undefined;
  try {
    const access = await recoveryAccess(raw, owner.userId, metadata.generation);
    const config = owner.approved
      ? await api.securityRequest<RecoveryConfig>('/recovery')
      : await api.securityRequest<RecoveryConfig>('/recovery/unlock', {
          generation: metadata.generation,
          token: access.token,
        });
    if (
      !config ||
      config.generation !== metadata.generation ||
      config.signingKey !== metadata.signingKey
    )
      throw new Error('DIRECTORY_INVALID');
    let codeSecret = config.encryptedSecret;
    if (codeSecret.startsWith('{')) {
      const secret = JSON.parse(codeSecret);
      if (secret.version !== 2 || typeof secret.codeSecret !== 'string') throw new Error('INVALID_RECOVERY');
      if (secret.passkeyWrap !== undefined) parsePasskeyWrap(secret.passkeyWrap);
      codeSecret = secret.codeSecret;
      archiveBytes = await deriveArchiveKey(raw, owner.userId, config.generation);
    } else archiveBytes = new Uint8Array(raw);
    privateBytes = await open(
      await aes(raw),
      codeSecret,
      aad(owner.userId, `secret:${config.generation}:${config.signingKey}`),
    );
    const signing = await crypto.subtle.importKey(
      'jwk',
      JSON.parse(new TextDecoder().decode(privateBytes)),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    );
    if (owner.approved && !config.accessConfigured) {
      await api.securityRequest('/recovery/access', {
        generation: config.generation,
        accessTokenHash: access.accessTokenHash,
      });
    }
    if (!owner.approved) {
      const signature = toBase64(
        new Uint8Array(
          await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            signing,
            encoder.encode(
              serializeDeviceDecision(directory.head, {
                kind: 'recovery',
                deviceId: owner.deviceId,
                identityKey: owner.identityKey,
                actorDeviceId: config.generation,
              }),
            ),
          ),
        ),
      );
      await api.securityRequest('/recovery/restore-device', {
        generation: config.generation,
        head: directory.head,
        signature,
      });
      const approved = await verifiedDirectory(owner.userId);
      if (!approved.devices[owner.deviceId]?.approved) throw new Error('DIRECTORY_INVALID');
      assertRecoveryOwner(owner);
      owner.approved = true;
    }
    return await restoreRecords(owner, config.generation, archiveBytes);
  } finally {
    raw.fill(0);
    privateBytes?.fill(0);
    archiveBytes?.fill(0);
  }
}
