import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import {
  generateKeyPackage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  encodeMlsMessage,
  type KeyPackage,
} from 'ts-mls';
import { signKeyPackage } from 'ts-mls/keyPackage.js';
import { MLS_CIPHERSUITE, Permissions } from '@alparts/shared';
import { validateMlsKeyPackage } from './mls-package.js';
import { consumeLoginChallenge, issueLoginChallenge } from './login-challenge.js';
import { normalizeEmail } from './email.js';
import { createHmac } from 'node:crypto';
import bcrypt from 'bcryptjs';
import { protectPasswordHash, passwordSalt } from './password-pepper.js';
import {
  hashPassword,
  verifyPassword,
  verifyPasswordForUpgrade,
  runPublicAuthentication,
  closePasswordWorkers,
} from './password-work.js';

process.env.PASSWORD_PEPPER = 'audit2-test-only-independent-password-pepper';
process.env.DATABASE_URL ||= 'postgres://test:test@127.0.0.1:5432/alparts_test';
process.env.S3_ACCESS_KEY ||= 'test-access-key';
process.env.S3_SECRET_KEY ||= 'test-secret-key';
process.env.AUDIT_INTEGRITY_KEY ||= 'test-audit-integrity-key-at-least-32-bytes';
after(closePasswordWorkers);

describe('second audit regressions', () => {
  it('protects bcrypt hashes with an independent secret and rejects weak/legacy verification', async () => {
    const raw = '$2b$12$DuhNW97PNP4tI0drdrcUqexxVq.nFCoTXyiFW3mvHNmBgkM7guOJq';
    const protectedHash = protectPasswordHash(raw);
    assert.equal(passwordSalt(protectedHash), raw.slice(0, 29));
    assert.ok(!protectedHash.includes(raw.slice(29)));
    assert.throws(() => protectPasswordHash(raw.replace('$12$', '$04$')), /UNSUPPORTED/);
    await assert.rejects(verifyPassword('test-password', raw), /UNSUPPORTED/);
    const hash = await hashPassword('correct-test-password', 12);
    assert.equal(await verifyPassword('correct-test-password', hash), true);
    assert.equal(await verifyPassword('wrong-test-password', hash), false);
    const previous = process.env.PASSWORD_PEPPER;
    try {
      process.env.PASSWORD_PEPPER = 'different-test-only-independent-password-pepper';
      assert.equal(await verifyPassword('correct-test-password', hash), false);
    } finally {
      process.env.PASSWORD_PEPPER = previous;
    }
  });

  it('rewraps credentials protected by a retired pepper and rejects unknown peppers', async () => {
    const original = process.env.PASSWORD_PEPPER!;
    const legacy = await hashPassword('rotated-test-password', 12);
    const legacyV1 = `p1:${legacy.split(':')[2]}:${createHmac('sha256', original)
      .update('alparts.password.pepper.v1\0').update(bcrypt.hashSync('rotated-test-password', passwordSalt(legacy))).digest('base64url')}`;
    try {
      process.env.PASSWORD_PEPPER = 'rotated-test-only-independent-password-pepper';
      assert.deepEqual(await verifyPasswordForUpgrade('rotated-test-password', legacy), { valid: false });
      process.env.PASSWORD_PEPPER_PREVIOUS = original;
      for (const stored of [legacy, legacyV1]) {
        const match = await verifyPasswordForUpgrade('rotated-test-password', stored);
        assert.equal(match.valid, true);
        assert.match(match.upgradedHash!, /^p2:/);
        assert.deepEqual(await verifyPasswordForUpgrade('rotated-test-password', match.upgradedHash!), { valid: true });
        assert.deepEqual(await verifyPasswordForUpgrade('wrong-test-password', stored), { valid: false });
      }
      delete process.env.PASSWORD_PEPPER_PREVIOUS;
      assert.equal(await verifyPassword('rotated-test-password', legacy), false);
      process.env.PASSWORD_PEPPER_PREVIOUS = process.env.PASSWORD_PEPPER;
      await assert.rejects(verifyPassword('rotated-test-password', legacy), /PREVIOUS_INVALID/);
    } finally {
      process.env.PASSWORD_PEPPER = original;
      delete process.env.PASSWORD_PEPPER_PREVIOUS;
    }
  });

  it('reserves credential workers and audit admission when public authentication is full', async () => {
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const publicWork = Array.from({ length: 2 }, () =>
      runPublicAuthentication(async () => {
        await hashPassword('untrusted-password-attempt', 12);
        await held;
      }),
    );
    await new Promise((resolve) => setImmediate(resolve));
    try {
      await assert.rejects(
        runPublicAuthentication(async () => undefined),
        /AUTH_CAPACITY/,
      );
      const hash = await hashPassword('authenticated-step-up-password', 12);
      assert.equal(await verifyPassword('authenticated-step-up-password', hash), true);
    } finally {
      release();
      await Promise.all(publicWork);
    }
  });

  it('prevents override self-expansion, upper-role lockout, and granting absent permissions', async () => {
    const { assertOverrideRoleAuthority } = await import(
      '../services/permission-override.service.js'
    );
    const actor = {
      isOwner: false,
      permissionMask: Permissions.VIEW_CHANNELS | Permissions.MANAGE_CHANNELS,
      highestPosition: 50,
    };
    assert.throws(
      () =>
        assertOverrideRoleAuthority(
          actor,
          { name: 'self', position: 50 },
          Permissions.VIEW_CHANNELS,
        ),
      /NOT_AUTHORIZED/,
    );
    assert.throws(
      () =>
        assertOverrideRoleAuthority(
          actor,
          { name: 'Administrator', position: 100 },
          Permissions.VIEW_CHANNELS,
        ),
      /NOT_AUTHORIZED/,
    );
    assert.throws(
      () =>
        assertOverrideRoleAuthority(
          actor,
          { name: 'Member', position: 10 },
          Permissions.DELETE_MESSAGES,
        ),
      /NOT_AUTHORIZED/,
    );
    assert.doesNotThrow(() =>
      assertOverrideRoleAuthority(
        actor,
        { name: 'Member', position: 10 },
        Permissions.VIEW_CHANNELS,
      ),
    );
    assert.throws(
      () =>
        assertOverrideRoleAuthority(
          { ...actor, isOwner: true },
          { name: 'Owner', position: 100 },
          0,
        ),
      /NOT_AUTHORIZED/,
    );
  });

  it('allows a bounded work proof through account throttling without transferable or replayable grants', () => {
    const proof =
      'eyJiaW5kaW5nIjoidGVzdC1pcDphY2NvdW50IiwiZXhwaXJlcyI6MTIxMDAwLCJub25jZSI6InRlc3Qtb25seS1maXhlZC1jaGFsbGVuZ2UifQ.s5u_ONsJcVB-NYM54lLUPcw2VY5Io7alM1DC4YzuJr0.766524';
    assert.equal(consumeLoginChallenge('other-ip:account', proof, 1000), false);
    assert.equal(consumeLoginChallenge('test-ip:other-account', proof, 1000), false);
    assert.equal(consumeLoginChallenge('test-ip:account', proof, 121000), false);
    assert.equal(
      consumeLoginChallenge('test-ip:account', proof.replace('766524', '0'), 1000),
      false,
    );
    assert.equal(consumeLoginChallenge('test-ip:account', proof, 1000), true);
    assert.equal(consumeLoginChallenge('test-ip:account', proof, 1000), false);
    const fresh = issueLoginChallenge('test-ip:account', 1000);
    assert.equal(fresh.difficulty, 22);
    assert.notEqual(fresh.token, proof.substring(0, proof.lastIndexOf('.')));
  });

  it('refuses to serve when a non-production runtime lacks its external checkpoint', async () => {
    const { config } = await import('../config/index.js');
    const { createApp } = await import('../app.js');
    const audit = config.audit as { checkpointPath: string | null; checkpointRequired: boolean };
    const before = { ...audit };
    try {
      audit.checkpointPath = null;
      audit.checkpointRequired = false;
      assert.throws(() => createApp(), /AUDIT_CHECKPOINT_REQUIRED/);
    } finally { Object.assign(audit, before); }
  });

  it('uses the same NFC form for login, invitations, and budgets', () => {
    assert.equal(normalizeEmail('  CAFÉ@example.test '), normalizeEmail('cafe\u0301@EXAMPLE.TEST'));
  });

  it('verifies native package and leaf signatures, lifetime, credential and usable init keys', async () => {
    const cs = await getCiphersuiteImpl(getCiphersuiteFromName(MLS_CIPHERSUITE));
    const device = '00000000-0000-4000-8000-000000000001';
    const now = BigInt(Math.floor(Date.now() / 1000));
    const pair = await generateKeyPackage(
      { credentialType: 'basic', identity: new TextEncoder().encode(device) },
      {
        versions: ['mls10'],
        ciphersuites: [MLS_CIPHERSUITE],
        credentials: ['basic'],
        extensions: [],
        proposals: [],
      },
      { notBefore: now - 300n, notAfter: now + 604800n },
      [],
      cs,
    );
    const encode = (keyPackage: KeyPackage) =>
      Buffer.from(
        encodeMlsMessage({ version: 'mls10', wireformat: 'mls_key_package', keyPackage }),
      ).toString('base64');
    const encoded = encode(pair.publicPackage);
    await validateMlsKeyPackage(encoded, device);
    await assert.rejects(
      validateMlsKeyPackage(encoded, device, Number(now + 604800n) * 1000),
      /INVALID_MLS/,
    );
    await assert.rejects(validateMlsKeyPackage(encoded, 'another-device'), /INVALID_MLS/);
    const native = structuredClone(pair.publicPackage);
    native.signature[0] ^= 1;
    await assert.rejects(validateMlsKeyPackage(encode(native), device), /INVALID_MLS/);
    const leaf = structuredClone(pair.publicPackage);
    leaf.leafNode.signature[0] ^= 1;
    const signedLeaf = await signKeyPackage(
      leaf,
      pair.privatePackage.signaturePrivateKey,
      cs.signature,
    );
    await assert.rejects(validateMlsKeyPackage(encode(signedLeaf), device), /INVALID_MLS/);
    for (const key of [new Uint8Array(32), pair.publicPackage.leafNode.hpkePublicKey]) {
      const broken = await signKeyPackage(
        { ...pair.publicPackage, initKey: key },
        pair.privatePackage.signaturePrivateKey,
        cs.signature,
      );
      await assert.rejects(validateMlsKeyPackage(encode(broken), device), /INVALID_MLS/);
    }
    await assert.rejects(
      validateMlsKeyPackage(
        Buffer.concat([Buffer.from(encoded, 'base64'), Buffer.from([0])]).toString('base64'),
        device,
      ),
      /INVALID_MLS/,
    );
  });
});
