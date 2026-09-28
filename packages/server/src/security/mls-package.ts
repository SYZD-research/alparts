import { decodeMlsMessage, getCiphersuiteFromName, getCiphersuiteImpl } from 'ts-mls';
import { verifyKeyPackage } from 'ts-mls/keyPackage.js';
import { verifyLeafNodeSignatureKeyPackage } from 'ts-mls/leafNode.js';
import { MLS_CIPHERSUITE } from '@alparts/shared';

const suite = getCiphersuiteImpl(getCiphersuiteFromName(MLS_CIPHERSUITE));

/** Validate RFC 9420 KeyPackage and leaf signatures before accepting a member's package. */
export async function validateMlsKeyPackage(
  encoded: string,
  deviceId: string,
  now = Date.now(),
): Promise<void> {
  try {
    if (encoded.length > 16_384) throw new Error();
    const bytes = Buffer.from(encoded, 'base64');
    if (bytes.toString('base64') !== encoded) throw new Error();
    const decoded = decodeMlsMessage(bytes, 0);
    if (!decoded || decoded[1] !== bytes.length) throw new Error();
    const message = decoded[0];
    if (message.version !== 'mls10' || message.wireformat !== 'mls_key_package') throw new Error();
    const pkg = message.keyPackage;
    const leaf = pkg.leafNode;
    const seconds = BigInt(Math.floor(now / 1000));
    if (
      pkg.version !== 'mls10' ||
      pkg.cipherSuite !== MLS_CIPHERSUITE ||
      leaf.leafNodeSource !== 'key_package' ||
      leaf.credential.credentialType !== 'basic' ||
      !Buffer.from(leaf.credential.identity).equals(Buffer.from(deviceId)) ||
      leaf.lifetime.notBefore > seconds ||
      leaf.lifetime.notAfter <= seconds ||
      leaf.lifetime.notAfter - leaf.lifetime.notBefore > 8n * 24n * 3600n ||
      !leaf.capabilities.versions.includes('mls10') ||
      !leaf.capabilities.ciphersuites.includes(MLS_CIPHERSUITE) ||
      !leaf.capabilities.credentials.includes('basic') ||
      pkg.extensions.length ||
      leaf.extensions.length ||
      pkg.initKey.length !== 32 ||
      leaf.hpkePublicKey.length !== 32 ||
      leaf.signaturePublicKey.length !== 32 ||
      Buffer.from(pkg.initKey).equals(Buffer.from(leaf.hpkePublicKey))
    )
      throw new Error();
    const cs = await suite;
    if (
      !(await verifyKeyPackage(pkg, cs.signature)) ||
      !(await verifyLeafNodeSignatureKeyPackage(leaf, cs.signature))
    )
      throw new Error();
    // Import alone accepts low-order X25519 points on some providers. A trial
    // encapsulation also checks that each key can produce a nonzero DH secret.
    for (const key of [pkg.initKey, leaf.hpkePublicKey]) {
      await cs.hpke.seal(await cs.hpke.importPublicKey(key), new Uint8Array(), new Uint8Array());
    }
  } catch {
    throw new Error('INVALID_MLS');
  }
}
