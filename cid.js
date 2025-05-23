import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';

/**
 * Generates a CID (Controlled Identifier) document according to the W3C specification
 * @param {string} controller - The DID of the controller
 * @param {Object} options - Options for key generation
 * @param {boolean} [options.includeEd25519=true] - Whether to include Ed25519 verification method
 * @param {boolean} [options.includeBBS=true] - Whether to include BBS+ verification method
 * @returns {Promise<{cid: Object, privateKeys: Object}>} - The CID document and associated private keys
 */
export async function generateCID(controller, options = {}) {
  const {
    includeEd25519 = true,
    includeBBS = true
  } = options;

  const cid = {
    '@context': "https://www.w3.org/ns/cid/v1",
    id: controller,
    verificationMethod: [],
    authentication: [],
    assertionMethod: [],
    capabilityInvocation: [],
    capabilityDelegation: []
  };

  let i = 0;

  const privateKeys = {};

  // Generate Ed25519 key pair if requested
  if (includeEd25519) {
    const ed25519KeyPair = await Ed25519VerificationKey2020.generate({
      id: `${controller}#key-${i++}`,
      controller: controller
    });
    const verificationMethod = {
      '@context': 'https://w3id.org/security/multikey/v1',
      id: `${controller}#key-${i}`,
      type: 'Multikey',
      controller: controller,
      publicKeyMultibase: ed25519KeyPair.publicKeyMultibase
    };

    cid.verificationMethod.push(verificationMethod);
    cid.authentication.push(verificationMethod.id);
    cid.assertionMethod.push(verificationMethod.id);
    cid.capabilityInvocation.push(verificationMethod.id);
    cid.capabilityDelegation.push(verificationMethod.id);

    privateKeys[verificationMethod.id] = ed25519KeyPair.privateKeyMultibase;
  }

  // Generate BBS+ key pair if requested
  if (includeBBS) {
    const bbsKeyPair = await Bls12381Multikey.generateBbsKeyPair({
      id: `${controller}#key-${i++}`,
      controller: controller,
      algorithm: Bls12381Multikey.ALGORITHMS.BBS_BLS12381_SHA256
    });
    const verificationMethod = {
      '@context': 'https://w3id.org/security/multikey/v1',
      id: `${controller}#key-${i}`,
      type: 'Multikey',
      controller: controller,
      publicKeyMultibase: bbsKeyPair.publicKeyMultibase
    };

    cid.verificationMethod.push(verificationMethod);
    cid.authentication.push(verificationMethod.id);
    cid.assertionMethod.push(verificationMethod.id);
    cid.capabilityInvocation.push(verificationMethod.id);
    cid.capabilityDelegation.push(verificationMethod.id);

    privateKeys[verificationMethod.id] = bbsKeyPair.secretKeyMultibase;

  }

  return { cid, privateKeys };
}
