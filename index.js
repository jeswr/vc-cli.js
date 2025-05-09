import { generateCID } from './cid.js';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as bbs2023Cryptosuite from '@digitalbazaar/bbs-2023-cryptosuite';
import { DataIntegrityProof } from '@digitalbazaar/data-integrity';
import jsigs from 'jsonld-signatures';
import { URL } from 'node:url';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import { _createVerifyData } from './lib/verify.js';
import * as vc from '@digitalbazaar/vc';
import { documentLoader as defaultDocumentLoader } from './documentLoader.js';
import { write } from '@jeswr/pretty-turtle';
import dereference from 'rdf-dereference-store';
import { DataFactory } from 'n3';
import { randomUUID, createHash } from 'node:crypto';
import { createDocumentLoader } from './documentLoader.js';

const {
  createSignCryptosuite,
  createVerifyCryptosuite,
  createDiscloseCryptosuite,
} = bbs2023Cryptosuite;
const { purposes: { AssertionProofPurpose } } = jsigs;

// Helper function to sanitize URL by removing fragment
const sanitizeUrl = (url) => {
  try {
    const parsedUrl = new URL(url);
    parsedUrl.hash = '';
    return parsedUrl.toString();
  } catch (e) {
    return url;
  }
};

async function sha256digest({string}) {
  return new Uint8Array(
    createHash('sha256').update(string).digest()
  );
}

const concat = (b1, b2) => {
  const rval = new Uint8Array(b1.length + b2.length);
  rval.set(b1, 0);
  rval.set(b2, b1.length);
  return rval;
}

// TODO: This is a hack to get the verification method from the CID document
// I think this is actually an upstream bug that should be reported
class MyDataIntegrityProof extends DataIntegrityProof {
  async getVerificationMethod({ proof, documentLoader }) {
    let verificationMethod = await super.getVerificationMethod({ proof, documentLoader });

    if (typeof verificationMethod === 'object' && verificationMethod.type !== 'Multikey' && 'verificationMethod' in verificationMethod && verificationMethod.verificationMethod.some(vm => vm.id === proof.verificationMethod)) {
      verificationMethod = verificationMethod.verificationMethod.find(vm => vm.id === proof.verificationMethod);
    }

    return verificationMethod;
  }
}

function getVerificationMethod(cid, document) {
  const verificationMethod = cid.verificationMethod.find(vm => vm.id === document.proof.verificationMethod);
  if (!verificationMethod) {
    throw new Error(`Verification method ${document.proof.verificationMethod} not found in CID document`);
  }
  return verificationMethod;
}

function cidDocumentLoader(cid, documentLoaderContent = {}) {
  const loader = createDocumentLoader(documentLoaderContent);
  return async (url) => {
    const sanitizedUrl = sanitizeUrl(url);
    // If the URL matches the CID document's ID, return the CID document
    if (sanitizedUrl === cid.id) {
      return {
        contextUrl: null,
        document: cid,
        documentUrl: sanitizedUrl
      };
    }
    // Otherwise use the provided document loader
    return loader(sanitizedUrl);
  };
}

/**
 * Generate a new CID document
 * @param {string} controller - Controller DID
 * @param {Object} options - Options for CID generation
 * @param {boolean} [options.includeEd25519=true] - Whether to include Ed25519 signature type
 * @param {boolean} [options.includeBBS=true] - Whether to include BBS+ signature type
 * @returns {Promise<{cid: Object, privateKeys: Object}>} The generated CID document and private keys
 */
export async function generateCIDDocument(controller, options = {}) {
  const { cid, privateKeys } = await generateCID(controller, {
    includeEd25519: options.includeEd25519 !== false,
    includeBBS: options.includeBBS !== false
  });
  return { cid, privateKeys };
}

/**
 * Sign a verifiable credential using a CID document and private keys
 * @param {Object} options - Options for signing
 * @param {string} options.cid - CID document
 * @param {Object} options.privateKeys - Private keys object
 * @param {Object} options.document - Document to sign
 * @param {string} options.keyId - ID of the key to use for signing
 * @param {string} [options.credentialId] - ID for the credential (optional)
 * @param {string} [options.subjectId] - ID for the credential subject (optional)
 * @returns {Promise<Object>} The signed credential
 */
export async function signCredential(options) {
  const { cid, privateKeys, document, keyId, credentialId, subjectId } = options;

  document.issuer = {
    "id": cid.id
  };

  if (credentialId) {
    document.id = credentialId;
  }

  if (subjectId) {
    if (!document.credentialSubject) {
      document.credentialSubject = {};
    }
    document.credentialSubject.id = subjectId;
  }

  const verificationMethod = cid.verificationMethod.find(vm => vm.id === keyId);
  if (!verificationMethod) {
    throw new Error(`Key ID ${keyId} not found in CID document`);
  }

  const privateKey = privateKeys[keyId];
  if (!privateKey) {
    throw new Error(`Private key for ${keyId} not found`);
  }

  let suite;
  let keyPair;
  let signedVC;

  if (verificationMethod.publicKeyMultibase.startsWith('zUC7')) {
    const algorithm = Bls12381Multikey.ALGORITHMS.BBS_BLS12381_SHA256;
    keyPair = await Bls12381Multikey.from({
      ...verificationMethod,
      secretKeyMultibase: privateKey,
    }, { algorithm });

    const date = new Date().toISOString();

    const entryPointers = ['/issuer'];
    if (document.validFrom) {
      entryPointers.push('/validFrom');
    }
    if (document.validUntil) {
      entryPointers.push('/validUntil');
    }

    suite = new DataIntegrityProof({
      signer: keyPair.signer(),
      date,
      cryptosuite: createSignCryptosuite({
        mandatoryPointers: entryPointers
      })
    });

    try {
      signedVC = await jsigs.sign(document, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader: defaultDocumentLoader
      });
    } catch (error) {
      throw new Error(`Failed to sign document using BBS Signature: ${error.message} [${JSON.stringify(error, null, 2)}]`);
    }
  } else {
    keyPair = await Ed25519VerificationKey2020.from({
      ...verificationMethod,
      privateKeyMultibase: privateKey
    });
    suite = new Ed25519Signature2020({
      key: keyPair,
      verificationMethod: verificationMethod.id
    });
    try {
      signedVC = await vc.issue({
        credential: document,
        suite,
        documentLoader: defaultDocumentLoader
      });
    } catch (error) {
      throw new Error(`Failed to sign document using Ed25519 Signature: ${error.message}`);
    }
  }

  return signedVC;
}

/**
 * Verify a verifiable credential using a CID document
 * @param {Object} options - Options for verification
 * @param {Object} options.cid - CID document
 * @param {Object} options.document - Verifiable credential to verify
 * @returns {Promise<boolean>} Whether the verification was successful
 */
export async function verifyCredential(options) {
  const { cid, document } = options;
  const documentLoader = cidDocumentLoader(cid);
  const verificationMethod = getVerificationMethod(cid, document);

  let suite;
  let keyPair;

  if (verificationMethod.publicKeyMultibase.startsWith('zUC7')) {
    keyPair = await Bls12381Multikey.from({
      ...verificationMethod,
      controller: document.issuer.id
    });
    const cryptosuite = await createVerifyCryptosuite({
      mandatoryPointers: ['/issuer']
    });
    suite = new MyDataIntegrityProof({
      verifier: keyPair.verifier(),
      cryptosuite,
    });

    const result = await jsigs.verify(document, {
      suite,
      purpose: new AssertionProofPurpose({
        controller: cid
      }),
      documentLoader
    });

    return result.verified;
  } else {
    keyPair = await Ed25519VerificationKey2020.from({
      ...verificationMethod,
      controller: document.issuer.id
    });
    suite = new Ed25519Signature2020({
      key: keyPair,
      verificationMethod: verificationMethod.id
    });

    const result = await vc.verifyCredential({
      credential: document,
      suite,
      documentLoader,
      checkStatus: async (credential) => {
        if (!credential.credentialStatus) {
          return { verified: true };
        }
        return { verified: true };
      }
    });

    return result.verified;
  }
}

/**
 * Create a derived BBS proof from a signed input BBS document
 * @param {Object} options - Options for deriving proof
 * @param {Object} options.document - Signed BBS document
 * @param {string[]} options.revealPointers - Array of JSON pointers to reveal
 * @returns {Promise<Object>} The derived document
 */
export async function deriveProof(options) {
  const { document, revealPointers } = options;

  const cryptosuite = createDiscloseCryptosuite({
    selectivePointers: revealPointers
  });

  const suite = new DataIntegrityProof({ cryptosuite });

  const derivedDocument = await jsigs.derive(document, {
    suite,
    purpose: new AssertionProofPurpose(),
    documentLoader: defaultDocumentLoader
  });

  return derivedDocument;
}

/**
 * Preprocess BBS verification data from derived credentials
 * @param {Object} options - Options for preprocessing
 * @param {Object} options.document - Derived BBS document
 * @param {Object} options.cid - CID document
 * @returns {Promise<Object>} The preprocessed data
 */
export async function preprocessBBSVerification(options) {
  const { document, cid } = options;
  const verificationMethod = getVerificationMethod(cid, document);

  const verifyData = await _createVerifyData({
    document,
    documentLoader: cidDocumentLoader(cid),
  });

  const keyPair = await Bls12381Multikey.from({
    ...verificationMethod,
    controller: document.issuer.id
  });
  const cryptosuite = await createVerifyCryptosuite({
    mandatoryPointers: ['/issuer']
  });
  const suite = new MyDataIntegrityProof({
    verifier: keyPair.verifier(),
    cryptosuite,
  });
  const method = await suite.getVerificationMethod({
    proof: document.proof,
    documentLoader: cidDocumentLoader(cid),
  });

  return {
    verifyData: {
      ...verifyData,
      bbsProof: Buffer.from(verifyData.bbsProof).toString('base64'),
      proofHash: Buffer.from(verifyData.proofHash).toString('base64'),
      mandatoryHash: Buffer.from(verifyData.mandatoryHash).toString('base64'),
    },
    verificationMethod: method,
    proof: document.proof
  };
}

/**
 * Preprocess Ed25519 verification data from signed credentials
 * @param {Object} options - Options for preprocessing
 * @param {Object} options.document - Signed Ed25519 document
 * @param {Object} options.cid - CID document
 * @returns {Promise<Object>} The preprocessed data
 */
export async function preprocessEd25519Verification(options) {
  const { document, cid } = options;
  const verificationMethod = getVerificationMethod(cid, document);

  const keyPair = await Ed25519VerificationKey2020.from({
    ...verificationMethod,
    controller: document.issuer.id
  });
  const suite = new Ed25519Signature2020({
    key: keyPair,
    verificationMethod: verificationMethod.id
  });

  const canonizedDocument = await suite.canonize({ ...document, proof: null }, {documentLoader: cidDocumentLoader(cid)});
  const canonizedProof = await suite.canonizeProof(document.proof, {document, documentLoader: cidDocumentLoader(cid)});

  const proofHash = await sha256digest({string: canonizedProof});
  const docHash = await sha256digest({string: canonizedDocument});
  const concatHash = concat(proofHash, docHash);

  const verified = await suite.verifySignature({
    verifyData: concatHash,
    proof: document.proof,
    verificationMethod: verificationMethod,
  });

  if (!verified) {
    throw new Error('Signature verification failed');
  }

  return {
    verifyData: {
      proofHash: Buffer.from(proofHash).toString('hex'),
      docHash: Buffer.from(docHash).toString('hex'),
      concatHash: Buffer.from(concatHash).toString('hex'),
      canonicalProof: canonizedProof,
      canonicalDocument: canonizedDocument
    },
    verificationMethod: verificationMethod,
    proof: document.proof
  };
}

/**
 * Collect JSON-LD documents into a single Turtle file, excluding proofs
 * @param {Object} options - Options for collection
 * @param {string[]} options.documents - Array of JSON-LD document paths
 * @param {string} options.outputPath - Output path for Turtle file
 * @returns {Promise<void>}
 */
export async function collectDocuments(options) {
  const { documents, outputPath } = options;

  if (!outputPath.endsWith('.ttl')) {
    throw new Error('Output file must have .ttl extension');
  }

  const data = await dereference.default(documents, {
    fetch: async (url) => {
      let res = await defaultDocumentLoader(url);

      if (!('@context' in res) && 'document' in res) {
        res = res.document;
      }

      const str = JSON.stringify(res, null, 2);
      return new Response(str, {
        headers: {
          'Content-Type': 'application/ld+json'
        }
      });
    },
    localFiles: true
  });

  const prefixes = {
    ...data.prefixes,
    schema: 'https://schema.org/',
    vdl: 'https://w3id.org/vdl#',
    ob: 'https://purl.imsglobal.org/spec/vc/ob/vocab.html#',
    citizenship: 'https://w3id.org/citizenship#',
    credentials: 'https://www.w3.org/2018/credentials#',
    ex: 'https://example.org/',
    exg: 'https://example.gov/',
    gov: 'https://example.gov/test#',
    xsd: 'http://www.w3.org/2001/XMLSchema#',
    status: 'https://example.gov/status/',
    lic: 'https://example.gov/drivers-license/',
    aamva: 'https://w3id.org/vdl/aamva#'
  };

  const turtle = await write([...data.store.match(null, null, null, DataFactory.defaultGraph())].filter(quad => !quad.predicate.equals(DataFactory.namedNode('https://w3id.org/security#proof'))), {
    prefixes
  });

  await fs.writeFile(outputPath, turtle);
}
