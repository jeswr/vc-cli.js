#!/usr/bin/env node

import { program } from 'commander';
import { generateCID } from './cid.js';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as bbs2023Cryptosuite from '@digitalbazaar/bbs-2023-cryptosuite';
import { DataIntegrityProof } from '@digitalbazaar/data-integrity';
import jsigs from 'jsonld-signatures';
import { URL } from 'url';
const {
  createSignCryptosuite,
  createVerifyCryptosuite

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

// Get the directory path of the current file
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Read package.json to get version
const packageJson = JSON.parse(await fs.readFile(path.join(__dirname, 'package.json'), 'utf8'));

program
  .name('vc-cli')
  .description('CLI utility for generating CIDs and issuing verifiable credentials')
  .version(packageJson.version);

program
  .command('generate-cid')
  .description('Generate a new CID document')
  .requiredOption('-c, --controller <controller>', 'Controller DID')
  .option('-o, --output <path>', 'Output path for CID document (file or directory)')
  .option('-k, --keys <path>', 'Path to save private keys JSON file')
  .option('--no-ed25519', 'Exclude Ed25519 signature type')
  .option('--no-bbs', 'Exclude BBS+ signature type')
  .action(async (options) => {
    try {
      const { cid, privateKeys } = await generateCID(options.controller, {
        includeEd25519: options.ed25519,
        includeBBS: options.bbs
      });

      // Handle CID document output
      if (options.output) {
        let outputPath = options.output;
        try {
          const stats = await fs.stat(outputPath);
          if (stats.isDirectory()) {
            // If it's a directory, create a file named after the encoded controller
            const encodedController = encodeURIComponent(options.controller);
            outputPath = path.join(outputPath, `${encodedController}.json`);
          }
        } catch (error) {
          // If the path doesn't exist, assume it's a file path
          const dir = path.dirname(outputPath);
          await fs.mkdir(dir, { recursive: true });
        }

        await fs.writeFile(outputPath, JSON.stringify(cid, null, 2));
        console.log(`CID document saved to: ${outputPath}`);
      } else {
        console.log('CID Document:');
        console.log(JSON.stringify(cid, null, 2));
      }

      // Handle private keys output
      if (options.keys) {
        try {
          // Check if file exists
          const existingContent = await fs.readFile(options.keys, 'utf8');
          const existingKeys = JSON.parse(existingContent);
          // Merge existing keys with new keys
          const mergedKeys = { ...existingKeys, ...privateKeys };
          await fs.writeFile(options.keys, JSON.stringify(mergedKeys, null, 2));
          console.log(`Private keys appended to: ${options.keys}`);
        } catch (error) {
          // If file doesn't exist or is invalid JSON, create new file
          await fs.writeFile(options.keys, JSON.stringify(privateKeys, null, 2));
          console.log(`Private keys saved to: ${options.keys}`);
        }
      } else {
        console.log('\nPrivate Keys:');
        console.log(JSON.stringify(privateKeys, null, 2));
      }
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program
  .command('sign-credential')
  .description('Sign a verifiable credential using a CID document and private keys')
  .requiredOption('-c, --cid <path>', 'Path to CID document')
  .requiredOption('-k, --keys <path>', 'Path to private keys JSON file')
  .requiredOption('-d, --document <path>', 'Path to JSON-LD document to sign')
  .requiredOption('-i, --key-id <id>', 'ID of the key to use for signing')
  .requiredOption('-o, --output <path>', 'Output path for signed credential')
  .action(async (options) => {
    try {
      // Read the CID document
      const cidContent = await fs.readFile(options.cid, 'utf8');
      const cid = JSON.parse(cidContent);

      // Read the private keys
      const keysContent = await fs.readFile(options.keys, 'utf8');
      const privateKeys = JSON.parse(keysContent);

      // Read the document to sign
      const documentContent = await fs.readFile(options.document, 'utf8');
      const document = JSON.parse(documentContent);

      document.issuer = {
        "id": cid.id
      };

      // Find the verification method in the CID document
      const verificationMethod = cid.verificationMethod.find(vm => vm.id === options.keyId);
      if (!verificationMethod) {
        throw new Error(`Key ID ${options.keyId} not found in CID document`);
      }

      // Get the private key
      const privateKey = privateKeys[options.keyId];
      if (!privateKey) {
        throw new Error(`Private key for ${options.keyId} not found`);
      }

      // Import necessary modules
      const { Ed25519VerificationKey2020 } = await import('@digitalbazaar/ed25519-verification-key-2020');
      const { Ed25519Signature2020 } = await import('@digitalbazaar/ed25519-signature-2020');

      const vc = await import('@digitalbazaar/vc');
      const { documentLoader } = await import('./documentLoader.js');

      let suite;
      let keyPair;
      let signedVC;

      // Determine which signature suite to use based on the key type
      if (verificationMethod.publicKeyMultibase.startsWith('zUC7')) {
        const algorithm = Bls12381Multikey.ALGORITHMS.BBS_BLS12381_SHA256;
        const keyPair = await Bls12381Multikey.from({
          ...verificationMethod,
          secretKeyMultibase: privateKey
        }, { algorithm });

        const date = '2023-03-01T21:29:24Z';
        const suite = new DataIntegrityProof({
          signer: keyPair.signer(), date, cryptosuite: createSignCryptosuite()
        });

        signedVC = await jsigs.sign(document, {
          suite,
          purpose: new AssertionProofPurpose(),
          documentLoader
        });
      } else {
        // Ed25519 signature
        keyPair = await Ed25519VerificationKey2020.from({
          ...verificationMethod,
          privateKeyMultibase: privateKey
        });
        suite = new Ed25519Signature2020({
          key: keyPair,
          verificationMethod: verificationMethod.id
        });

        // Sign the credential
        signedVC = await vc.issue({
          credential: document,
          suite,
          documentLoader
        });

      }

      // Write the signed credential to the output file
      await fs.writeFile(options.output, JSON.stringify(signedVC, null, 2));
      console.log(`Signed credential saved to: ${options.output}`);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program
  .command('verify-credential')
  .description('Verify a verifiable credential using a CID document')
  .requiredOption('-c, --cid <path>', 'Path to CID document')
  .requiredOption('-d, --document <path>', 'Path to verifiable credential to verify')
  .action(async (options) => {
    try {
      // Read the CID document
      const cidContent = await fs.readFile(options.cid, 'utf8');
      const cid = JSON.parse(cidContent);

      // Read the verifiable credential
      const documentContent = await fs.readFile(options.document, 'utf8');
      const document = JSON.parse(documentContent);

      // Import necessary modules
      const { Ed25519VerificationKey2020 } = await import('@digitalbazaar/ed25519-verification-key-2020');
      const { Ed25519Signature2020 } = await import('@digitalbazaar/ed25519-signature-2020');
      const vc = await import('@digitalbazaar/vc');
      const { documentLoader: defaultDocumentLoader } = await import('./documentLoader.js');

      // Create a custom document loader that includes the CID document
      const documentLoader = async (url) => {
        url = sanitizeUrl(url);
        // If the URL matches the CID document's ID, return the CID document
        if (url === cid.id) {
          return {
            contextUrl: null,
            document: cid,
            documentUrl: url
          };
        }
        // Otherwise use the default document loader
        return defaultDocumentLoader(url);
      };

      // Get the verification method from the CID document
      const verificationMethod = cid.verificationMethod.find(vm => vm.id === document.proof.verificationMethod);
      if (!verificationMethod) {
        throw new Error(`Verification method ${document.proof.verificationMethod} not found in CID document`);
      }

      let suite;
      let keyPair;

      // Determine which signature suite to use based on the key type
      if (verificationMethod.publicKeyMultibase.startsWith('zUC7')) {
        // BBS+ signature
        keyPair = await Bls12381Multikey.from({
          ...verificationMethod,
          controller: document.issuer.id
        });
        const cryptosuite = await createVerifyCryptosuite();
        const suite = new DataIntegrityProof({
          verifier: keyPair.verifier(),
          cryptosuite
        });

        // Verify the credential
        const result = await jsigs.verify(document, {
          suite,
          purpose: new AssertionProofPurpose(),
          documentLoader
        });

        if (result.verified) {
          console.log('Credential verified successfully!');
        } else {
          console.error('Credential verification failed:');
          console.error(result.error);
          process.exit(1);
        }
      } else {
        // Ed25519 signature
        keyPair = await Ed25519VerificationKey2020.from({
          ...verificationMethod,
          controller: document.issuer.id
        });
        suite = new Ed25519Signature2020({
          key: keyPair,
          verificationMethod: verificationMethod.id
        });
      }

      // Verify the credential
      const result = await vc.verifyCredential({
        credential: document,
        suite,
        documentLoader,
      });

      if (result.verified) {
        console.log('Credential verified successfully!');
      } else {
        console.error('Credential verification failed:');
        console.error(result.error);
        process.exit(1);
      }
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program.parse(); 
