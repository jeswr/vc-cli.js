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
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import * as vc from '@digitalbazaar/vc';
import { documentLoader as defaultDocumentLoader } from './documentLoader.js';

const {
  createSignCryptosuite,
  createVerifyCryptosuite,
  createDiscloseCryptosuite
} = bbs2023Cryptosuite;
const { purposes: { AssertionProofPurpose } } = jsigs;

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

      let suite;
      let keyPair;
      let signedVC;

      // Determine which signature suite to use based on the key type
      if (verificationMethod.publicKeyMultibase.startsWith('zUC7')) {
        const algorithm = Bls12381Multikey.ALGORITHMS.BBS_BLS12381_SHA256;
        const keyPair = await Bls12381Multikey.from({
          ...verificationMethod,
          secretKeyMultibase: privateKey,
        }, { algorithm });

        const date = new Date().toISOString();
        const suite = new DataIntegrityProof({
          signer: keyPair.signer(),
          date,
          cryptosuite: createSignCryptosuite({
            mandatoryPointers: ['/issuer']
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
        // Ed25519 signature
        keyPair = await Ed25519VerificationKey2020.from({
          ...verificationMethod,
          privateKeyMultibase: privateKey
        });
        suite = new Ed25519Signature2020({
          key: keyPair,
          verificationMethod: verificationMethod.id
        });
        try {
          // Sign the credential
          signedVC = await vc.issue({
            credential: document,
            suite,
            documentLoader: defaultDocumentLoader
          });
        } catch (error) {
          throw new Error(`Failed to sign document using Ed25519 Signature: ${error.message}`);
        }
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
        const cryptosuite = await createVerifyCryptosuite({
          mandatoryPointers: ['/issuer']
        });
        suite = new MyDataIntegrityProof({
          verifier: keyPair.verifier(),
          cryptosuite,
        });

        // Verify the credential
        const result = await jsigs.verify(document, {
          suite,
          purpose: new AssertionProofPurpose({
            controller: cid
          }),
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
      }

    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program
  .command('derive-proof')
  .description('Create a derived BBS proof from a signed input BBS document')
  .requiredOption('-d, --document <path>', 'Path to signed BBS document')
  .requiredOption('-r, --reveal <pointers>', 'Comma-separated list of JSON pointers to reveal (e.g. /credentialSubject/name,/credentialSubject/age)')
  .requiredOption('-o, --output <path>', 'Output path for derived document')
  .action(async (options) => {
    try {
      // Read the signed document
      const documentContent = await fs.readFile(options.document, 'utf8');
      const document = JSON.parse(documentContent);

      // Parse the reveal pointers
      const revealPointers = options.reveal.split(',').map(pointer => pointer.trim());

      // Import necessary modules
      const { documentLoader } = await import('./documentLoader.js');

      // Create the disclose cryptosuite with the reveal pointers
      const cryptosuite = createDiscloseCryptosuite({
        selectivePointers: revealPointers
      });

      // Create the proof suite
      const suite = new DataIntegrityProof({ cryptosuite });

      // Derive the proof
      const derivedDocument = await jsigs.derive(document, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });

      // Write the derived document to the output file
      await fs.writeFile(options.output, JSON.stringify(derivedDocument, null, 2));
      console.log(`Derived document saved to: ${options.output}`);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program
  .command('generate')
  .description('Generate CIDs, sign credentials, and create derived proofs')
  .option('-c, --cids <ids>', 'Comma-separated list of CID controller DIDs [default: "did:example:alice,did:example:bob,did:example:charlie,did:example:dave"]')
  .option('-d, --documents <paths>', 'Comma-separated list of credential document paths to sign [default: all mock credentials]')
  .option('-s, --signatures <types>', 'Comma-separated list of signature types to use (bbs,ed25519) [default: "bbs,ed25519"]')
  .option('--no-derive', 'Skip creating derived proofs for BBS signatures')
  .option('-o, --output-dir <path>', 'Output directory for generated files [default: "./generated"]')
  .action(async (options) => {
    try {
      // Parse options with defaults
      const cids = options.cids ? options.cids.split(',') : [
        'did:example:alice',
        'did:example:bob',
        'did:example:charlie',
        'did:example:dave'
      ];

      const documents = options.documents ? options.documents.split(',') : [
        './mocks/residence.jsonld',
        './mocks/barcode.jsonld',
        './mocks/employable.jsonld',
        './mocks/education.jsonld'
      ];

      const signatures = options.signatures ? options.signatures.split(',') : ['bbs', 'ed25519'];
      const shouldDerive = options.derive !== false;
      const baseOutputDir = options.outputDir || './generated';

      console.log('\n=== Starting Generation Process ===');
      console.log(`Base output directory: ${baseOutputDir}`);
      console.log(`CIDs to generate: ${cids.join(', ')}`);
      console.log(`Documents to sign: ${documents.join(', ')}`);
      console.log(`Signature types: ${signatures.join(', ')}`);
      console.log(`Derive proofs: ${shouldDerive ? 'Yes' : 'No'}\n`);

      // Define directory paths and files
      const cidsDir = path.join(baseOutputDir, 'cids');
      const bbsDir = path.join(baseOutputDir, 'bbs');
      const ed25519Dir = path.join(baseOutputDir, 'ed25519');
      const derivedDir = path.join(baseOutputDir, 'derived');
      const keysFile = path.join(baseOutputDir, 'privateKeys.json');

      // Create output directories
      console.log('=== Creating Output Directories ===');
      try {
        await Promise.all([
          fs.mkdir(cidsDir, { recursive: true }),
          fs.mkdir(bbsDir, { recursive: true }),
          fs.mkdir(ed25519Dir, { recursive: true }),
          fs.mkdir(derivedDir, { recursive: true })
        ]);
        console.log('✓ Output directories created successfully\n');
      } catch (error) {
        throw new Error(`Failed to create output directories: ${error.message}`);
      }

      // Initialize combined private keys object
      const allPrivateKeys = {};

      // Generate CIDs
      console.log('=== Generating CIDs ===');
      const cidFiles = [];

      for (const cid of cids) {
        try {
          console.log(`\nGenerating CID for: ${cid}`);
          const shortName = cid.split(':').pop(); // Extract 'alice' from 'did:example:alice'
          const cidFile = path.join(cidsDir, `${shortName}-cid.json`);

          // Generate CID and get private keys
          const { cid: cidDoc, privateKeys } = await generateCID(cid, {
            includeEd25519: signatures.includes('ed25519'),
            includeBBS: signatures.includes('bbs')
          });

          // Save CID document
          await fs.writeFile(cidFile, JSON.stringify(cidDoc, null, 2));
          console.log(`✓ CID document saved to: ${cidFile}`);

          // Merge private keys into combined object
          Object.assign(allPrivateKeys, privateKeys);

          cidFiles.push(cidFile);
        } catch (error) {
          throw new Error(`Failed to generate CID for ${cid}: ${error.message}`);
        }
      }
      console.log('\n✓ All CIDs generated successfully\n');

      // Save all private keys to a single file
      console.log('=== Saving Private Keys ===');
      try {
        await fs.writeFile(keysFile, JSON.stringify(allPrivateKeys, null, 2));
        console.log(`✓ All private keys saved to: ${keysFile}\n`);
      } catch (error) {
        throw new Error(`Failed to save private keys: ${error.message}`);
      }

      // Sign credentials
      console.log('=== Signing Credentials ===');
      const signedFiles = [];

      for (const cidFile of cidFiles) {
        try {
          const cidContent = await fs.readFile(cidFile, 'utf8');
          const cid = JSON.parse(cidContent);
          const shortName = cid.id.split(':').pop();
          console.log(`\nProcessing CID: ${cid.id}`);

          for (const docPath of documents) {
            try {
              const docName = path.basename(docPath, '.jsonld');
              console.log(`\nSigning document: ${docName}`);

              for (const sigType of signatures) {
                try {
                  const keyId = cid.verificationMethod.find(vm =>
                    sigType === 'bbs' ? vm.publicKeyMultibase.startsWith('zUC7') : !vm.publicKeyMultibase.startsWith('zUC7')
                  )?.id;

                  if (!keyId) {
                    console.warn(`⚠️ No ${sigType} key found for CID ${cid.id}, skipping...`);
                    continue;
                  }

                  const outputDir = sigType === 'bbs' ? bbsDir : ed25519Dir;
                  const outputFile = path.join(outputDir, `${docName}-${shortName}.json`);

                  console.log(`Signing with ${sigType.toUpperCase()}...`);
                  await program.parseAsync([
                    '', '', 'sign-credential',
                    '-c', cidFile,
                    '-k', keysFile,
                    '-d', docPath,
                    '-i', keyId,
                    '-o', outputFile
                  ]);
                  console.log(`✓ Signed document saved to: ${outputFile}`);

                  signedFiles.push({
                    file: outputFile,
                    type: sigType,
                    cid: cid.id
                  });
                } catch (error) {
                  throw new Error(`Failed to sign document ${docPath} with ${sigType} for CID ${cid.id}: ${error.message}`);
                }
              }
            } catch (error) {
              throw new Error(`Failed to process document ${docPath}: ${error.message}`);
            }
          }
        } catch (error) {
          throw new Error(`Failed to process CID file ${cidFile}: ${error.message}`);
        }
      }
      console.log('\n✓ All credentials signed successfully\n');

      // Create derived proofs for BBS signatures
      if (shouldDerive) {
        console.log('=== Creating Derived Proofs ===');
        const bbsFiles = signedFiles.filter(f => f.type === 'bbs');

        for (const { file } of bbsFiles) {
          try {
            const docName = path.basename(file, '.json');
            const outputFile = path.join(derivedDir, `${docName}-derived.json`);

            console.log(`\nDeriving proof for: ${docName}`);
            // Use a reasonable set of reveal pointers based on the credential type
            const revealPointers = [
              '/credentialSubject',
            ].join(',');

            await program.parseAsync([
              '', '', 'derive-proof',
              '-d', file,
              '-r', revealPointers,
              '-o', outputFile
            ]);
            console.log(`✓ Derived proof saved to: ${outputFile}`);
          } catch (error) {
            throw new Error(`Failed to derive proof for ${file}: ${error.message}`);
          }
        }
        console.log('\n✓ All proofs derived successfully\n');
      }

      // Verify all generated documents
      console.log('=== Verifying Generated Documents ===');
      for (const { file, cid } of signedFiles) {
        try {
          const shortName = cid.split(':').pop();
          const cidFile = path.join(cidsDir, `${shortName}-cid.json`);
          console.log(`\nVerifying: ${path.basename(file)}`);
          await program.parseAsync(['', '', 'verify-credential', '-c', cidFile, '-d', file]);
          console.log('✓ Verification successful');
        } catch (error) {
          throw new Error(`Failed to verify document ${file}: ${error.message}`);
        }
      }
      console.log('\n✓ All documents verified successfully\n');

      console.log('=== Generation Complete ===');
      console.log('All files are organized in:', baseOutputDir);
      console.log('- CIDs:', cidsDir);
      console.log('- BBS Signatures:', bbsDir);
      console.log('- Ed25519 Signatures:', ed25519Dir);
      console.log('- Derived Credentials:', derivedDir);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program.parse(); 
