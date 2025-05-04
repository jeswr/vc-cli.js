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
import { _createVerifyData } from './lib/verify.js';
import * as vc from '@digitalbazaar/vc';
import { documentLoader as defaultDocumentLoader } from './documentLoader.js';
import { write } from '@jeswr/pretty-turtle';
import dereference from 'rdf-dereference-store';
import { DataFactory } from 'n3';
import { randomUUID, createHash } from 'crypto';

async function sha256digest({string}) {
  return new Uint8Array(
    createHash('sha256').update(string).digest()
  );
}

const {
  createSignCryptosuite,
  createVerifyCryptosuite,
  createDiscloseCryptosuite,
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
            outputPath = path.join(outputPath, `${encodedController}.jsonld`);
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
  .option('--credential-id <id>', 'ID for the credential (optional)')
  .option('--subject-id <id>', 'ID for the credential subject (optional)')
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

      // Add credential ID if provided
      if (options.credentialId) {
        document.id = options.credentialId;
      }

      // Add credential subject ID if provided
      if (options.subjectId) {
        if (!document.credentialSubject) {
          document.credentialSubject = {};
        }
        document.credentialSubject.id = options.subjectId;
      }

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

        const entryPointers = ['/issuer'];
        if (document.validFrom) {
          entryPointers.push('/validFrom');
        }
        if (document.validUntil) {
          entryPointers.push('/validUntil');
        }

        const suite = new DataIntegrityProof({
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
      const documentLoader = cidDocumentLoader(cid);

      // Get the verification method from the CID document
      const verificationMethod = getVerificationMethod(cid, document);

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
          checkStatus: async (credential) => {
            if (!credential.credentialStatus) {
              return { verified: true };
            }
            
            // For now, we'll assume all credentials are valid
            // In a production environment, this would check a revocation registry
            return { verified: true };
          }
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
  .command('bbs-verify-preprocess')
  .description('Preprocess BBS verification data from derived credentials')
  .requiredOption('-d, --document <path>', 'Path to derived BBS document or directory containing derived BBS documents')
  .requiredOption('-c, --cid <path>', 'Path to CID document')
  .requiredOption('-o, --output <path>', 'Output path for preprocessed data (file or directory)')
  .action(async (options) => {
    try {
      // Check if input is a directory
      const stats = await fs.stat(options.document);
      const isDirectory = stats.isDirectory();

      // Get list of files to process
      const filesToProcess = isDirectory ? 
        (await fs.readdir(options.document))
          .filter(file => file.endsWith('.jsonld'))
          .map(file => path.join(options.document, file)) :
        [options.document];

      if (filesToProcess.length === 0) {
        throw new Error('No JSON-LD files found to process');
      }

      // Process each file
      for (const filePath of filesToProcess) {
        try {
          // Read the derived document
          const documentContent = await fs.readFile(filePath, 'utf8');
          const document = JSON.parse(documentContent);

          const cid = JSON.parse(await fs.readFile(options.cid, 'utf8'));
          const verificationMethod = getVerificationMethod(cid, document);

          // Get the verification data
          const verifyData = await _createVerifyData({
            document,
            documentLoader: cidDocumentLoader(cid),
          });

        // BBS+ signature
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

          // Format the output data
          const outputData = {
            verifyData: {
              ...verifyData,
              bbsProof: Buffer.from(verifyData.bbsProof).toString('base64'),
              proofHash: Buffer.from(verifyData.proofHash).toString('base64'),
              mandatoryHash: Buffer.from(verifyData.mandatoryHash).toString('base64'),
            },
            verificationMethod: method,
            proof: document.proof
          };

          // Handle output path
          let outputPath = options.output;
          try {
            const outputStats = await fs.stat(outputPath);
            if (outputStats.isDirectory()) {
              // If it's a directory, create a file named after the input document
              const docName = path.basename(filePath, '.jsonld');
              outputPath = path.join(outputPath, `${docName}-preprocessed.json`);
            } else if (filesToProcess.length > 1) {
              // If multiple files but output is a file, throw error
              throw new Error('Output must be a directory when processing multiple files');
            }
          } catch (error) {
            if (error.code === 'ENOENT') {
              // If the path doesn't exist, assume it's a file path
              const dir = path.dirname(outputPath);
              await fs.mkdir(dir, { recursive: true });
            } else {
              throw error;
            }
          }

          // Write the preprocessed data to the output file
          await fs.writeFile(outputPath, JSON.stringify(outputData, null, 2));
          console.log(`Preprocessed data saved to: ${outputPath}`);
        } catch (error) {
          console.error(`Error processing ${filePath}:`, error.message);
          if (filesToProcess.length === 1) {
            // If only processing one file, exit with error
            process.exit(1);
          }
          // Otherwise continue with next file
        }
      }
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program
  .command('ed25519-verify-preprocess')
  .description('Preprocess Ed25519 verification data from signed credentials')
  .requiredOption('-d, --document <path>', 'Path to signed Ed25519 document or directory containing signed Ed25519 documents')
  .requiredOption('-c, --cid <path>', 'Path to CID document')
  .requiredOption('-o, --output <path>', 'Output path for preprocessed data (file or directory)')
  .action(async (options) => {
    try {
      // Check if input is a directory
      const stats = await fs.stat(options.document);
      const isDirectory = stats.isDirectory();

      // Get list of files to process
      const filesToProcess = isDirectory ? 
        (await fs.readdir(options.document))
          .filter(file => file.endsWith('.jsonld'))
          .map(file => path.join(options.document, file)) :
        [options.document];

      if (filesToProcess.length === 0) {
        throw new Error('No JSON-LD files found to process');
      }

      // Process each file
      for (const filePath of filesToProcess) {
        try {
          // Read the signed document
          const documentContent = await fs.readFile(filePath, 'utf8');
          const document = JSON.parse(documentContent);

          const cid = JSON.parse(await fs.readFile(options.cid, 'utf8'));
          const verificationMethod = getVerificationMethod(cid, document);

          // Create the Ed25519 suite
          const keyPair = await Ed25519VerificationKey2020.from({
            ...verificationMethod,
            controller: document.issuer.id
          });
          const suite = new Ed25519Signature2020({
            key: keyPair,
            verificationMethod: verificationMethod.id
          });

          // Get the verification data
          const canonizedDocument = await suite.canonize({ ...document, proof: null }, {documentLoader: cidDocumentLoader(cid)});
          const canonizedProof = await suite.canonizeProof(document.proof, {document, documentLoader: cidDocumentLoader(cid)});

          const proofHash = await sha256digest({string: canonizedProof});
          const docHash = await sha256digest({string: canonizedDocument});

          // Format the output data
          const outputData = {
            verifyData: {
              proofHash: Buffer.from(proofHash).toString('hex'),
              docHash: Buffer.from(docHash).toString('hex'),
              canonicalProof: canonizedProof,
              canonicalDocument: canonizedDocument
            },
            verificationMethod: verificationMethod,
            proof: document.proof
          };

          // Handle output path
          let outputPath = options.output;
          try {
            const outputStats = await fs.stat(outputPath);
            if (outputStats.isDirectory()) {
              // If it's a directory, create a file named after the input document
              const docName = path.basename(filePath, '.jsonld');
              outputPath = path.join(outputPath, `${docName}-preprocessed.json`);
            } else if (filesToProcess.length > 1) {
              // If multiple files but output is a file, throw error
              throw new Error('Output must be a directory when processing multiple files');
            }
          } catch (error) {
            if (error.code === 'ENOENT') {
              // If the path doesn't exist, assume it's a file path
              const dir = path.dirname(outputPath);
              await fs.mkdir(dir, { recursive: true });
            } else {
              throw error;
            }
          }

          // Write the preprocessed data to the output file
          await fs.writeFile(outputPath, JSON.stringify(outputData, null, 2));
          console.log(`Preprocessed data saved to: ${outputPath}`);
        } catch (error) {
          console.error(`Error processing ${filePath}:`, error.message);
          if (filesToProcess.length === 1) {
            // If only processing one file, exit with error
            process.exit(1);
          }
          // Otherwise continue with next file
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
  .option('--no-preprocess', 'Skip preprocessing derived proofs')
  .option('-o, --output-dir <path>', 'Output directory for generated files [default: "./generated"]')
  .option('--distribute', 'Distribute documents across CIDs instead of having each CID sign all documents')
  .option('--collect', 'Collect all generated files into a single Turtle file')
  .option('--subject-id <id>', 'ID for the credential subject (optional)')
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
        path.join(__dirname, 'mocks/residence.jsonld'),
        path.join(__dirname, 'mocks/barcode.jsonld'),
        path.join(__dirname, 'mocks/employable.jsonld'),
        path.join(__dirname, 'mocks/education.jsonld')
      ];

      const signatures = options.signatures ? options.signatures.split(',') : ['bbs', 'ed25519'];
      const shouldDerive = options.derive !== false;
      const shouldPreprocess = options.preprocess !== false;
      const baseOutputDir = options.outputDir || './generated';
      const distribute = options.distribute || false;
      const subjectId = options.subjectId || `did:example:${randomUUID()}`;

      console.log('\n=== Starting Generation Process ===');
      console.log(`Base output directory: ${baseOutputDir}`);
      console.log(`CIDs to generate: ${cids.join(', ')}`);
      console.log(`Documents to sign: ${documents.join(', ')}`);
      console.log(`Signature types: ${signatures.join(', ')}`);
      console.log(`Derive proofs: ${shouldDerive ? 'Yes' : 'No'}`);
      console.log(`Preprocess derived proofs: ${shouldPreprocess ? 'Yes' : 'No'}`);
      console.log(`Distribute documents: ${distribute ? 'Yes' : 'No'}`);
      console.log(`Credential Subject ID: ${subjectId}\n`);

      // Define directory paths and files
      const cidsDir = path.join(baseOutputDir, 'cids');
      const bbsDir = path.join(baseOutputDir, 'bbs');
      const ed25519Dir = path.join(baseOutputDir, 'ed25519');
      const derivedDir = path.join(baseOutputDir, 'derived');
      const preprocessedDir = path.join(baseOutputDir, 'derived-preprocessed');
      const ed25519PreprocessedDir = path.join(baseOutputDir, 'ed25519-preprocessed');
      const keysFile = path.join(baseOutputDir, 'privateKeys.json');

      // Create output directories
      console.log('=== Creating Output Directories ===');
      try {
        await Promise.all([
          fs.mkdir(cidsDir, { recursive: true }),
          fs.mkdir(bbsDir, { recursive: true }),
          fs.mkdir(ed25519Dir, { recursive: true }),
          fs.mkdir(derivedDir, { recursive: true }),
          shouldPreprocess && fs.mkdir(preprocessedDir, { recursive: true }),
          shouldPreprocess && fs.mkdir(ed25519PreprocessedDir, { recursive: true })
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
          const cidFile = path.join(cidsDir, `${shortName}-cid.jsonld`);

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

      // Helper function to sign a document with a CID
      async function signDocumentWithCID(cidFile, docPath, signedFiles) {
        try {
          const cidContent = await fs.readFile(cidFile, 'utf8');
          const cid = JSON.parse(cidContent);
          const shortName = cid.id.split(':').pop();
          const docName = path.basename(docPath, '.jsonld');
          console.log(`\nProcessing document: ${docName} with CID: ${cid.id}`);

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
              const outputFile = path.join(outputDir, `${docName}-${shortName}.jsonld`);
              const credentialId = `urn:uuid:${randomUUID()}`;

              console.log(`Signing with ${sigType.toUpperCase()}...`);
              await program.parseAsync([
                '', '', 'sign-credential',
                '-c', cidFile,
                '-k', keysFile,
                '-d', docPath,
                '-i', keyId,
                '-o', outputFile,
                '--credential-id', credentialId,
                '--subject-id', subjectId
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
          throw new Error(`Failed to process CID file ${cidFile}: ${error.message}`);
        }
      }

      if (distribute) {
        // Distribute documents across CIDs
        for (let i = 0; i < documents.length; i++) {
          const docPath = documents[i];
          const cidIndex = i % cidFiles.length;
          const cidFile = cidFiles[cidIndex];
          await signDocumentWithCID(cidFile, docPath, signedFiles);
        }
      } else {
        // Original behavior - each CID signs all documents
        for (const cidFile of cidFiles) {
          for (const docPath of documents) {
            await signDocumentWithCID(cidFile, docPath, signedFiles);
          }
        }
      }
      console.log('\n✓ All credentials signed successfully\n');

      // Create derived proofs for BBS signatures
      if (shouldDerive) {
        console.log('=== Creating Derived Proofs ===');
        const bbsFiles = signedFiles.filter(f => f.type === 'bbs');

        for (const { file } of bbsFiles) {
          try {
            const docName = path.basename(file, '.jsonld');
            const outputFile = path.join(derivedDir, `${docName}-derived.jsonld`);

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

            // Preprocess the derived proof if enabled
            if (shouldPreprocess) {
              console.log(`Preprocessing derived proof: ${docName}`);

              const cidFile = cidFiles.find(f => f.includes(docName.split('-')[1]));

              await program.parseAsync([
                '', '', 'bbs-verify-preprocess',
                '-d', outputFile,
                '-c', cidFile,
                '-o', preprocessedDir
              ]);
            }
          } catch (error) {
            throw new Error(`Failed to derive proof for ${file}: ${error.message}`);
          }
        }
        console.log('\n✓ All proofs derived successfully\n');
      }

      // Verify all generated documents
      console.log('=== Verifying Generated Documents ===');
      
      // Verify Ed25519 signatures
      console.log('\nVerifying Ed25519 Signatures:');
      const ed25519Files = await fs.readdir(path.join(baseOutputDir, 'ed25519'));
      for (const file of ed25519Files) {
        try {
          const cidName = file.split('-')[1].split('.')[0]; // Extract CID name from filename
          const cidFile = path.join(cidsDir, `${cidName}-cid.jsonld`);
          const signedFile = path.join(baseOutputDir, 'ed25519', file);
          
          console.log(`\nVerifying: ${file}`);
          await program.parseAsync(['', '', 'verify-credential', '-c', cidFile, '-d', signedFile]);
          console.log('✓ Verification successful');

          // Preprocess Ed25519 documents if enabled
          if (shouldPreprocess) {
            console.log(`Preprocessing Ed25519 document: ${file}`);
            await program.parseAsync([
              '', '', 'ed25519-verify-preprocess',
              '-d', signedFile,
              '-c', cidFile,
              '-o', ed25519PreprocessedDir
            ]);
          }
        } catch (error) {
          throw new Error(`Failed to verify Ed25519 document ${file}: ${error.message}`);
        }
      }

      // Verify derived BBS proofs
      console.log('\nVerifying Derived BBS Proofs:');
      const derivedFiles = await fs.readdir(path.join(baseOutputDir, 'derived'));
      for (const file of derivedFiles) {
        try {
          const cidName = file.split('-')[1].split('.')[0]; // Extract CID name from filename
          const cidFile = path.join(cidsDir, `${cidName}-cid.jsonld`);
          const derivedFile = path.join(baseOutputDir, 'derived', file);
          
          console.log(`\nVerifying: ${file}`);
          await program.parseAsync(['', '', 'verify-credential', '-c', cidFile, '-d', derivedFile]);
          console.log('✓ Verification successful');
        } catch (error) {
          throw new Error(`Failed to verify derived BBS document ${file}: ${error.message}`);
        }
      }

      console.log('\n✓ All documents verified successfully\n');

      console.log('=== Generation Complete ===');
      console.log('All files are organized in:', baseOutputDir);
      console.log('- CIDs:', cidsDir);
      console.log('- BBS Signatures:', bbsDir);
      console.log('- Ed25519 Signatures:', ed25519Dir);
      console.log('- Derived Credentials:', derivedDir);
      if (shouldPreprocess) {
        console.log('- Preprocessed Derived Credentials:', preprocessedDir);
        console.log('- Preprocessed Ed25519 Credentials:', ed25519PreprocessedDir);
      }

      // If --collect flag is set, collect all files into a single Turtle file
      if (options.collect) {
        console.log('\n=== Collecting Generated Files ===');
        const outputFile = path.join(baseOutputDir, 'collected.ttl');
        await program.parseAsync(['', '', 'collect', '-d', baseOutputDir, '-o', outputFile]);
        console.log(`✓ All files collected into: ${outputFile}`);
      }
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program
  .command('collect')
  .description('Collect JSON-LD documents into a single Turtle file, excluding proofs')
  .requiredOption('-d, --directory <path>', 'Directory containing JSON-LD documents')
  .requiredOption('-o, --output <path>', 'Output path for Turtle file (must end with .ttl)')
  .action(async (options) => {
    try {
      // Validate output file extension
      if (!options.output.endsWith('.ttl')) {
        throw new Error('Output file must have .ttl extension');
      }

      // Read all files in the directory
      const files = await fs.readdir(options.directory, { recursive: true });
      const jsonldFiles = files.filter(file => file.endsWith('.jsonld'))
        .map(file => path.join(options.directory, file))
        .filter(file => !file.includes('-cid.jsonld'));



      if (jsonldFiles.length === 0) {
        throw new Error('No JSON-LD files found in the specified directory');
      }

      const data = await dereference.default(jsonldFiles, {
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

      // Serialize to Turtle
      const turtle = await write([...data.store.match(null, null, null, DataFactory.defaultGraph())].filter(quad => !quad.predicate.equals(DataFactory.namedNode('https://w3id.org/security#proof'))), {
        prefixes
      });

      // Write to output file
      await fs.writeFile(options.output, turtle);
      console.log(`Successfully collected ${jsonldFiles.length} documents into ${options.output}`);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program.parse(); 

function getVerificationMethod(cid, document) {
  const verificationMethod = cid.verificationMethod.find(vm => vm.id === document.proof.verificationMethod);
  if (!verificationMethod) {
    throw new Error(`Verification method ${document.proof.verificationMethod} not found in CID document`);
  }
  return verificationMethod;
}

function cidDocumentLoader(cid) {
  return async (url) => {
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
}

