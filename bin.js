#!/usr/bin/env node

import { program } from 'commander';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import {
  generateCIDDocument,
  signCredential,
  verifyCredential,
  deriveProof,
  preprocessBBSVerification,
  preprocessEd25519Verification,
  collectDocuments
} from './index.js';

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
  .option('--document-loader-content <path>', 'Path to JSON file containing predefined document loader responses')
  .action(async (options) => {
    try {
      const { cid, privateKeys } = await generateCIDDocument(options.controller, {
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
  .option('--document-loader-content <path>', 'Path to JSON file containing predefined document loader responses')
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

      const signedVC = await signCredential({
        cid,
        privateKeys,
        document,
        keyId: options.keyId,
        credentialId: options.credentialId,
        subjectId: options.subjectId,
        documentLoaderContent: await getDocumentLoaderContent(options)
      });

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
  .option('--document-loader-content <path>', 'Path to JSON file containing predefined document loader responses')
  .action(async (options) => {
    try {
      // Read the CID document
      const cidContent = await fs.readFile(options.cid, 'utf8');
      const cid = JSON.parse(cidContent);

      // Read the verifiable credential
      const documentContent = await fs.readFile(options.document, 'utf8');
      const document = JSON.parse(documentContent);

      const isValid = await verifyCredential({ cid, document, documentLoaderContent: await getDocumentLoaderContent(options) });

      if (isValid) {
        console.log('Credential verified successfully!');
      } else {
        console.error('Credential verification failed');
        process.exit(1);
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
  .option('--document-loader-content <path>', 'Path to JSON file containing predefined document loader responses')
  .action(async (options) => {
    try {
      // Read the signed document
      const documentContent = await fs.readFile(options.document, 'utf8');
      const document = JSON.parse(documentContent);

      // Parse the reveal pointers
      const revealPointers = options.reveal.split(',').map(pointer => pointer.trim());

      const derivedDocument = await deriveProof({
        document,
        revealPointers,
        documentLoaderContent: await getDocumentLoaderContent(options)
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
  .command('bbs-verify-preprocess')
  .description('Preprocess BBS verification data from derived credentials')
  .requiredOption('-d, --document <path>', 'Path to derived BBS document or directory containing derived BBS documents')
  .requiredOption('-c, --cid <path>', 'Path to CID document')
  .requiredOption('-o, --output <path>', 'Output path for preprocessed data (file or directory)')
  .option('--document-loader-content <path>', 'Path to JSON file containing predefined document loader responses')
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

      // Read the CID document
      const cidContent = await fs.readFile(options.cid, 'utf8');
      const cid = JSON.parse(cidContent);

      // Process each file
      for (const filePath of filesToProcess) {
        try {
          // Read the derived document
          const documentContent = await fs.readFile(filePath, 'utf8');
          const document = JSON.parse(documentContent);

          const preprocessedData = await preprocessBBSVerification({
            document,
            cid,
            documentLoaderContent: await getDocumentLoaderContent(options)
          });

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
          await fs.writeFile(outputPath, JSON.stringify(preprocessedData, null, 2));
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
  .option('--document-loader-content <path>', 'Path to JSON file containing predefined document loader responses')
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

      // Read the CID document
      const cidContent = await fs.readFile(options.cid, 'utf8');
      const cid = JSON.parse(cidContent);

      // Process each file
      for (const filePath of filesToProcess) {
        try {
          // Read the signed document
          const documentContent = await fs.readFile(filePath, 'utf8');
          const document = JSON.parse(documentContent);

          const preprocessedData = await preprocessEd25519Verification({
            document,
            cid,
            documentLoaderContent: await getDocumentLoaderContent(options)
          });

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
          await fs.writeFile(outputPath, JSON.stringify(preprocessedData, null, 2));
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
  .option('--document-loader-content <path>', 'Path to JSON file containing predefined document loader responses')
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
          const { cid: cidDoc, privateKeys } = await generateCIDDocument(cid, {
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
              const documentContent = await fs.readFile(docPath, 'utf8');
              const document = JSON.parse(documentContent);

              const signedVC = await signCredential({
                cid,
                privateKeys: allPrivateKeys,
                document,
                keyId,
                credentialId,
                subjectId
              });

              await fs.writeFile(outputFile, JSON.stringify(signedVC, null, 2));
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
            ];

            const documentContent = await fs.readFile(file, 'utf8');
            const document = JSON.parse(documentContent);

            const derivedDocument = await deriveProof({
              document,
              revealPointers,
              documentLoaderContent: await getDocumentLoaderContent(options)
            });

            await fs.writeFile(outputFile, JSON.stringify(derivedDocument, null, 2));
            console.log(`✓ Derived proof saved to: ${outputFile}`);

            // Preprocess the derived proof if enabled
            if (shouldPreprocess) {
              console.log(`Preprocessing derived proof: ${docName}`);

              const cidFile = cidFiles.find(f => f.includes(docName.split('-')[1]));
              const cidContent = await fs.readFile(cidFile, 'utf8');
              const cid = JSON.parse(cidContent);

              const preprocessedData = await preprocessBBSVerification({
                document: derivedDocument,
                cid,
                documentLoaderContent: await getDocumentLoaderContent(options)
              });

              const preprocessedFile = path.join(preprocessedDir, `${docName}-preprocessed.json`);
              await fs.writeFile(preprocessedFile, JSON.stringify(preprocessedData, null, 2));
              console.log(`✓ Preprocessed data saved to: ${preprocessedFile}`);
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
          const cidContent = await fs.readFile(cidFile, 'utf8');
          const cid = JSON.parse(cidContent);
          const documentContent = await fs.readFile(signedFile, 'utf8');
          const document = JSON.parse(documentContent);

          const isValid = await verifyCredential({ cid, document, documentLoaderContent: await getDocumentLoaderContent(options) });
          if (!isValid) {
            throw new Error('Verification failed');
          }
          console.log('✓ Verification successful');

          // Preprocess Ed25519 documents if enabled
          if (shouldPreprocess) {
            console.log(`Preprocessing Ed25519 document: ${file}`);
            const preprocessedData = await preprocessEd25519Verification({
              document,
              cid,
              documentLoaderContent: await getDocumentLoaderContent(options)
            });

            const preprocessedFile = path.join(ed25519PreprocessedDir, `${file}-preprocessed.json`);
            await fs.writeFile(preprocessedFile, JSON.stringify(preprocessedData, null, 2));
            console.log(`✓ Preprocessed data saved to: ${preprocessedFile}`);
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
          const cidContent = await fs.readFile(cidFile, 'utf8');
          const cid = JSON.parse(cidContent);
          const documentContent = await fs.readFile(derivedFile, 'utf8');
          const document = JSON.parse(documentContent);

          const isValid = await verifyCredential({ cid, document, documentLoaderContent: await getDocumentLoaderContent(options) });
          if (!isValid) {
            throw new Error('Verification failed');
          }
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
        await collectDocuments({
          documents: [
            ...(await fs.readdir(cidsDir)).map(f => path.join(cidsDir, f)),
            ...(await fs.readdir(bbsDir)).map(f => path.join(bbsDir, f)),
            ...(await fs.readdir(ed25519Dir)).map(f => path.join(ed25519Dir, f)),
            ...(await fs.readdir(derivedDir)).map(f => path.join(derivedDir, f))
          ],
          outputPath: outputFile
        });
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
  .option('--document-loader-content <path>', 'Path to JSON file containing predefined document loader responses')
  .action(async (options) => {
    try {
      // Read all files in the directory
      const files = await fs.readdir(options.directory, { recursive: true });
      const jsonldFiles = files.filter(file => file.endsWith('.jsonld'))
        .map(file => path.join(options.directory, file))
        .filter(file => !file.includes('-cid.jsonld'));

      if (jsonldFiles.length === 0) {
        throw new Error('No JSON-LD files found in the specified directory');
      }

      await collectDocuments({
        documents: jsonldFiles,
        outputPath: options.output,
        documentLoaderContent: await getDocumentLoaderContent(options)
      });

      console.log(`Successfully collected ${jsonldFiles.length} documents into ${options.output}`);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program.parse();

async function getDocumentLoaderContent(options) {
  let documentLoaderContent = {};
  if (options.documentLoaderContent) {
    try {
      documentLoaderContent = JSON.parse(await fs.readFile(options.documentLoaderContent, 'utf8'));
    } catch (error) {
      console.error('Error:', error.message);
    }
  }
  return documentLoaderContent;
}

