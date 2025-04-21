#!/usr/bin/env node

import { program } from 'commander';
import { generateCID } from './cid.js';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

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

      // Create key pair from verification method and private key
      const keyPair = await Ed25519VerificationKey2020.from({
        ...verificationMethod,
        privateKeyMultibase: privateKey
      });

      // Create signature suite
      const suite = new Ed25519Signature2020({
        key: keyPair,
        verificationMethod: verificationMethod.id
      });

      // Sign the credential
      const signedVC = await vc.issue({
        credential: document,
        suite,
        documentLoader
      });

      // Write the signed credential to the output file
      await fs.writeFile(options.output, JSON.stringify(signedVC, null, 2));
      console.log(`Signed credential saved to: ${options.output}`);
    } catch (error) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program.parse(); 
