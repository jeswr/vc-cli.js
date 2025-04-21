#!/usr/bin/env node

import { program } from 'commander';
import { generateCID } from './cid.js';
import fs from 'fs/promises';
import path from 'path';

program
  .name('vc-cli')
  .description('CLI utility for generating CIDs and issuing verifiable credentials')
  .version('1.0.0');

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

program.parse(); 
