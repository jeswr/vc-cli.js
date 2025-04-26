#!/usr/bin/env node

import { promises as fs } from 'fs';
import jsonld from 'jsonld';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { Command } from 'commander';
import { documentLoader } from './documentLoader.js';

const __filename = fileURLToPath(import.meta.url);

const program = new Command();

program
  .name('validate-jsonld')
  .description('Validate JSON-LD documents in strict mode')
  .version('1.0.0')
  .argument('<file>', 'JSON-LD file to validate')
  .action(async (file) => {
    try {
      // Read the JSON-LD document
      const document = JSON.parse(await fs.readFile(file, 'utf8'));

      // Parse the document in strict mode
      const res = await jsonld.toRDF(document, {
        documentLoader,
        processingMode: 'json-ld-1.1',
      });

      console.log('✅ JSON-LD document is valid in strict mode');
      process.exit(0);
    } catch (error) {
      console.error('❌ JSON-LD validation failed:', error.message, '[', JSON.stringify(error, null, 2), ']');
      process.exit(1);
    }
  });

program.parse(process.argv); 