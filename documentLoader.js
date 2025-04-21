import * as vc from '@digitalbazaar/vc';
import { createHash } from 'crypto';
import fs from 'node:fs/promises';
import path from 'path';

// Create cache directory if it doesn't exist
const CACHE_DIR = '.cache';
fs.mkdir(CACHE_DIR, { recursive: true }).catch(console.error);

// Helper function to get cache file path for a URL
const getCachePath = (url) => {
  const hash = createHash('sha256').update(url).digest('hex');
  return path.join(CACHE_DIR, `${hash}.json`);
};

// Create a custom document loader
export const documentLoader = async (url) => {
  const cachePath = getCachePath(url);

  try {
    // Try to read from cache first
    const cachedData = await fs.readFile(cachePath, 'utf8');
    return JSON.parse(cachedData);
  } catch (e) {
    // Cache miss or error reading cache
  }

  try {
    const result = await vc.defaultDocumentLoader(url);
    // Cache the result
    await fs.writeFile(cachePath, JSON.stringify(result));
    return result;
  } catch (e) {
    // Suppress error
  }

  // If not in cache and default loader failed, fetch and cache
  const res = {
    contextUrl: null,
    document: await (await fetch(url)).json(),
    documentUrl: url
  };

  // Cache the result
  await fs.writeFile(cachePath, JSON.stringify(res));
  return res;
};
