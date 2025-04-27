import * as vc from '@digitalbazaar/vc';
import { createHash } from 'crypto';
import fs from 'node:fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

// Get the directory path of the current file
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Create cache directories if they don't exist
const SCRIPT_CACHE_DIR = path.join(__dirname, '.cache');
const PROCESS_CACHE_DIR = '.cache';
fs.mkdir(SCRIPT_CACHE_DIR, { recursive: true }).catch(console.error);
fs.mkdir(PROCESS_CACHE_DIR, { recursive: true }).catch(console.error);

// Helper function to get cache file path for a URL
const getCachePath = (url, isRead = false) => {
  const hash = createHash('sha256').update(url).digest('hex');
  return path.join(isRead ? SCRIPT_CACHE_DIR : PROCESS_CACHE_DIR, `${hash}.json`);
};

// Helper function to try reading from a cache path
const tryReadCache = async (cachePath) => {
  try {
    const cachedData = await fs.readFile(cachePath, 'utf8');
    return JSON.parse(cachedData);
  } catch (e) {
    return null;
  }
};

// Create a custom document loader
export const documentLoader = async (url) => {
  // First try reading from script-relative cache
  const scriptCachePath = getCachePath(url, true);
  const scriptCacheResult = await tryReadCache(scriptCachePath);
  if (scriptCacheResult) {
    return scriptCacheResult;
  }

  // Then try reading from process-relative cache
  const processCachePath = getCachePath(url, false);
  const processCacheResult = await tryReadCache(processCachePath);
  if (processCacheResult) {
    return processCacheResult;
  }

  try {
    const result = await vc.defaultDocumentLoader(url);
    // Cache the result in process-relative cache
    await fs.writeFile(processCachePath, JSON.stringify(result));
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

  // Cache the result in process-relative cache
  await fs.writeFile(processCachePath, JSON.stringify(res));
  return res;
};
