/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import * as cborg from 'cborg';

/* CBOR proof value representation:
0xd9 == 11011001
110 = CBOR major type 6
11001 = 25, 16-bit tag size (65536 possible values)
0x5d = always the first 8-bits of a bbs-2023 tag
0x02 | 0x03 = last 8-bits of a bbs-2023 tag indicating proof mode
proof mode can be 2 = base, 3 = derived
*/
const CBOR_PREFIX_DERIVED = new Uint8Array([0xd9, 0x5d, 0x03]);

// CBOR decoder for implementations that use tag 64 for Uint8Array instead
// of byte string major type 2
const TAGS = [];
TAGS[64] = _decodeUint8Array;

export function parseDisclosureProofValue({proof} = {}) {
  try {
    if(typeof proof?.proofValue !== 'string') {
      throw new TypeError('"proof.proofValue" must be a string.');
    }
    if(proof.proofValue[0] !== 'u') {
      throw new Error('Only base64url multibase encoding is supported.');
    }

    // decode from base64url
    const proofValue = base64url.decode(proof.proofValue.slice(1));
    if(!_startsWithBytes(proofValue, CBOR_PREFIX_DERIVED)) {
      throw new TypeError('"proof.proofValue" must be a derived proof.');
    }

    const payload = proofValue.subarray(CBOR_PREFIX_DERIVED.length);
    const [
      bbsProof,
      compressedLabelMap,
      mandatoryIndexes,
      selectiveIndexes,
      presentationHeader
    ] = cborg.decode(payload, {useMaps: true, tags: TAGS});

    const labelMap = _decompressLabelMap(compressedLabelMap);
    const params = {
      bbsProof, labelMap, mandatoryIndexes, selectiveIndexes,
      presentationHeader
    };
    _validateDerivedProofParams(params);
    return params;
  } catch(e) {
    const err = new TypeError(
      'The proof does not include a valid "proofValue" property.');
    err.cause = e;
    throw err;
  }
}

function _decompressLabelMap(compressedLabelMap) {
  const map = new Map();
  for(const [k, v] of compressedLabelMap.entries()) {
    map.set(`c14n${k}`, `b${v}`);
  }
  return map;
}

function _startsWithBytes(buffer, prefix) {
  for(let i = 0; i < prefix.length; ++i) {
    if(buffer[i] !== prefix[i]) {
      return false;
    }
  }
  return true;
}

function _validateDerivedProofParams({
  bbsProof, labelMap, mandatoryIndexes, selectiveIndexes, presentationHeader
}) {
  if(!(bbsProof instanceof Uint8Array)) {
    // note: `bbsProof` length is variable
    throw new TypeError('"bbsProof" must be a Uint8Array.');
  }
  if(!(labelMap instanceof Map &&
    [...labelMap.entries()].every(
      ([k, v]) => typeof k === 'string' && typeof v === 'string'))) {
    throw new TypeError('"labelMap" must be a Map of strings to strings.');
  }
  if(!(Array.isArray(mandatoryIndexes) &&
    mandatoryIndexes.every(Number.isInteger))) {
    throw new TypeError('"mandatoryIndexes" must be an array of integers.');
  }
  if(!(Array.isArray(selectiveIndexes) &&
    selectiveIndexes.every(Number.isInteger))) {
    throw new TypeError('"selectiveIndexes" must be an array of integers.');
  }
  if(!(presentationHeader instanceof Uint8Array)) {
    // note: `presentationHeader` length is variable
    throw new TypeError('"presentationHeader" must be a Uint8Array.');
  }
}

function _decodeUint8Array(bytes) {
  return bytes;
}
