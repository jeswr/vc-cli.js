/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import { parseDisclosureProofValue } from './proofValue.js';
import {
  createLabelMapFunction,
  hashCanonizedProof,
  hashMandatory,
  labelReplacementCanonicalizeJsonLd,
} from '@digitalbazaar/di-sd-primitives';

export async function _createVerifyData({
  document, documentLoader
}) {
  const proof = document.proof;
  document = {
    ...document,
    proof: null
  };
  // 1. Generate `proofHash` in parallel.
  const options = { documentLoader };
  const proofHashPromise = hashCanonizedProof({ document, proof, options })
    .catch(e => e);

  // 2. Parse disclosure `proof` to get parameters to verify.
  const {
    bbsProof, labelMap, mandatoryIndexes, selectiveIndexes, presentationHeader
  } = await parseDisclosureProofValue({ proof });

  // 4. Canonicalize document using label map.
  const labelMapFactoryFunction = await createLabelMapFunction({ labelMap });
  const nquads = await labelReplacementCanonicalizeJsonLd(
    { document, labelMapFactoryFunction, options });

  // 5. Separate N-Quads into mandatory and non-mandatory.
  const mandatory = [];
  const nonMandatory = [];
  for (const [index, nq] of nquads.entries()) {
    if (mandatoryIndexes.includes(index)) {
      mandatory.push(nq);
    } else {
      nonMandatory.push(nq);
    }
  }

  // 6. Hash any mandatory N-Quads.
  const { mandatoryHash } = await hashMandatory({ mandatory });

  // 7. Return data used by cryptosuite to verify.
  const proofHash = await proofHashPromise;
  if (proofHash instanceof Error) {
    throw proofHash;
  }
  return {
    bbsProof, proofHash, nonMandatory, mandatoryHash, selectiveIndexes,
    presentationHeader, mandatory
  };
}
