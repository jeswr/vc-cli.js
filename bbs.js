import * as vc from '@digitalbazaar/vc';
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as bbs2023Cryptosuite from '@digitalbazaar/bbs-2023-cryptosuite';

import jsigs from 'jsonld-signatures';
import { credential } from './credential.js';
import { documentLoader } from './documentLoader.js';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
const {
  createDiscloseCryptosuite,
  createSignCryptosuite
} = bbs2023Cryptosuite;

const {purposes: {AssertionProofPurpose}} = jsigs;

const cryptosuite = createSignCryptosuite();

const publicKeyMultibase = 'zUC76eySqgji6uNDaCrsWnmQnwq8pj1MZUDrRGc2BGRu61baZPKPFB7YpHawussp2YohcEMAeMVGHQ9JtKvjxgGTkYSMN53ZfCH4pZ6TGYLawvzy1wE54dS6PQcut9fxdHH32gi';
const secretKeyMultibase = 'z488x5kHU9aUe1weTqaf2sGFPgQS1HhunREFwB9bFeFwLch5';

export const controller = `did:key:${publicKeyMultibase}`;
const keyId = `${controller}#${publicKeyMultibase}`;

export const publicBls12381Multikey = {
  '@context': 'https://w3id.org/security/multikey/v1',
  type: 'Multikey',
  controller,
  id: keyId,
  publicKeyMultibase
};

export const bls12381MultikeyKeyPair = {
  '@context': 'https://w3id.org/security/multikey/v1',
  type: 'Multikey',
  controller,
  id: keyId,
  publicKeyMultibase,
  secretKeyMultibase
};

const algorithm = Bls12381Multikey.ALGORITHMS.BBS_BLS12381_SHA256;
const keyPair = await Bls12381Multikey.from({
  ...bls12381MultikeyKeyPair
}, {algorithm});

const date = '2023-03-01T21:29:24Z';
const suite = new DataIntegrityProof({
  signer: keyPair.signer(), date, cryptosuite
});

const signedCredential = await jsigs.sign(credential, {
    suite,
    purpose: new AssertionProofPurpose(),
    documentLoader
  });

console.log(signedCredential);