import * as vc from '@digitalbazaar/vc';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';
import { credential } from './credential.js';
import { documentLoader } from './documentLoader.js';

const keyPair = await Ed25519VerificationKey2020.generate({
  id: 'did:example:abc123'
});

const suite = new Ed25519Signature2020({
  key: keyPair,
  verificationMethod: keyPair.id
});

const signedVC = await vc.issue({ 
  credential, 
  suite, 
  documentLoader 
});

console.log(JSON.stringify(signedVC, null, 2));
