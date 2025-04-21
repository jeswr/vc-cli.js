import * as vc from '@digitalbazaar/vc';
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020';
import { Ed25519Signature2020 } from '@digitalbazaar/ed25519-signature-2020';

const keyPair = await Ed25519VerificationKey2020.generate({
  id: 'did:example:abc123'
});

const suite = new Ed25519Signature2020({
  key: keyPair,
  verificationMethod: keyPair.id
});

// Sample unsigned credential
const credential = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/citizenship/v4rc1"
  ],
  "type": [
    "VerifiableCredential",
    "PermanentResidentCardCredential"
  ],
  "issuer": {
    "id": "did:key:zDnaeTHxNEBZoKaEo6PdA83fq98ebiFvo3X273Ydu4YmV96rg",
    "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2P4z/DiPwAG0ALnwgz64QAAAABJRU5ErkJggg=="
  },
  "name": "Permanent Resident Card",
  "description": "Government of Utopia Permanent Resident Card.",
  "credentialSubject": {
    "type": [
      "PermanentResident",
      "Person"
    ]
  }
};

const signedVC = await vc.issue({ credential, suite, documentLoader: vc.defaultDocumentLoader() });
console.log(JSON.stringify(signedVC, null, 2));