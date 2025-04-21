export const credential = {
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