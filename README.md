# Verifiable Credentials CLI and API

This package provides both a CLI and programmatic API for working with Verifiable Credentials, including CID generation, credential signing, verification, and proof derivation.

## Installation

```bash
npm install -g @jeswr/vc-cli
```

## ⚠️ Warning

This library is currently in development and is **not intended for production use**. It is provided for testing and educational purposes only. Use at your own risk.

## API Reference

### `generateCIDDocument(controller, options)`

Generates a new CID (Cryptographic Identifier) document.

```javascript
import { generateCIDDocument } from '@your-package-name';

const { cid, privateKeys } = await generateCIDDocument('did:example:alice', {
  includeEd25519: true,  // optional, defaults to true
  includeBBS: true       // optional, defaults to true
});
```

#### Parameters:
- `controller` (string): The DID to use as the controller
- `options` (object, optional):
  - `includeEd25519` (boolean): Whether to include Ed25519 signature type
  - `includeBBS` (boolean): Whether to include BBS+ signature type

#### Returns:
- `{ cid: Object, privateKeys: Object }`: The generated CID document and private keys

### `signCredential(options)`

Signs a verifiable credential using a CID document and private keys.

```javascript
import { signCredential } from '@your-package-name';

const signedCredential = await signCredential({
  cid: cidDocument,
  privateKeys: privateKeysObject,
  document: credentialDocument,
  keyId: 'verification-method-id',
  credentialId: 'optional-credential-id',
  subjectId: 'optional-subject-id'
});
```

#### Parameters:
- `options` (object):
  - `cid` (Object): CID document
  - `privateKeys` (Object): Private keys object
  - `document` (Object): Document to sign
  - `keyId` (string): ID of the key to use for signing
  - `credentialId` (string, optional): ID for the credential
  - `subjectId` (string, optional): ID for the credential subject

#### Returns:
- `Object`: The signed credential

### `verifyCredential(options)`

Verifies a verifiable credential using a CID document.

```javascript
import { verifyCredential } from '@your-package-name';

const isValid = await verifyCredential({
  cid: cidDocument,
  document: signedCredential
});
```

#### Parameters:
- `options` (object):
  - `cid` (Object): CID document
  - `document` (Object): Verifiable credential to verify

#### Returns:
- `boolean`: Whether the verification was successful

### `deriveProof(options)`

Creates a derived BBS proof from a signed input BBS document.

```javascript
import { deriveProof } from '@your-package-name';

const derivedDocument = await deriveProof({
  document: signedBBSDocument,
  revealPointers: ['/credentialSubject/name', '/credentialSubject/age']
});
```

#### Parameters:
- `options` (object):
  - `document` (Object): Signed BBS document
  - `revealPointers` (string[]): Array of JSON pointers to reveal

#### Returns:
- `Object`: The derived document

### `preprocessBBSVerification(options)`

Preprocesses BBS verification data from derived credentials.

```javascript
import { preprocessBBSVerification } from '@your-package-name';

const preprocessedData = await preprocessBBSVerification({
  document: derivedBBSDocument,
  cid: cidDocument
});
```

#### Parameters:
- `options` (object):
  - `document` (Object): Derived BBS document
  - `cid` (Object): CID document

#### Returns:
- `Object`: The preprocessed data containing verification information

### `preprocessEd25519Verification(options)`

Preprocesses Ed25519 verification data from signed credentials.

```javascript
import { preprocessEd25519Verification } from '@your-package-name';

const preprocessedData = await preprocessEd25519Verification({
  document: signedEd25519Document,
  cid: cidDocument
});
```

#### Parameters:
- `options` (object):
  - `document` (Object): Signed Ed25519 document
  - `cid` (Object): CID document

#### Returns:
- `Object`: The preprocessed data containing verification information

### `collectDocuments(options)`

Collects JSON-LD documents into a single Turtle file, excluding proofs.

```javascript
import { collectDocuments } from '@your-package-name';

await collectDocuments({
  documents: ['path/to/doc1.jsonld', 'path/to/doc2.jsonld'],
  outputPath: 'output.ttl'
});
```

#### Parameters:
- `options` (object):
  - `documents` (string[]): Array of JSON-LD document paths
  - `outputPath` (string): Output path for Turtle file (must end with .ttl)

#### Returns:
- `Promise<void>`

## CLI Commands

### Generate CID

Generate a new CID document with cryptographic keys.

```bash
vc-cli generate-cid -c <controller-did> [options]
```

#### Options:

- `-c, --controller <controller>`: Controller DID (required)
- `-o, --output <path>`: Output path for CID document (file or directory)
- `-k, --keys <path>`: Path to save private keys JSON file
- `--no-ed25519`: Exclude Ed25519 signature type
- `--no-bbs`: Exclude BBS+ signature type
- `--document-loader-content <path>`: Path to JSON file containing predefined document loader responses

#### Examples:

```bash
# Generate CID with default options
vc-cli generate-cid -c did:example:123

# Generate CID and save to specific files
vc-cli generate-cid -c did:example:123 -o cid.json -k keys.json

# Generate CID with custom document loader content
vc-cli generate-cid -c did:example:123 --document-loader-content loader-content.json
```

### Sign Credential

Sign a verifiable credential using a CID document and private keys.

```bash
vc-cli sign-credential -c <cid-path> -k <keys-path> -d <document-path> -i <key-id> -o <output-path>
```

#### Options:

- `-c, --cid <path>`: Path to CID document (required)
- `-k, --keys <path>`: Path to private keys JSON file (required)
- `-d, --document <path>`: Path to JSON-LD document to sign (required)
- `-i, --key-id <id>`: ID of the key to use for signing (required)
- `-o, --output <path>`: Output path for signed credential (required)
- `--credential-id <id>`: ID for the credential (optional)
- `--subject-id <id>`: ID for the credential subject (optional)
- `--document-loader-content <path>`: Path to JSON file containing predefined document loader responses

#### Example:

```bash
# Sign a credential with default options
vc-cli sign-credential -c cid.json -k keys.json -d credential.json -i key-1 -o signed-credential.json

# Sign a credential with custom IDs and document loader content
vc-cli sign-credential -c cid.json -k keys.json -d credential.json -i key-1 -o signed-credential.json --credential-id "urn:uuid:123" --subject-id "did:example:subject" --document-loader-content loader-content.json
```

### Verify Credential

Verify a verifiable credential using a CID document.

```bash
vc-cli verify-credential -c <cid-path> -d <document-path>
```

#### Options:

- `-c, --cid <path>`: Path to CID document (required)
- `-d, --document <path>`: Path to verifiable credential to verify (required)
- `--document-loader-content <path>`: Path to JSON file containing predefined document loader responses

#### Example:

```bash
# Verify a credential with default options
vc-cli verify-credential -c cid.json -d signed-credential.json

# Verify a credential with custom document loader content
vc-cli verify-credential -c cid.json -d signed-credential.json --document-loader-content loader-content.json
```

### Derive Credential

Create a derived BBS proof from a signed credential, revealing only specific fields while maintaining the cryptographic integrity of the original credential.

```bash
vc-cli derive-proof -d <document-path> -r <pointers> -o <output-path>
```

#### Options:

- `-d, --document <path>`: Path to signed BBS document (required)
- `-r, --reveal <pointers>`: Comma-separated list of JSON pointers to reveal (required)
- `-o, --output <path>`: Output path for derived document (required)
- `--document-loader-content <path>`: Path to JSON file containing predefined document loader responses

#### Example:

```bash
# Derive a credential revealing only specific fields
vc-cli derive-proof -d signed-credential.json -r '/credentialSubject/givenName,/credentialSubject/familyName' -o derived-credential.json

# Derive a credential with custom document loader content
vc-cli derive-proof -d signed-credential.json -r '/credentialSubject/givenName,/credentialSubject/familyName' -o derived-credential.json --document-loader-content loader-content.json
```

### BBS Verify Preprocess

Preprocess BBS verification data from derived credentials for efficient verification.

```bash
vc-cli bbs-verify-preprocess -d <document-path> -c <cid-path> -o <output-path>
```

#### Options:

- `-d, --document <path>`: Path to derived BBS document or directory containing derived BBS documents (required)
- `-c, --cid <path>`: Path to CID document (required)
- `-o, --output <path>`: Output path for preprocessed data (file or directory) (required)
- `--document-loader-content <path>`: Path to JSON file containing predefined document loader responses

#### Example:

```bash
# Preprocess a single derived BBS document
vc-cli bbs-verify-preprocess -d derived-credential.json -c cid.json -o preprocessed.json

# Preprocess with custom document loader content
vc-cli bbs-verify-preprocess -d derived-credential.json -c cid.json -o preprocessed.json --document-loader-content loader-content.json
```

### Ed25519 Verify Preprocess

Preprocess Ed25519 verification data from signed credentials for efficient verification.

```bash
vc-cli ed25519-verify-preprocess -d <document-path> -c <cid-path> -o <output-path>
```

#### Options:

- `-d, --document <path>`: Path to signed Ed25519 document or directory containing signed Ed25519 documents (required)
- `-c, --cid <path>`: Path to CID document (required)
- `-o, --output <path>`: Output path for preprocessed data (file or directory) (required)
- `--document-loader-content <path>`: Path to JSON file containing predefined document loader responses

#### Example:

```bash
# Preprocess a single Ed25519 document
vc-cli ed25519-verify-preprocess -d signed-credential.json -c cid.json -o preprocessed.json

# Preprocess with custom document loader content
vc-cli ed25519-verify-preprocess -d signed-credential.json -c cid.json -o preprocessed.json --document-loader-content loader-content.json
```

### Generate

Generate CIDs, sign credentials, and create derived proofs in a batch process.

```bash
vc-cli generate [options]
```

#### Options:

- `-c, --cids <ids>`: Comma-separated list of CID controller DIDs [default: "did:example:alice,did:example:bob,did:example:charlie,did:example:dave"]
- `-d, --documents <paths>`: Comma-separated list of credential document paths to sign [default: all mock credentials]
- `-s, --signatures <types>`: Comma-separated list of signature types to use (bbs,ed25519) [default: "bbs,ed25519"]
- `--no-derive`: Skip creating derived proofs for BBS signatures
- `--no-preprocess`: Skip preprocessing derived proofs (enabled by default)
- `-o, --output-dir <path>`: Output directory for generated files [default: "./generated"]
- `--distribute`: Distribute documents across CIDs instead of having each CID sign all documents
- `--collect`: Collect all generated files into a single Turtle file named `collected.ttl` in the output directory
- `--subject-id <id>`: ID for the credential subject (optional, defaults to a random DID)
- `--document-loader-content <path>`: Path to JSON file containing predefined document loader responses

#### Example:

```bash
# Generate with default options
vc-cli generate

# Generate with custom document loader content
vc-cli generate --document-loader-content loader-content.json

# Generate with custom CIDs, documents, and document loader content
vc-cli generate -c "did:example:alice,did:example:bob" -d "./mocks/residence.jsonld,./mocks/education.jsonld" --document-loader-content loader-content.json
```

### Collect

Collect multiple JSON-LD documents into a single Turtle file, excluding proofs.

```bash
vc-cli collect -d <directory-path> -o <output-path>
```

#### Options:

- `-d, --directory <path>`: Directory containing JSON-LD documents (required)
- `-o, --output <path>`: Output path for Turtle file (must end with .ttl) (required)
- `--document-loader-content <path>`: Path to JSON file containing predefined document loader responses

#### Example:

```bash
# Collect all JSON-LD documents from a directory into a single Turtle file
vc-cli collect -d ./generated -o output.ttl

# Collect with custom document loader content
vc-cli collect -d ./generated -o output.ttl --document-loader-content loader-content.json
```

## Document Loader Content

The `--document-loader-content` option allows you to provide predefined responses for specific URLs used in JSON-LD document processing. This is useful for:

- Testing with mock data
- Working offline
- Ensuring consistent responses
- Avoiding network requests for known contexts and schemas

The document loader content file should be a JSON file with the following structure:

```json
{
  "https://example.org/context.json": {
    "@context": {
      // context content
    }
  },
  "https://example.org/schema.json": {
    // schema content
  }
}
```

When a URL is requested during document processing, the document loader will:
1. First check if the URL exists in the provided content
2. If found, return that content immediately
3. If not found, fall back to the existing caching behavior
4. Finally, if not in cache, use the default document loader or fetch from the network

This allows for more control over the document loading process and can help improve performance and reliability in various scenarios.

## Error Handling

The CLI tool provides clear error messages when:

- Required options are missing
- Files cannot be read or written
- Cryptographic operations fail
- Credential verification fails

## License

MIT

## Author

Jesse Wright
