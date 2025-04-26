# VC-CLI

A command-line utility for generating CIDs (Cryptographic Identifier Documents) and managing Verifiable Credentials.

## Installation

```bash
npm install -g @jeswr/vc-cli
```

## ⚠️ Warning

This library is currently in development and is **not intended for production use**. It is provided for testing and educational purposes only. Use at your own risk.

## Commands

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

#### Examples:

```bash
# Generate CID with default options
vc-cli generate-cid -c did:example:123

# Generate CID and save to specific files
vc-cli generate-cid -c did:example:123 -o cid.json -k keys.json
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

#### Example:

```bash
vc-cli sign-credential -c cid.json -k keys.json -d credential.json -i key-1 -o signed-credential.json
```

### Verify Credential

Verify a verifiable credential using a CID document.

```bash
vc-cli verify-credential -c <cid-path> -d <document-path>
```

#### Options:

- `-c, --cid <path>`: Path to CID document (required)
- `-d, --document <path>`: Path to verifiable credential to verify (required)

#### Example:

```bash
vc-cli verify-credential -c cid.json -d signed-credential.json
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

#### Example:

```bash
# Derive a credential revealing only specific fields
vc-cli derive-proof -d signed-credential.json -r '/credentialSubject/givenName,/credentialSubject/familyName' -o derived-credential.json
```

The derived credential can be verified using the same verification process as the original credential.

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
- `-o, --output-dir <path>`: Output directory for generated files [default: "./generated"]
- `--distribute`: Distribute documents across CIDs instead of having each CID sign all documents

#### Example:

```bash
# Generate with default options
vc-cli generate

# Generate with custom CIDs and documents
vc-cli generate -c "did:example:alice,did:example:bob" -d "./mocks/residence.jsonld,./mocks/education.jsonld"

# Generate with only BBS signatures and no derived proofs
vc-cli generate -s bbs --no-derive

# Generate with documents distributed across CIDs
vc-cli generate --distribute
```

The generate command will:
1. Create CIDs for each specified controller DID
2. Sign each document with each CID using the specified signature types
3. Create derived proofs for BBS signatures (unless disabled)
4. Save all generated files in the specified output directory
5. Verify all generated documents

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
