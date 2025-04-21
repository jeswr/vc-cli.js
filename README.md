# VC-CLI

A command-line utility for generating CIDs (Cryptographic Identifier Documents) and managing Verifiable Credentials.

## Installation

```bash
npm install -g @jeswr/vc-cli
```

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
