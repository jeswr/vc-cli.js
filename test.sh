#!/bin/bash

# Exit on any error
set -e

# Validate all JSON-LD files in the mocks directory
for file in ./mocks/*.jsonld; do
  echo "Validating $file..."
  if ! npm run validate-jsonld "$file"; then
    echo "Validation failed for $file"
    exit 1
  fi
done

if ! npm run validate-jsonld ./mocks/employable.jsonld; then
  echo "Validation failed for employable.jsonld"
  exit 1
fi

node bin.js generate-cid -c 'http://example.org/alice' -o ./alice.jsonld -k privatekeys.jsonld
node ./bin.js sign-credential --cid ./alice.jsonld -k ./privatekeys.jsonld -d ./mocks/residence.jsonld -o ./signed-residence.jsonld -i 'http://example.org/alice#key-1'
node ./bin.js sign-credential --cid ./alice.jsonld -k ./privatekeys.jsonld -d ./mocks/residence.jsonld -o ./bbs-signed-residence.jsonld -i 'http://example.org/alice#key-2'

# Derive a BBS proof revealing only specific fields
node ./bin.js derive-proof -d ./bbs-signed-residence.jsonld -r '/credentialSubject/givenName,/credentialSubject/familyName,/credentialSubject/birthCountry' -o ./derived-residence.jsonld

node bin.js verify-credential -c ./alice.jsonld -d ./signed-residence.jsonld
node bin.js verify-credential -c ./alice.jsonld -d ./derived-residence.jsonld

node bin.js generate 

node bin.js generate  -o ./generate-distributed --distribute --collect

node bin.js collect -d ./generated -o generated.ttl
node bin.js collect -d ./generate-distributed -o generated-distributed.ttl

npx rdf-dereference generated.ttl > generated-dereferenced.ttl
npx rdf-dereference generated-distributed.ttl > generated-distributed-dereferenced.ttl
npx rdf-dereference ./generate-distributed/collected.ttl > generated-distributed-collected-dereferenced.ttl
