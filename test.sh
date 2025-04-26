node bin.js generate-cid -c 'http://example.org/alice' -o ./alice.jsonld -k privatekeys.jsonld
node ./bin.js sign-credential --cid ./alice.jsonld -k ./privatekeys.jsonld -d ./mocks/residence.jsonld -o ./signed-residence.jsonld -i 'http://example.org/alice#key-1'
node ./bin.js sign-credential --cid ./alice.jsonld -k ./privatekeys.jsonld -d ./mocks/residence.jsonld -o ./bbs-signed-residence.jsonld -i 'http://example.org/alice#key-2'

# Derive a BBS proof revealing only specific fields
node ./bin.js derive-proof -d ./bbs-signed-residence.jsonld -r '/credentialSubject/givenName,/credentialSubject/familyName,/credentialSubject/birthCountry' -o ./derived-residence.jsonld

node bin.js verify-credential -c ./alice.jsonld -d ./signed-residence.jsonld
node bin.js verify-credential -c ./alice.jsonld -d ./derived-residence.jsonld

# node bin.js generate 
