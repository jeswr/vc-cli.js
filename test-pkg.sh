mkdir -p test-pkg
cd test-pkg
npm init -y
npm install ..

npx vc-cli generate -o ./generated --distribute --collect
cd ..
# rm -rf ./test-pkg/
