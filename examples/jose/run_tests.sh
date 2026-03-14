#!/bin/bash

algorithms=(
    "ML-DSA-44-ES256"
    "ML-DSA-65-ES256"
    "ML-DSA-87-ES384"
    "ML-DSA-44-Ed25519"
    "ML-DSA-65-Ed25519"
    "ML-DSA-87-Ed448"
)

echo "Generation of JOSE Test Vectors..."

for alg in "${algorithms[@]}"
do
    echo "Algorithm: $alg"
    go run jws_composite.go -alg "$alg" > "$alg.jose.json"
done

echo "All JOSE test vectors generated."