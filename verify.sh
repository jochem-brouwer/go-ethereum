#!/usr/bin/env bash
# usage:
#   cat matches.jsonl | ./verify.sh > still_matching.jsonl
#
# Two passes:
#   1. eth_getProof per address: keep only those still satisfying the
#      zero-nonce / empty-code / non-empty-storage condition on `latest`.
#   2. For each survivor, build the storage trie locally from the slots
#      we listed in matches.jsonl, fetching their values via eth_getProof
#      with all keys at once, and verify that the computed root equals
#      mainnet's reported storageHash. Any mismatch means we missed slots.
#
# The second pass requires the verify-storage-root binary; build it with
#   go build -o ./verify-storage-root ./cmd/verify-storage-root
set -euo pipefail
RPC="${RPC:-https://eth.llamarpc.com}"
VERIFIER="${VERIFIER:-./verify-storage-root}"
EMPTY_ROOT="0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
EMPTY_CODE="0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

if [ ! -x "$VERIFIER" ]; then
  echo "verify-storage-root not found at $VERIFIER; build with: go build -o $VERIFIER ./cmd/verify-storage-root" >&2
  exit 1
fi

# Pass 1: filter to addresses still matching on mainnet, decorate with the
# current storage hash, then pipe straight into verify-storage-root which
# does the trie reconstruction check on stderr-friendly format.
{
  while IFS= read -r line; do
    addr=$(jq -r .address <<<"$line")
    [ -z "$addr" ] || [ "$addr" = "null" ] && continue

    resp=$(curl -sS -X POST -H 'Content-Type: application/json' "$RPC" --data \
      "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getProof\",\"params\":[\"$addr\",[],\"latest\"]}")

    read -r nonce code storage <<<$(jq -r '[.result.nonce, .result.codeHash, .result.storageHash] | @tsv' <<<"$resp")

    if [ "$nonce" = "0x0" ] && [ "$code" = "$EMPTY_CODE" ] && [ "$storage" != "$EMPTY_ROOT" ]; then
      jq -c --arg sh "$storage" '. + {currentStorageHash: $sh}' <<<"$line"
    fi

    sleep 2  # be polite to public RPC
  done
} | tee >("$VERIFIER" --rpc "$RPC" >&2)
