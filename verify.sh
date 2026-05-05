#!/usr/bin/env bash
# usage: cat matches.jsonl | ./verify.sh > still_matching.jsonl
set -euo pipefail
RPC="${RPC:-https://eth.llamarpc.com}"
EMPTY_ROOT="0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
EMPTY_CODE="0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

while IFS= read -r line; do
  addr=$(jq -r .address <<<"$line")
  [ -z "$addr" ] || [ "$addr" = "null" ] && continue

  resp=$(curl -sS -X POST -H 'Content-Type: application/json' "$RPC" --data \
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getProof\",\"params\":[\"$addr\",[],\"latest\"]}")

  read -r nonce code storage <<<$(jq -r '[.result.nonce, .result.codeHash, .result.storageHash] | @tsv' <<<"$resp")

  if [ "$nonce" = "0x0" ] && [ "$code" = "$EMPTY_CODE" ] && [ "$storage" != "$EMPTY_ROOT" ]; then
    jq -c --arg sh "$storage" '. + {currentStorageHash: $sh}' <<<"$line"
  fi

  sleep 0.05  # be polite to public RPC
done
