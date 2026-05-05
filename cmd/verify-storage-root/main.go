// verify-storage-root reads matches.jsonl entries on stdin, fetches the
// current value of every listed storage slot from a mainnet RPC endpoint
// via eth_getProof, builds the storage trie locally from the (slotHash,
// value) pairs, and compares the computed root to the storageHash that
// mainnet itself reports.
//
// Equality means our snapshot scan captured every slot for that account.
// Inequality means either we missed slots or mainnet's storage has changed
// since the boundary block (which shouldn't happen for matching accounts —
// they have no code, so nothing can write to their storage post-creation).
//
// Usage:
//   go build -o verify-storage-root ./cmd/verify-storage-root
//   cat verified.jsonl | ./verify-storage-root --rpc https://eth.llamarpc.com
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
)

type slot struct {
	Key     *common.Hash `json:"key,omitempty"`
	KeyHash common.Hash  `json:"keyHash"`
}

type match struct {
	Address     *common.Address `json:"address"`
	AddressHash common.Hash     `json:"addressHash"`
	StorageRoot common.Hash     `json:"storageRoot"`
	Storage     []slot          `json:"storage"`
}

type rpcReq struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      int           `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type rpcResp struct {
	Result *proofResult    `json:"result"`
	Error  json.RawMessage `json:"error,omitempty"`
}

type proofResult struct {
	StorageHash  common.Hash    `json:"storageHash"`
	StorageProof []storageProof `json:"storageProof"`
}

type storageProof struct {
	Key   string `json:"key"`   // slot key preimage as 0x-prefixed hex
	Value string `json:"value"` // big-endian, leading zeros stripped on the wire
}

func main() {
	rpcURL := flag.String("rpc", "https://eth.llamarpc.com", "JSON-RPC endpoint")
	block := flag.String("block", "latest", "Block to verify against (tag or 0x-hex)")
	delay := flag.Duration("delay", 100*time.Millisecond, "Delay between RPC requests (politeness for public RPCs)")
	flag.Parse()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var (
		total, ok, mismatch, skipped int
	)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var m match
		if err := json.Unmarshal(line, &m); err != nil {
			log.Printf("skip malformed line: %v", err)
			skipped++
			continue
		}
		total++
		result, err := verify(*rpcURL, *block, m)
		if err != nil {
			log.Printf("%s: %v", addrStr(m), err)
			skipped++
			continue
		}
		fmt.Println(result)
		if strings.Contains(result, "match=true") {
			ok++
		} else {
			mismatch++
		}
		time.Sleep(*delay)
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("read stdin: %v", err)
	}
	log.Printf("verified=%d match=%d mismatch=%d skipped=%d", total, ok, mismatch, skipped)
}

func addrStr(m match) string {
	if m.Address != nil {
		return m.Address.Hex()
	}
	return m.AddressHash.Hex()
}

func verify(rpcURL, block string, m match) (string, error) {
	if m.Address == nil {
		return "", fmt.Errorf("address preimage missing")
	}
	keys := make([]string, 0, len(m.Storage))
	for _, s := range m.Storage {
		if s.Key == nil {
			return "", fmt.Errorf("missing slot preimage for keyHash %s", s.KeyHash.Hex())
		}
		keys = append(keys, s.Key.Hex())
	}

	pr, err := getProof(rpcURL, m.Address.Hex(), keys, block)
	if err != nil {
		return "", err
	}

	// Build a fresh storage trie from (keccak256(slotKey), rlp(stripped value)) pairs.
	// Storage trie keys are hashed slot keys (we pre-have them in keyHash, but we
	// rederive from each proof entry to ensure ordering integrity). Storage trie
	// values are RLP of the slot value with leading zero bytes trimmed; zero
	// values aren't stored at all.
	db := triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil)
	tr, err := trie.New(trie.TrieID(common.Hash{}), db)
	if err != nil {
		return "", fmt.Errorf("open empty trie: %w", err)
	}
	for _, sp := range pr.StorageProof {
		valBytes, err := hexToBytes(sp.Value)
		if err != nil {
			return "", fmt.Errorf("invalid value %q: %w", sp.Value, err)
		}
		stripped := bytes.TrimLeft(valBytes, "\x00")
		if len(stripped) == 0 {
			continue // zero value — not in trie
		}
		rlpVal, err := rlp.EncodeToBytes(stripped)
		if err != nil {
			return "", err
		}
		keyBytes, err := hexToBytes(sp.Key)
		if err != nil {
			return "", fmt.Errorf("invalid key %q: %w", sp.Key, err)
		}
		// Slot key preimage may be returned without leading zeros; left-pad to 32 bytes.
		if len(keyBytes) < 32 {
			padded := make([]byte, 32)
			copy(padded[32-len(keyBytes):], keyBytes)
			keyBytes = padded
		}
		keyHash := crypto.Keccak256Hash(keyBytes)
		if err := tr.Update(keyHash[:], rlpVal); err != nil {
			return "", err
		}
	}

	computed := tr.Hash()
	matchOK := computed == pr.StorageHash
	return fmt.Sprintf("%s mainnetRoot=%s computedRoot=%s slots=%d match=%v",
		m.Address.Hex(), pr.StorageHash.Hex(), computed.Hex(), len(m.Storage), matchOK), nil
}

func hexToBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

func getProof(rpcURL, address string, slotKeys []string, block string) (*proofResult, error) {
	body := rpcReq{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "eth_getProof",
		Params:  []interface{}{address, slotKeys, block},
	}
	enc, _ := json.Marshal(body)

	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(enc))
	if err != nil {
		return nil, fmt.Errorf("post %s: %w", rpcURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(raw))
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var r rpcResp
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parse response: %w (body=%s)", err, string(raw))
	}
	if len(r.Error) > 0 {
		return nil, fmt.Errorf("rpc error: %s", string(r.Error))
	}
	if r.Result == nil {
		return nil, fmt.Errorf("nil result (body=%s)", string(raw))
	}
	return r.Result, nil
}
