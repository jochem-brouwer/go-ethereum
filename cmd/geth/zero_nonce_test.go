// Copyright 2026 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"encoding/json"
	"math"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// TestZeroNonceFinder builds a synthetic chain whose Spurious Dragon (EIP-158)
// activation is at block 5, deploys a contract in block 1 whose init code
// writes a storage slot and returns empty deployment bytecode, then checks
// that the resulting nonce-0/empty-code/non-empty-storage account is reported
// at the boundary. This exercises both the tracer (which must catch the
// transaction-level CREATE) and the post-state filter.
func TestZeroNonceFinder(t *testing.T) {
	var (
		key, _ = crypto.GenerateKey()
		addr   = crypto.PubkeyToAddress(key.PublicKey)

		// EIP158Block = 5 means blocks 0..4 are pre-Spurious-Dragon. The
		// contract is deployed in block 1, so its nonce stays at 0.
		// All later forks are pinned to block 5 as well so the chain config
		// is internally consistent.
		boundary = big.NewInt(5)
		config   = &params.ChainConfig{
			ChainID:                 big.NewInt(1),
			HomesteadBlock:          big.NewInt(0),
			EIP150Block:             big.NewInt(0),
			EIP155Block:             big.NewInt(0),
			EIP158Block:             boundary,
			ByzantiumBlock:          boundary,
			ConstantinopleBlock:     boundary,
			PetersburgBlock:         boundary,
			IstanbulBlock:           boundary,
			MuirGlacierBlock:        boundary,
			BerlinBlock:             boundary,
			LondonBlock:             boundary,
			ArrowGlacierBlock:       boundary,
			GrayGlacierBlock:        boundary,
			TerminalTotalDifficulty: big.NewInt(math.MaxInt64),
			Ethash:                  new(params.EthashConfig),
		}

		gspec = &core.Genesis{
			Config: config,
			Alloc: types.GenesisAlloc{
				addr: {Balance: big.NewInt(1_000_000_000_000_000_000)},
			},
		}
		signer = types.LatestSigner(config)

		// Init code:
		//   PUSH1 0x42  (60 42)
		//   PUSH1 0x00  (60 00)
		//   SSTORE      (55)
		//   PUSH1 0x00  (60 00)
		//   PUSH1 0x00  (60 00)
		//   RETURN      (f3)
		// Stores 0x42 at slot 0 then returns zero bytes of code.
		initCode = common.Hex2Bytes("604260005560006000F3")
	)

	_, blocks, _ := core.GenerateChainWithGenesis(gspec, ethash.NewFaker(), 5, func(i int, gen *core.BlockGen) {
		if i == 0 {
			tx, err := types.SignTx(
				types.NewContractCreation(gen.TxNonce(addr), new(big.Int), 200_000, big.NewInt(1), initCode),
				signer, key,
			)
			if err != nil {
				t.Fatalf("sign tx: %v", err)
			}
			gen.AddTx(tx)
		}
	})

	collector := newCreateCollector()
	options := core.DefaultConfig().WithStateScheme(rawdb.HashScheme)
	options.VmConfig.Tracer = collector.hooks()

	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), gspec, ethash.NewFaker(), options)
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	defer chain.Stop()

	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("insert chain: %v", err)
	}

	expectAddr := crypto.CreateAddress(addr, 0)
	if _, ok := collector.creations[expectAddr]; !ok {
		t.Fatalf("tracer did not record contract address %s", expectAddr.Hex())
	}

	header := chain.GetHeaderByNumber(boundary.Uint64())
	if header == nil {
		t.Fatalf("missing header at boundary block %d", boundary.Uint64())
	}
	statedb, err := chain.StateAt(header.Root)
	if err != nil {
		t.Fatalf("StateAt: %v", err)
	}

	// Sanity-check the contract really has the property we set up.
	if got := statedb.GetNonce(expectAddr); got != 0 {
		t.Fatalf("expected nonce 0, got %d", got)
	}
	if got := statedb.GetCodeHash(expectAddr); got != types.EmptyCodeHash {
		t.Fatalf("expected empty code hash, got %s", got.Hex())
	}
	if got := statedb.GetStorageRoot(expectAddr); got == (common.Hash{}) || got == types.EmptyRootHash {
		t.Fatalf("expected non-empty storage root, got %s", got.Hex())
	}

	var buf bytes.Buffer
	matches, err := inspectCreations(statedb, collector.creations, &buf)
	if err != nil {
		t.Fatalf("inspectCreations: %v", err)
	}
	if matches != 1 {
		t.Fatalf("expected 1 match, got %d", matches)
	}

	var match zeroNonceMatch
	if err := json.NewDecoder(&buf).Decode(&match); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if match.Address == nil {
		t.Fatalf("address missing from output")
	}
	if *match.Address != expectAddr {
		t.Fatalf("address mismatch: got %s want %s", match.Address.Hex(), expectAddr.Hex())
	}
	if match.AddressHash != crypto.Keccak256Hash(expectAddr.Bytes()) {
		t.Fatalf("address hash mismatch: got %s", match.AddressHash.Hex())
	}
	if match.CodeHash != types.EmptyCodeHash {
		t.Fatalf("expected empty code hash in output, got %s", match.CodeHash.Hex())
	}
	if match.StorageRoot == types.EmptyRootHash {
		t.Fatalf("expected non-empty storage root in output")
	}
}

// TestZeroNonceFinderIgnoresAccountsWithCode confirms that contracts that
// successfully deployed code (post-EIP-2-style) are NOT reported, even if
// they exist with nonce 0 (the user only cares about empty-code contracts).
func TestZeroNonceFinderIgnoresAccountsWithCode(t *testing.T) {
	var (
		key, _   = crypto.GenerateKey()
		addr     = crypto.PubkeyToAddress(key.PublicKey)
		boundary = big.NewInt(5)
		config   = &params.ChainConfig{
			ChainID:                 big.NewInt(1),
			HomesteadBlock:          big.NewInt(0),
			EIP150Block:             big.NewInt(0),
			EIP155Block:             big.NewInt(0),
			EIP158Block:             boundary,
			ByzantiumBlock:          boundary,
			ConstantinopleBlock:     boundary,
			PetersburgBlock:         boundary,
			IstanbulBlock:           boundary,
			MuirGlacierBlock:        boundary,
			BerlinBlock:             boundary,
			LondonBlock:             boundary,
			ArrowGlacierBlock:       boundary,
			GrayGlacierBlock:        boundary,
			TerminalTotalDifficulty: big.NewInt(math.MaxInt64),
			Ethash:                  new(params.EthashConfig),
		}
		gspec = &core.Genesis{
			Config: config,
			Alloc:  types.GenesisAlloc{addr: {Balance: big.NewInt(1_000_000_000_000_000_000)}},
		}
		signer = types.LatestSigner(config)

		// Init code that does SSTORE then RETURNs a non-empty code blob:
		//   PUSH1 0x42 PUSH1 0x00 SSTORE          ; storage[0] = 0x42
		//   PUSH1 0x01 PUSH1 0x00 PUSH1 0x00 CODECOPY  ; copy 1 byte of code at pc 0 to mem[0]
		//   PUSH1 0x01 PUSH1 0x00 RETURN          ; return 1 byte
		// Result: deployed code is "60" (1 byte), non-empty.
		initCode = common.Hex2Bytes("60426000556001600060003960016000F3")
	)

	_, blocks, _ := core.GenerateChainWithGenesis(gspec, ethash.NewFaker(), 5, func(i int, gen *core.BlockGen) {
		if i == 0 {
			tx, err := types.SignTx(
				types.NewContractCreation(gen.TxNonce(addr), new(big.Int), 200_000, big.NewInt(1), initCode),
				signer, key,
			)
			if err != nil {
				t.Fatalf("sign tx: %v", err)
			}
			gen.AddTx(tx)
		}
	})

	collector := newCreateCollector()
	options := core.DefaultConfig().WithStateScheme(rawdb.HashScheme)
	options.VmConfig.Tracer = collector.hooks()

	chain, err := core.NewBlockChain(rawdb.NewMemoryDatabase(), gspec, ethash.NewFaker(), options)
	if err != nil {
		t.Fatalf("new chain: %v", err)
	}
	defer chain.Stop()

	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("insert chain: %v", err)
	}

	expectAddr := crypto.CreateAddress(addr, 0)
	header := chain.GetHeaderByNumber(boundary.Uint64())
	statedb, err := chain.StateAt(header.Root)
	if err != nil {
		t.Fatalf("StateAt: %v", err)
	}

	// The contract should exist with deployed code; confirm and then check
	// our filter excludes it.
	if got := statedb.GetCodeHash(expectAddr); got == types.EmptyCodeHash {
		t.Fatalf("test setup: expected non-empty deployed code at %s", expectAddr.Hex())
	}

	var buf bytes.Buffer
	matches, err := inspectCreations(statedb, collector.creations, &buf)
	if err != nil {
		t.Fatalf("inspectCreations: %v", err)
	}
	if matches != 0 {
		t.Fatalf("expected 0 matches (contract has code), got %d; output: %s", matches, buf.String())
	}
}
