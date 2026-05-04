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
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/holiman/uint256"
)

// writeSnapshotAccount writes a synthetic snapshot account entry for tests.
// Setting storageRoot != EmptyRootHash makes the account appear to have
// non-empty storage; codeHash != EmptyCodeHash makes it appear to have code.
func writeSnapshotAccount(t *testing.T, db ethdb.KeyValueWriter, addr common.Address, nonce uint64, balance uint64, codeHash, storageRoot common.Hash) common.Hash {
	t.Helper()
	full := types.StateAccount{
		Nonce:    nonce,
		Balance:  uint256.NewInt(balance),
		Root:     storageRoot,
		CodeHash: codeHash[:],
	}
	addrHash := crypto.Keccak256Hash(addr.Bytes())
	rawdb.WriteAccountSnapshot(db, addrHash, types.SlimAccountRLP(full))
	return addrHash
}

// TestScanSnapshot constructs a synthetic snapshot containing four accounts
// with different shapes and verifies scanSnapshot only reports the one that
// matches the zero-nonce / empty-code / non-empty-storage condition. Storage
// slot keys and address preimages are also asserted.
func TestScanSnapshot(t *testing.T) {
	db := rawdb.NewMemoryDatabase()

	matchAddr := common.HexToAddress("0x0a0b0c0d0e0f10111213141516171819aaaabbbb")
	withCodeAddr := common.HexToAddress("0xdeadbeef00000000000000000000000000000001")
	emptyAddr := common.HexToAddress("0xdeadbeef00000000000000000000000000000002")
	nonZeroNonceAddr := common.HexToAddress("0xdeadbeef00000000000000000000000000000003")

	// Synthetic non-empty hashes for the matching account.
	storageRoot := common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	customCodeHash := common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")

	matchHash := writeSnapshotAccount(t, db, matchAddr, 0, 100, types.EmptyCodeHash, storageRoot)
	writeSnapshotAccount(t, db, withCodeAddr, 0, 0, customCodeHash, storageRoot)
	writeSnapshotAccount(t, db, emptyAddr, 0, 0, types.EmptyCodeHash, types.EmptyRootHash)
	writeSnapshotAccount(t, db, nonZeroNonceAddr, 1, 0, types.EmptyCodeHash, storageRoot)

	// Two storage slots for the matching account, with one preimage available.
	slotKeyKnown := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000007")
	slotKeyUnknown := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000ff")
	slotHashKnown := crypto.Keccak256Hash(slotKeyKnown.Bytes())
	slotHashUnknown := crypto.Keccak256Hash(slotKeyUnknown.Bytes())
	rawdb.WriteStorageSnapshot(db, matchHash, slotHashKnown, []byte{0x42})
	rawdb.WriteStorageSnapshot(db, matchHash, slotHashUnknown, []byte{0x99})

	// Preimages: address of the matching account and one slot key.
	rawdb.WritePreimages(db, map[common.Hash][]byte{
		matchHash:     matchAddr.Bytes(),
		slotHashKnown: slotKeyKnown.Bytes(),
	})

	var buf bytes.Buffer
	emitted := make(map[common.Address]struct{})
	matches, err := scanSnapshot(db, &buf, emitted)
	if err != nil {
		t.Fatalf("scanSnapshot: %v", err)
	}
	if matches != 1 {
		t.Fatalf("expected 1 match, got %d (output: %s)", matches, buf.String())
	}

	var got zeroNonceMatch
	if err := json.NewDecoder(&buf).Decode(&got); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if got.Address == nil || *got.Address != matchAddr {
		t.Fatalf("address mismatch: got %v want %s", got.Address, matchAddr.Hex())
	}
	if got.AddressHash != matchHash {
		t.Fatalf("address hash mismatch: got %s want %s", got.AddressHash.Hex(), matchHash.Hex())
	}
	if got.CodeHash != types.EmptyCodeHash {
		t.Fatalf("code hash mismatch: got %s", got.CodeHash.Hex())
	}
	if got.StorageRoot != storageRoot {
		t.Fatalf("storage root mismatch: got %s want %s", got.StorageRoot.Hex(), storageRoot.Hex())
	}

	if len(got.Storage) != 2 {
		t.Fatalf("expected 2 storage slots, got %d (%+v)", len(got.Storage), got.Storage)
	}
	var foundKnown, foundUnknown bool
	for _, slot := range got.Storage {
		switch slot.KeyHash {
		case slotHashKnown:
			foundKnown = true
			if slot.Key == nil || *slot.Key != slotKeyKnown {
				t.Errorf("known slot preimage missing or wrong: %+v", slot)
			}
		case slotHashUnknown:
			foundUnknown = true
			if slot.Key != nil {
				t.Errorf("expected no preimage for unknown slot, got %s", slot.Key.Hex())
			}
		default:
			t.Errorf("unexpected slot in output: %+v", slot)
		}
	}
	if !foundKnown || !foundUnknown {
		t.Fatalf("missing one of the expected slots; foundKnown=%v foundUnknown=%v", foundKnown, foundUnknown)
	}

	// Re-scan should be a no-op (dedupe via emitted set).
	buf.Reset()
	matches, err = scanSnapshot(db, &buf, emitted)
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if matches != 0 {
		t.Fatalf("expected 0 matches on rescan (already emitted), got %d (output: %s)", matches, buf.String())
	}
}
