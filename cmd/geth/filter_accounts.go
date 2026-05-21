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
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/urfave/cli/v2"
)

// Tri-state filter applied to a per-account boolean predicate (has code, has
// non-empty storage, nonzero nonce, nonzero balance). filterAny is the
// identity; filterRequireFalse keeps accounts whose predicate is false
// ("empty"/"zero" side); filterRequireTrue keeps accounts whose predicate is
// true ("nonempty"/"nonzero" side).
type accountFilter int

const (
	filterAny accountFilter = iota
	filterRequireFalse
	filterRequireTrue
)

func parseAccountFilter(val string) (accountFilter, error) {
	switch val {
	case "", "any":
		return filterAny, nil
	case "empty", "zero":
		return filterRequireFalse, nil
	case "nonempty", "nonzero":
		return filterRequireTrue, nil
	default:
		return filterAny, fmt.Errorf("invalid filter value %q (expected any|empty|zero|nonempty|nonzero)", val)
	}
}

func (f accountFilter) matches(hasFeature bool) bool {
	switch f {
	case filterRequireFalse:
		return !hasFeature
	case filterRequireTrue:
		return hasFeature
	default:
		return true
	}
}

var (
	filterAccountsCodeFlag = &cli.StringFlag{
		Name:  "filter-accounts.code",
		Value: "any",
		Usage: "Filter on code: any|empty|nonempty",
	}
	filterAccountsNonceFlag = &cli.StringFlag{
		Name:  "filter-accounts.nonce",
		Value: "any",
		Usage: "Filter on nonce: any|zero|nonzero",
	}
	filterAccountsStorageFlag = &cli.StringFlag{
		Name:  "filter-accounts.storage",
		Value: "any",
		Usage: "Filter on storage: any|empty|nonempty",
	}
	filterAccountsBalanceFlag = &cli.StringFlag{
		Name:  "filter-accounts.balance",
		Value: "any",
		Usage: "Filter on balance: any|zero|nonzero",
	}
	filterAccountsOutFlag = &cli.StringFlag{
		Name:  "filter-accounts.out",
		Value: "-",
		Usage: "Output JSONL path (- for stdout)",
	}
)

// filterAccounts walks the disk-layer snapshot of the open datadir and emits
// one JSONL record per account satisfying every supplied filter. The DB's
// head block is logged at start and the total match count at the end, so
// callers know which state was filtered and how many accounts matched.
func filterAccounts(ctx *cli.Context) error {
	codeF, err := parseAccountFilter(ctx.String(filterAccountsCodeFlag.Name))
	if err != nil {
		return err
	}
	nonceF, err := parseAccountFilter(ctx.String(filterAccountsNonceFlag.Name))
	if err != nil {
		return err
	}
	storageF, err := parseAccountFilter(ctx.String(filterAccountsStorageFlag.Name))
	if err != nil {
		return err
	}
	balanceF, err := parseAccountFilter(ctx.String(filterAccountsBalanceFlag.Name))
	if err != nil {
		return err
	}

	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	db := utils.MakeChainDatabase(ctx, stack, true)
	defer db.Close()

	if head := rawdb.ReadHeadBlock(db); head != nil {
		log.Info("Filter accounts: DB head",
			"number", head.NumberU64(), "hash", head.Hash(), "root", head.Root())
	} else {
		log.Warn("Filter accounts: no head block in DB")
	}
	snapRoot := rawdb.ReadSnapshotRoot(db)
	if snapRoot == (common.Hash{}) {
		return errors.New("no snapshot present in this datadir; build one (snap sync or find-zero-nonce-replay) first")
	}
	log.Info("Filter accounts: snapshot root", "root", snapRoot)
	log.Info("Filter accounts: filters",
		"code", ctx.String(filterAccountsCodeFlag.Name),
		"nonce", ctx.String(filterAccountsNonceFlag.Name),
		"storage", ctx.String(filterAccountsStorageFlag.Name),
		"balance", ctx.String(filterAccountsBalanceFlag.Name))

	var w io.Writer = os.Stdout
	if outPath := ctx.String(filterAccountsOutFlag.Name); outPath != "" && outPath != "-" {
		f, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("open %s: %w", outPath, err)
		}
		defer f.Close()
		w = f
		log.Info("Filter accounts: writing matches", "path", outPath)
	}

	matches, scanned, err := scanFilteredAccounts(db, w, codeF, nonceF, storageF, balanceF)
	if err != nil {
		return err
	}
	log.Info("Filter accounts: done", "scanned", scanned, "matches", matches)
	return nil
}

// filteredAccount is the JSONL record emitted per match. AddressHash is the
// snapshot key (always present); Address is the 20-byte preimage and is only
// populated when the trie database has it recorded.
type filteredAccount struct {
	AddressHash common.Hash     `json:"addressHash"`
	Address     *common.Address `json:"address,omitempty"`
}

// scanFilteredAccounts iterates the disk-layer snapshot's account range and
// emits one JSON line per account that passes the four predicate filters. It
// returns (matches, scanned, error). The writer is wrapped in a bufio.Writer
// and flushed both on each emission and on completion so a SIGKILL mid-scan
// still leaves the output file in a readable state.
func scanFilteredAccounts(db ethdb.Database, out io.Writer,
	codeF, nonceF, storageF, balanceF accountFilter,
) (matches, scanned uint64, err error) {
	bw := bufio.NewWriter(out)
	defer bw.Flush()
	enc := json.NewEncoder(bw)

	prefix := rawdb.SnapshotAccountPrefix
	keyLen := len(prefix) + common.HashLength

	iter := db.NewIterator(prefix, nil)
	defer iter.Release()

	var (
		start  = time.Now()
		logged = time.Now()
	)
	for iter.Next() {
		k := iter.Key()
		if len(k) != keyLen {
			continue
		}
		scanned++

		acc, derr := types.FullAccount(iter.Value())
		if derr != nil {
			return matches, scanned, fmt.Errorf("decode snapshot account: %w", derr)
		}

		hasCode := !bytes.Equal(acc.CodeHash, types.EmptyCodeHash.Bytes())
		hasStorage := acc.Root != (common.Hash{}) && acc.Root != types.EmptyRootHash
		nonzeroNonce := acc.Nonce != 0
		nonzeroBalance := acc.Balance != nil && !acc.Balance.IsZero()

		if !codeF.matches(hasCode) ||
			!nonceF.matches(nonzeroNonce) ||
			!storageF.matches(hasStorage) ||
			!balanceF.matches(nonzeroBalance) {
			if time.Since(logged) > 8*time.Second {
				log.Info("Filter accounts: scanning",
					"scanned", scanned, "matches", matches,
					"elapsed", common.PrettyDuration(time.Since(start)))
				logged = time.Now()
			}
			continue
		}

		addressHash := common.BytesToHash(k[len(prefix):])
		rec := filteredAccount{AddressHash: addressHash}
		if pre := rawdb.ReadPreimage(db, addressHash); len(pre) == common.AddressLength {
			addr := common.BytesToAddress(pre)
			rec.Address = &addr
		}
		if err := enc.Encode(rec); err != nil {
			return matches, scanned, err
		}
		if err := bw.Flush(); err != nil {
			return matches, scanned, fmt.Errorf("flush output: %w", err)
		}
		matches++

		if time.Since(logged) > 8*time.Second {
			log.Info("Filter accounts: scanning",
				"scanned", scanned, "matches", matches,
				"elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now()
		}
	}
	if err := iter.Error(); err != nil {
		return matches, scanned, err
	}
	log.Info("Filter accounts: scan finished",
		"scanned", scanned, "matches", matches,
		"elapsed", common.PrettyDuration(time.Since(start)))
	return matches, scanned, nil
}
