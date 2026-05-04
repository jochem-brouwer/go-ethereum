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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/internal/era"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/urfave/cli/v2"
)

// Pre-Spurious Dragon (EIP-161), CREATE could leave a contract with nonce 0,
// no code, but non-empty storage if the init code wrote storage and returned
// empty deployment bytecode. EIP-161 changed CREATE to bump the new contract's
// nonce to 1 and made empty-account touching delete the account, so no such
// account can be created post-fork. CREATE2 was introduced in Constantinople,
// long after Spurious Dragon, so it is irrelevant here but checked anyway.

// createCollector implements vm.EVMLogger and accumulates the addresses of
// contracts created during chain replay. v1.13's tracer interface fires
// CaptureStart for the top-level frame (with create=true for tx-creates)
// and CaptureEnter for sub-calls (with typ=CREATE/CREATE2 for opcode-level
// creates), so the two hooks together capture every contract creation.
type createCollector struct {
	creations map[common.Address]struct{}
}

func newCreateCollector() *createCollector {
	return &createCollector{creations: make(map[common.Address]struct{})}
}

func (c *createCollector) CaptureTxStart(uint64) {}
func (c *createCollector) CaptureTxEnd(uint64)   {}

func (c *createCollector) CaptureStart(env *vm.EVM, from, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	if create {
		c.creations[to] = struct{}{}
	}
}
func (c *createCollector) CaptureEnd([]byte, uint64, error) {}

func (c *createCollector) CaptureEnter(typ vm.OpCode, from, to common.Address, input []byte, gas uint64, value *big.Int) {
	if typ == vm.CREATE || typ == vm.CREATE2 {
		c.creations[to] = struct{}{}
	}
}
func (c *createCollector) CaptureExit([]byte, uint64, error) {}

func (c *createCollector) CaptureState(uint64, vm.OpCode, uint64, uint64, *vm.ScopeContext, []byte, int, error) {
}
func (c *createCollector) CaptureFault(uint64, vm.OpCode, uint64, uint64, *vm.ScopeContext, int, error) {
}

// zeroNonceSlot describes one storage slot of a matching account. KeyHash is
// always set (it is the on-disk trie key); Key is the preimage and is only
// populated when known: always for the replay scanner (preimage caching is
// enabled and the trie commit records every slot key) and opportunistically
// for the snapshot scanner (when geth has the preimage on disk).
type zeroNonceSlot struct {
	Key     *common.Hash `json:"key,omitempty"`
	KeyHash common.Hash  `json:"keyHash"`
}

// zeroNonceMatch is one record in the JSON Lines output stream. Address is
// only populated when the preimage is known: always for the replay scanner
// (we observe the address before it is hashed), and opportunistically for
// the snapshot scanner (when geth has the preimage on disk).
type zeroNonceMatch struct {
	Address     *common.Address `json:"address,omitempty"`
	AddressHash common.Hash     `json:"addressHash"`
	Balance     *hexutil.Big    `json:"balance"`
	CodeHash    common.Hash     `json:"codeHash"`
	StorageRoot common.Hash     `json:"storageRoot"`
	Storage     []zeroNonceSlot `json:"storage,omitempty"`
}

// inspectCreations walks the tracked create-set and emits any account whose
// post-state at `stateRoot` has nonce==0, empty code, and non-empty storage.
// For each match the storage trie is iterated to enumerate slot keys, and
// each slot's preimage is resolved via the trie database (which the secure-
// trie commit populates whenever CacheConfig.Preimages is enabled). Accounts
// that were SELFDESTRUCT-ed before the boundary are silently skipped — pre-
// EIP-6780 SELFDESTRUCT clears storage, so they neither exist nor have storage.
func inspectCreations(statedb *state.StateDB, tdb *triedb.Database, stateRoot common.Hash, collector *createCollector, out io.Writer) (int, error) {
	enc := json.NewEncoder(out)
	matches := 0
	for addr := range collector.creations {
		if !statedb.Exist(addr) {
			continue
		}
		if statedb.GetNonce(addr) != 0 {
			continue
		}
		codeHash := statedb.GetCodeHash(addr)
		if codeHash != types.EmptyCodeHash {
			continue
		}
		storageRoot := statedb.GetStorageRoot(addr)
		if storageRoot == (common.Hash{}) || storageRoot == types.EmptyRootHash {
			continue
		}
		addrCopy := addr
		addrHash := crypto.Keccak256Hash(addr.Bytes())
		match := zeroNonceMatch{
			Address:     &addrCopy,
			AddressHash: addrHash,
			Balance:     (*hexutil.Big)(statedb.GetBalance(addr).ToBig()),
			CodeHash:    codeHash,
			StorageRoot: storageRoot,
		}
		st, err := trie.NewStateTrie(trie.StorageTrieID(stateRoot, addrHash, storageRoot), tdb)
		if err != nil {
			return matches, fmt.Errorf("open storage trie for %s: %w", addr.Hex(), err)
		}
		nodeIt, err := st.NodeIterator(nil)
		if err != nil {
			return matches, fmt.Errorf("storage iterator for %s: %w", addr.Hex(), err)
		}
		var slots []zeroNonceSlot
		leafIt := trie.NewIterator(nodeIt)
		for leafIt.Next() {
			slotHash := common.BytesToHash(leafIt.Key)
			slot := zeroNonceSlot{KeyHash: slotHash}
			if pre := tdb.Preimage(slotHash); len(pre) == common.HashLength {
				key := common.BytesToHash(pre)
				slot.Key = &key
			}
			slots = append(slots, slot)
		}
		if leafIt.Err != nil {
			return matches, fmt.Errorf("walk storage trie for %s: %w", addr.Hex(), leafIt.Err)
		}
		sort.Slice(slots, func(i, j int) bool {
			return bytes.Compare(slots[i].KeyHash[:], slots[j].KeyHash[:]) < 0
		})
		match.Storage = slots
		if err := enc.Encode(match); err != nil {
			return matches, err
		}
		matches++
	}
	return matches, nil
}

// findZeroNonceReplay replays an Era1 archive of the chain through the
// EIP-158 (Spurious Dragon) activation block. Every contract creation is
// recorded by address, and once the boundary block is committed the post-
// state is inspected for the zero-nonce, empty-code, non-empty-storage
// condition.
//
// CacheConfig.Preimages is forced on so the secure-trie commit records each
// storage slot key as a preimage; we look these up after replay to emit the
// raw slot keys in addition to their on-disk hashes.
func findZeroNonceReplay(ctx *cli.Context) error {
	if ctx.Args().Len() != 1 {
		utils.Fatalf("usage: geth snapshot find-zero-nonce-replay <era-dir>")
	}
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chainDb := utils.MakeChainDatabase(ctx, stack, false)
	defer chainDb.Close()

	gspec := utils.MakeGenesis(ctx)
	chainConfig, err := core.LoadChainConfig(chainDb, gspec)
	if err != nil {
		return err
	}
	if chainConfig.EIP158Block == nil {
		return errors.New("chain config has no EIP-158 activation block; nothing to do")
	}
	target := chainConfig.EIP158Block.Uint64()

	engine, err := ethconfig.CreateConsensusEngine(chainConfig, chainDb)
	if err != nil {
		return err
	}
	scheme, err := rawdb.ParseStateScheme(ctx.String(utils.StateSchemeFlag.Name), chainDb)
	if err != nil {
		return err
	}

	collector := newCreateCollector()
	cache := &core.CacheConfig{
		TrieCleanLimit: ethconfig.Defaults.TrieCleanCache,
		TrieDirtyLimit: ethconfig.Defaults.TrieDirtyCache,
		TrieTimeLimit:  ethconfig.Defaults.TrieTimeout,
		SnapshotLimit:  0,
		Preimages:      true,
		StateScheme:    scheme,
	}
	vmcfg := vm.Config{Tracer: collector}

	chain, err := core.NewBlockChain(chainDb, cache, gspec, nil, engine, vmcfg, nil, nil)
	if err != nil {
		return fmt.Errorf("create blockchain: %w", err)
	}
	defer chain.Stop()

	dir := ctx.Args().Get(0)
	network, err := detectEraNetwork(ctx, dir)
	if err != nil {
		return err
	}
	log.Info("Replaying era archives", "dir", dir, "network", network, "target", target)
	if err := replayEraToBlock(chain, dir, network, target); err != nil {
		return err
	}

	header := chain.GetHeaderByNumber(target)
	if header == nil {
		return fmt.Errorf("target block %d missing from chain after replay", target)
	}
	statedb, err := chain.StateAt(header.Root)
	if err != nil {
		return fmt.Errorf("open state at block %d (root %x): %w", target, header.Root, err)
	}
	matches, err := inspectCreations(statedb, chain.TrieDB(), header.Root, collector, os.Stdout)
	if err != nil {
		return err
	}
	log.Info("Zero-nonce replay scan complete",
		"block", target, "tracked", len(collector.creations), "matches", matches)
	return nil
}

// detectEraNetwork mirrors importHistory's network resolution: prefer an
// explicit network flag, otherwise auto-detect by scanning the directory.
func detectEraNetwork(ctx *cli.Context, dir string) (string, error) {
	if utils.IsNetworkPreset(ctx) {
		switch {
		case ctx.Bool(utils.MainnetFlag.Name):
			return "mainnet", nil
		case ctx.Bool(utils.SepoliaFlag.Name):
			return "sepolia", nil
		case ctx.Bool(utils.HoleskyFlag.Name):
			return "holesky", nil
		}
	}
	var found []string
	for _, n := range params.NetworkNames {
		entries, err := era.ReadDir(dir, n)
		if err != nil {
			return "", fmt.Errorf("read era dir %s: %w", dir, err)
		}
		if len(entries) > 0 {
			found = append(found, n)
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("no era archives found in %s", dir)
	case 1:
		return found[0], nil
	default:
		return "", errors.New("multiple networks present in era dir; pass a network flag")
	}
}

// replayEraToBlock streams blocks out of the era archives in `dir` and feeds
// them through chain.InsertChain (executing them, unlike utils.ImportHistory
// which uses InsertReceiptChain). Replay halts once the chain head reaches
// `target`. Checksums are verified against checksums.txt so the caller gets
// the same integrity guarantees as `geth import-history`.
func replayEraToBlock(chain *core.BlockChain, dir, network string, target uint64) error {
	if chain.CurrentSnapBlock().Number.BitLen() != 0 {
		return errors.New("replay only supported when starting from genesis; clear --datadir first")
	}
	entries, err := era.ReadDir(dir, network)
	if err != nil {
		return fmt.Errorf("read era dir: %w", err)
	}
	checksums, err := readEraChecksums(path.Join(dir, "checksums.txt"))
	if err != nil {
		return fmt.Errorf("read checksums.txt: %w", err)
	}
	if len(checksums) != len(entries) {
		return fmt.Errorf("checksums (%d) and entries (%d) count mismatch", len(checksums), len(entries))
	}

	const batchSize = 2500
	var (
		start    = time.Now()
		reported = time.Now()
		imported = 0
		hasher   = sha256.New()
		hbuf     = bytes.NewBuffer(nil)
	)

	for i, filename := range entries {
		stop, err := func() (bool, error) {
			f, err := os.Open(path.Join(dir, filename))
			if err != nil {
				return false, fmt.Errorf("open %s: %w", filename, err)
			}
			defer f.Close()

			if _, err := io.Copy(hasher, f); err != nil {
				return false, fmt.Errorf("checksum %s: %w", filename, err)
			}
			got := common.BytesToHash(hasher.Sum(hbuf.Bytes()[:])).Hex()
			hasher.Reset()
			hbuf.Reset()
			if got != checksums[i] {
				return false, fmt.Errorf("%s checksum mismatch: got %s want %s", filename, got, checksums[i])
			}

			e, err := era.From(f)
			if err != nil {
				return false, fmt.Errorf("open era %s: %w", filename, err)
			}
			it, err := era.NewIterator(e)
			if err != nil {
				return false, fmt.Errorf("create era iterator: %w", err)
			}

			batch := make([]*types.Block, 0, batchSize)
			flush := func() error {
				if len(batch) == 0 {
					return nil
				}
				if _, err := chain.InsertChain(batch); err != nil {
					return fmt.Errorf("insert blocks %d..%d: %w",
						batch[0].NumberU64(), batch[len(batch)-1].NumberU64(), err)
				}
				imported += len(batch)
				if time.Since(reported) >= 8*time.Second {
					log.Info("Replaying era files",
						"head", batch[len(batch)-1].NumberU64(),
						"imported", imported,
						"elapsed", common.PrettyDuration(time.Since(start)))
					reported = time.Now()
				}
				batch = batch[:0]
				return nil
			}

			for it.Next() {
				block, err := it.Block()
				if err != nil {
					return false, fmt.Errorf("read block %d: %w", it.Number(), err)
				}
				if block.NumberU64() == 0 {
					continue
				}
				if block.NumberU64() > target {
					if err := flush(); err != nil {
						return false, err
					}
					return true, nil
				}
				batch = append(batch, block)
				if len(batch) >= batchSize {
					if err := flush(); err != nil {
						return false, err
					}
				}
			}
			return false, flush()
		}()
		if err != nil {
			return err
		}
		if stop {
			break
		}
	}

	head := chain.CurrentBlock().Number.Uint64()
	if head < target {
		return fmt.Errorf("era archives exhausted before reaching target block %d (head: %d)", target, head)
	}
	return nil
}

// readEraChecksums reads a checksums.txt file (one hex-encoded sha256 per
// line) and returns the entries in the order written.
func readEraChecksums(p string) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		if line := s.Text(); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, s.Err()
}

// findZeroNonce iterates the on-disk snapshot at the given root (defaulting
// to the chain head) and emits every account whose stored value matches the
// zero-nonce, empty-code, non-empty-storage condition. Account preimages are
// emitted when present in the geth preimage table; storage slot preimages
// are similarly emitted when available.
func findZeroNonce(ctx *cli.Context) error {
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	db := utils.MakeChainDatabase(ctx, stack, true)
	defer db.Close()

	tdb := utils.MakeTrieDatabase(ctx, db, false, true, false)
	defer tdb.Close()

	if ctx.NArg() > 1 {
		return errors.New("too many arguments")
	}
	var (
		root common.Hash
		err  error
	)
	if ctx.NArg() == 1 {
		root, err = parseRoot(ctx.Args().First())
		if err != nil {
			return err
		}
	} else {
		head := rawdb.ReadHeadBlock(db)
		if head == nil {
			return errors.New("no head block in database")
		}
		root = head.Root()
	}

	snapConfig := snapshot.Config{
		CacheSize:  256,
		Recovery:   false,
		NoBuild:    true,
		AsyncBuild: false,
	}
	snaptree, err := snapshot.New(snapConfig, db, tdb, root)
	if err != nil {
		return err
	}
	accIt, err := snaptree.AccountIterator(root, common.Hash{})
	if err != nil {
		return err
	}
	defer accIt.Release()

	enc := json.NewEncoder(os.Stdout)
	var (
		scanned uint64
		matches uint64
		start   = time.Now()
		logged  = time.Now()
	)
	log.Info("Zero-nonce snapshot scan started", "root", root)
	for accIt.Next() {
		scanned++
		account, err := types.FullAccount(accIt.Account())
		if err != nil {
			return err
		}
		if account.Nonce != 0 {
			continue
		}
		if !bytes.Equal(account.CodeHash, types.EmptyCodeHash.Bytes()) {
			continue
		}
		if account.Root == (common.Hash{}) || account.Root == types.EmptyRootHash {
			continue
		}
		match := zeroNonceMatch{
			AddressHash: accIt.Hash(),
			Balance:     (*hexutil.Big)(account.Balance.ToBig()),
			CodeHash:    common.BytesToHash(account.CodeHash),
			StorageRoot: account.Root,
		}
		if pre := rawdb.ReadPreimage(db, accIt.Hash()); len(pre) == common.AddressLength {
			addr := common.BytesToAddress(pre)
			match.Address = &addr
		}
		stIt, err := snaptree.StorageIterator(root, accIt.Hash(), common.Hash{})
		if err != nil {
			return fmt.Errorf("open storage iterator for %s: %w", accIt.Hash().Hex(), err)
		}
		for stIt.Next() {
			slotHash := stIt.Hash()
			slot := zeroNonceSlot{KeyHash: slotHash}
			if pre := rawdb.ReadPreimage(db, slotHash); len(pre) == common.HashLength {
				key := common.BytesToHash(pre)
				slot.Key = &key
			}
			match.Storage = append(match.Storage, slot)
		}
		stIt.Release()
		if err := enc.Encode(match); err != nil {
			return err
		}
		matches++
		if time.Since(logged) > 8*time.Second {
			log.Info("Zero-nonce snapshot scan in progress",
				"scanned", scanned, "matches", matches, "elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now()
		}
	}
	log.Info("Zero-nonce snapshot scan complete",
		"scanned", scanned, "matches", matches, "elapsed", common.PrettyDuration(time.Since(start)))
	return nil
}
