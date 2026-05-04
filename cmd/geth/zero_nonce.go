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
	"os"
	"path"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/era"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/urfave/cli/v2"
)

// Pre-Spurious Dragon (EIP-161), CREATE could leave a contract with nonce 0,
// no code, but non-empty storage if the init code wrote storage and returned
// empty deployment bytecode. EIP-161 changed CREATE to bump the new contract's
// nonce to 1 and made empty-account touching delete the account, so no such
// account can be created post-fork. Once the chain has crossed Spurious Dragon,
// these contracts are stable in the state — they have no code, and SELFDESTRUCT
// can only be invoked by code running in the contract's own context, so they
// can never delete themselves. (Pre-EIP-6780 SELFDESTRUCT *would* have wiped
// them, but reaching it requires code, and matching contracts have none.)
//
// We exploit this stability: rather than tracing every CREATE during replay,
// we just replay the chain through the EIP-158 boundary, build a snapshot at
// that block, and walk the snapshot directly. The snapshot's flat layout
// makes a full pass cheap, and CacheConfig.Preimages=true ensures the trie
// commit populates account- and storage-key preimages in the trie database
// for reverse lookup at emission time.

// zeroNonceSlot describes one storage slot of a matching account. KeyHash is
// always set (it is the on-disk trie key); Key is the preimage and is only
// populated when the trie database has it (which it does for everything written
// during a replay run, since we run with Preimages=true).
type zeroNonceSlot struct {
	Key     *common.Hash `json:"key,omitempty"`
	KeyHash common.Hash  `json:"keyHash"`
}

// zeroNonceMatch is one record in the JSON Lines output stream. Address is
// only populated when the preimage is on disk: always for the replay scanner
// (preimages are recorded for every address modified during replay), and
// opportunistically for the standalone snapshot scanner.
type zeroNonceMatch struct {
	Address     *common.Address `json:"address,omitempty"`
	AddressHash common.Hash     `json:"addressHash"`
	Balance     *hexutil.Big    `json:"balance"`
	CodeHash    common.Hash     `json:"codeHash"`
	StorageRoot common.Hash     `json:"storageRoot"`
	Storage     []zeroNonceSlot `json:"storage,omitempty"`
}

// zeroNonceMatchesFlag controls where matches are persisted. The file is
// opened in append mode and a dedupe set is built from its existing contents
// at startup, so both find-zero-nonce-replay and find-zero-nonce can be
// invoked repeatedly against the same datadir without producing duplicates.
var zeroNonceMatchesFlag = &cli.StringFlag{
	Name:  "zero-nonce.matches",
	Value: "zero-nonce-matches.jsonl",
	Usage: "Path to JSON-Lines file matches are appended to (idempotent across re-runs)",
}

// findZeroNonceReplay replays an Era1 archive of the chain through the
// EIP-158 (Spurious Dragon) activation block, builds a snapshot at the
// boundary root, then walks the snapshot's flat key layout to find every
// account matching the zero-nonce / empty-code / non-empty-storage condition.
//
// Replay starts from chain.CurrentBlock()+1, so a previously crashed run
// can be resumed by re-invoking the same command — block bodies, receipts,
// and state are all persisted by InsertChain. The snapshot is built only
// once at the end (CacheConfig.SnapshotLimit=0 during replay) so replay
// itself stays fast.
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

	cache := &core.CacheConfig{
		TrieCleanLimit: ethconfig.Defaults.TrieCleanCache,
		TrieDirtyLimit: ethconfig.Defaults.TrieDirtyCache,
		TrieTimeLimit:  ethconfig.Defaults.TrieTimeout,
		SnapshotLimit:  0,
		Preimages:      true,
		StateScheme:    scheme,
		// Force archive-mode commits so every block's state lands on disk before
		// InsertChain returns. This trades some replay speed and chaindata size
		// for crash safety: with the default buffered mode, triedb.Commit only
		// fires after gcproc accumulates beyond TrieTimeout (60 min), so a
		// non-graceful exit (panic, SIGKILL, OOM) can leave the most recent
		// hours of work as in-memory dirty nodes that vanish on crash. The
		// repair on next startup then has to walk back to whatever Cap last
		// evicted, which is expensive on leveldb. Forcing per-block commits
		// makes restart-from-where-we-left-off truly cheap.
		TrieDirtyDisabled: true,
	}
	chain, err := core.NewBlockChain(chainDb, cache, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		return fmt.Errorf("create blockchain: %w", err)
	}
	defer chain.Stop()

	dir := ctx.Args().Get(0)
	network, err := detectEraNetwork(ctx, dir)
	if err != nil {
		return err
	}

	headNum := chain.CurrentBlock().Number.Uint64()
	log.Info("Zero-nonce replay starting",
		"era", dir, "network", network, "target", target, "chainHead", headNum)

	if headNum < target {
		if err := replayEraToBlock(chain, dir, network, target, headNum); err != nil {
			return err
		}
	} else {
		log.Info("Chain already past target, skipping replay", "head", headNum)
	}

	boundaryHeader := chain.GetHeaderByNumber(target)
	if boundaryHeader == nil {
		return fmt.Errorf("boundary block %d missing after replay", target)
	}
	boundaryRoot := boundaryHeader.Root

	log.Info("Building snapshot at boundary block (synchronous)",
		"block", target, "root", boundaryRoot)
	snapConfig := snapshot.Config{
		CacheSize:  256,
		Recovery:   false,
		NoBuild:    false,
		AsyncBuild: false,
	}
	if _, err := snapshot.New(snapConfig, chainDb, chain.TrieDB(), boundaryRoot); err != nil {
		return fmt.Errorf("build snapshot: %w", err)
	}
	log.Info("Snapshot ready, scanning for matches", "root", boundaryRoot)

	matchesPath := ctx.String(zeroNonceMatchesFlag.Name)
	return runSnapshotScan(chainDb, matchesPath)
}

// findZeroNonce walks the existing snapshot of an open datadir and emits
// every account matching the zero-nonce / empty-code / non-empty-storage
// condition. The optional <root> argument is accepted for compatibility but
// ignored — the disk-layer snapshot is keyed by keccak256(address) regardless
// of which state root it represents, and a node only ever has one disk-layer
// snapshot at a time.
func findZeroNonce(ctx *cli.Context) error {
	if ctx.NArg() > 1 {
		return errors.New("too many arguments")
	}
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	db := utils.MakeChainDatabase(ctx, stack, true)
	defer db.Close()

	if root := rawdb.ReadSnapshotRoot(db); root == (common.Hash{}) {
		return errors.New("no snapshot present in this datadir; run snap sync or find-zero-nonce-replay first")
	} else {
		log.Info("Scanning existing snapshot", "root", root)
	}
	matchesPath := ctx.String(zeroNonceMatchesFlag.Name)
	return runSnapshotScan(db, matchesPath)
}

// runSnapshotScan opens the matches file, prepares the dedupe set from its
// existing contents, and invokes scanSnapshot. Shared by both subcommands.
func runSnapshotScan(db ethdb.Database, matchesPath string) error {
	emitted, err := readEmittedMatches(matchesPath)
	if err != nil {
		return fmt.Errorf("read existing matches %s: %w", matchesPath, err)
	}
	matchesFile, err := os.OpenFile(matchesPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open matches file %s: %w", matchesPath, err)
	}
	defer matchesFile.Close()

	log.Info("Snapshot scan starting", "matchesFile", matchesPath, "alreadyEmitted", len(emitted))
	matches, err := scanSnapshot(db, matchesFile, emitted)
	if err != nil {
		return err
	}
	log.Info("Snapshot scan complete", "newMatches", matches, "totalEmitted", len(emitted))
	return nil
}

// scanSnapshot iterates the disk-layer snapshot (SnapshotAccountPrefix range)
// and emits accounts matching the zero-nonce / empty-code / non-empty-storage
// condition. For each match the storage trie's flat snapshot is walked to
// enumerate slot keys (SnapshotStoragePrefix range, scoped to the account),
// and address + slot preimages are looked up in the trie database's preimage
// table. Already-emitted addresses (per the `emitted` set) are skipped.
//
// The direct prefix iteration deliberately bypasses snapshot.Tree's diff-layer
// machinery because at this point only the disk-layer state matters and key
// length filtering is enough to avoid stray entries.
func scanSnapshot(db ethdb.Database, out io.Writer, emitted map[common.Address]struct{}) (int, error) {
	// Wrap the writer once so json.Encoder buffers between encodings; we
	// flush after each emitted match so a crash mid-scan still leaves the
	// matches file in a recoverable state.
	buf := bufio.NewWriter(out)
	enc := json.NewEncoder(buf)

	accountPrefix := rawdb.SnapshotAccountPrefix
	accountKeyLen := len(accountPrefix) + common.HashLength

	iter := db.NewIterator(accountPrefix, nil)
	defer iter.Release()

	var (
		scanned uint64
		matches int
		start   = time.Now()
		logged  = time.Now()
	)
	for iter.Next() {
		if k := iter.Key(); len(k) != accountKeyLen {
			continue
		}
		scanned++

		accountHash := common.BytesToHash(iter.Key()[len(accountPrefix):])

		full, err := types.FullAccount(iter.Value())
		if err != nil {
			return matches, fmt.Errorf("decode snapshot account %s: %w", accountHash.Hex(), err)
		}
		if full.Nonce != 0 {
			continue
		}
		if !bytes.Equal(full.CodeHash, types.EmptyCodeHash.Bytes()) {
			continue
		}
		if full.Root == (common.Hash{}) || full.Root == types.EmptyRootHash {
			continue
		}

		match := zeroNonceMatch{
			AddressHash: accountHash,
			Balance:     (*hexutil.Big)(full.Balance.ToBig()),
			CodeHash:    common.BytesToHash(full.CodeHash),
			StorageRoot: full.Root,
		}
		if pre := rawdb.ReadPreimage(db, accountHash); len(pre) == common.AddressLength {
			addr := common.BytesToAddress(pre)
			if _, dup := emitted[addr]; dup {
				continue
			}
			match.Address = &addr
		}

		// Walk the account's storage snapshot range to enumerate slot keys.
		stIter := rawdb.IterateStorageSnapshots(db, accountHash)
		for stIter.Next() {
			key := stIter.Key()
			// Key layout: SnapshotStoragePrefix(1) || accountHash(32) || slotHash(32)
			slotHash := common.BytesToHash(key[len(rawdb.SnapshotStoragePrefix)+common.HashLength:])
			slot := zeroNonceSlot{KeyHash: slotHash}
			if pre := rawdb.ReadPreimage(db, slotHash); len(pre) == common.HashLength {
				k := common.BytesToHash(pre)
				slot.Key = &k
			}
			match.Storage = append(match.Storage, slot)
		}
		stIter.Release()

		if err := enc.Encode(match); err != nil {
			return matches, err
		}
		if err := buf.Flush(); err != nil {
			return matches, fmt.Errorf("flush matches: %w", err)
		}
		matches++
		if match.Address != nil {
			emitted[*match.Address] = struct{}{}
		}

		if time.Since(logged) > 8*time.Second {
			log.Info("Scanning snapshot",
				"scanned", scanned, "matches", matches, "elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now()
		}
	}
	if err := iter.Error(); err != nil {
		return matches, err
	}
	if err := buf.Flush(); err != nil {
		return matches, fmt.Errorf("flush matches: %w", err)
	}
	log.Info("Snapshot scan finished",
		"scanned", scanned, "newMatches", matches, "elapsed", common.PrettyDuration(time.Since(start)))
	return matches, nil
}

// readEmittedMatches scans an existing matches file (JSON-Lines) and returns
// the set of addresses already written. Missing file → empty set. Malformed
// individual lines are skipped (with a warning) rather than aborting, so a
// truncated final line from a previous crash doesn't block restart.
func readEmittedMatches(p string) (map[common.Address]struct{}, error) {
	out := make(map[common.Address]struct{})
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	skipped := 0
	for s.Scan() {
		line := bytes.TrimSpace(s.Bytes())
		if len(line) == 0 {
			continue
		}
		var m zeroNonceMatch
		if err := json.Unmarshal(line, &m); err != nil {
			skipped++
			continue
		}
		if m.Address != nil {
			out[*m.Address] = struct{}{}
		}
	}
	if skipped > 0 {
		log.Warn("Skipped malformed lines in matches file", "file", p, "lines", skipped)
	}
	return out, s.Err()
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
// which uses InsertReceiptChain). Replay starts from `resumeFrom + 1` and
// halts after the block at `target` is committed. Blocks are inserted in
// batches for performance; matches are emitted later from the snapshot scan,
// so there is no longer any need to break batches on block boundaries.
func replayEraToBlock(chain *core.BlockChain, dir, network string, target, resumeFrom uint64) error {
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
		imported = uint64(0)
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
				imported += uint64(len(batch))
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
				num := block.NumberU64()
				if num == 0 || num <= resumeFrom {
					continue
				}
				if num > target {
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
