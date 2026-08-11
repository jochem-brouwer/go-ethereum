package blobpool

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/billy"
	"github.com/holiman/uint256"
)

// Init's billy.Open index callback tracks every stored transaction into
// p.lookup, but p.store is only assigned once billy.Open returns. For that
// window a lookup hit names a transaction the store cannot serve, and
// getByVhash dereferences a nil store. Cache.update reaches it because
// eth/backend.go builds the cache before txpool.New runs Init.
//
//	panic: runtime error: invalid memory address or nil pointer dereference
//	blobpool.(*BlobPool).getByVhash(...)  blobpool.go:1303
//	blobpool.(*Cache).update.func1()      cache.go:429

// TestGetByVhashNilStore covers the state directly: lookup populated, store not.
func TestGetByVhashNilStore(t *testing.T) {
	p := &BlobPool{lookup: newLookup()}

	vhash := common.HexToHash("0x01deadbeef")
	custody := types.CustodyBitmap{}
	p.lookup.track(&blobTxMeta{
		hash:    common.HexToHash("0xc0ffee"),
		vhashes: []common.Hash{vhash},
		id:      1,
		custody: &custody,
	})
	if _, exists := p.lookup.storeidOfBlob(vhash); !exists {
		t.Fatal("lookup must report the blob, else getByVhash returns early")
	}
	if got := p.getByVhash(vhash); got != nil {
		t.Fatalf("expected nil for an unavailable store, got %v", got)
	}
}

// TestInitRaceAgainstCacheReader runs the real Init while a goroutine does what
// Cache.update's goroutine does.
func TestInitRaceAgainstCacheReader(t *testing.T) {
	const (
		rounds = 8
		txs    = 200 // more stored txs widens billy.Open, and the window
	)
	var (
		crashes int
		reached atomic.Int64
		mu      sync.Mutex
	)
	for range rounds {
		storage := t.TempDir()

		os.MkdirAll(filepath.Join(storage, pendingTransactionStore), 0700)
		store, err := billy.Open(
			billy.Options{Path: filepath.Join(storage, pendingTransactionStore)},
			newSlotterEIP7594(testMaxBlobsPerBlock), nil)
		if err != nil {
			t.Fatalf("opening seed store: %v", err)
		}
		key, _ := crypto.GenerateKey()
		var vhashes []common.Hash
		for nonce := range uint64(txs) {
			tx := makeTx(nonce, 1, 1, 1, key)
			store.Put(encodeForPool(tx))
			vhashes = append(vhashes, tx.BlobHashes()...)
		}
		store.Close()

		statedb, _ := state.New(types.EmptyRootHash,
			state.NewDatabase(triedb.NewDatabase(nil, nil), nil))
		statedb.AddBalance(crypto.PubkeyToAddress(key.PublicKey),
			uint256.NewInt(1000000000), tracing.BalanceChangeUnspecified)
		statedb.Commit(0, true, false)

		chain := &testBlockChain{
			config:  params.MainnetChainConfig,
			basefee: uint256.NewInt(params.InitialBaseFee),
			blobfee: uint256.NewInt(params.BlobTxMinBlobGasprice),
			statedb: statedb,
		}
		pool := New(Config{Datadir: storage}, chain, nil)

		var (
			wg   sync.WaitGroup
			stop = make(chan struct{})
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					mu.Lock()
					crashes++
					mu.Unlock()
				}
			}()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, vh := range vhashes {
					if pool.getByVhash(vh) != nil {
						reached.Add(1)
					}
				}
			}
		}()

		if err := pool.Init(1, chain.CurrentBlock(), newReserver()); err != nil {
			t.Fatalf("init: %v", err)
		}
		close(stop)
		wg.Wait()
		pool.Close()
	}

	t.Logf("rounds=%d blobs served during Init=%d crashes=%d",
		rounds, reached.Load(), crashes)
	if crashes != 0 {
		t.Fatalf("getByVhash faulted %d times during Init", crashes)
	}
}
