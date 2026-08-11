# blobpool: `Init` builds the pool unlocked while it is already reachable

Seen on `ethpandaops/geth:glamsterdam-devnet-7`
(`Geth/v1.17.6-unstable-bdf6e17f-20260803`); the code is unchanged on master
(`42c5059b5`).

```text
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x28]
github.com/ethereum/go-ethereum/core/txpool/blobpool.(*BlobPool).getByVhash(...)
	core/txpool/blobpool/blobpool.go:1303 +0x192
github.com/ethereum/go-ethereum/core/txpool/blobpool.(*Cache).update.func1()
	core/txpool/blobpool/cache.go:429 +0x1ca
created by ...blobpool.(*Cache).update in goroutine 17772
	core/txpool/blobpool/cache.go:415 +0x51e
```

## Cause

`Init` builds `p.lookup`, `p.index` and `p.store` **without holding `p.lock`**,
and the pool is already published to a reader by then:

```go
// eth/backend.go
eth.blobTxPool = blobpool.New(...)                  // store not set
eth.blobCache  = blobpool.NewCache(eth.blobTxPool)  // reader created here
eth.txPool, _  = txpool.New(..., []txpool.SubPool{legacyPool, eth.blobTxPool})
                                                    // Init runs here
```

`Cache.update` spawns a goroutine (`cache.go:415`) calling
`c.blobpool.getByVhash` (`cache.go:429`). Two ways that fails:

1. **nil store.** `Init` fills the lookup *inside* `billy.Open` (its `index`
   callback runs `parseTransaction` → `trackTransaction`) and assigns
   `p.store` only after it returns. For that window a lookup hit names a
   transaction whose store does not exist, and `blobpool.go:1303`
   (`p.store.Get`) dereferences nil. This is the crash above.

2. **concurrent map access.** The lookup is plain maps guarded by `p.lock`.
   `getByVhash` reads them under `RLock`, but the `index` callback — and
   `recheck`, `evict`, `drop` later in `Init` — write them under no lock. That
   is `fatal error: concurrent map read and map write`, which is not
   recoverable.

## Reproducing

```bash
go test ./core/txpool/blobpool/ -run 'TestGetByVhashNilStore|TestInitRaceAgainstCacheReader' -v
```

- **`TestGetByVhashNilStore`** — populates the lookup the way the `index`
  callback does, leaves the store unset, calls `getByVhash`. Faults on master.
- **`TestInitRaceAgainstCacheReader`** — seeds a store with blob transactions,
  runs the real `Init`, and concurrently calls `getByVhash` as `Cache.update`'s
  goroutine does. Nothing is stubbed. Faults on master.

## Why a benchmark harness sees it and a node does not

The window is one `billy.Open` wide, so a node that starts once rarely hits it.
A harness that restarts the client per test does: across four CI runs of a
1463-test suite (one geth start per test) the crash hit **13, 15, 17 and 62**
times, 1–4% of starts. Each one kills the client, so the harness records the
test it was about to start as failed. The failing tests differ completely
between runs — 0 tests failed in all four, 104 distinct across them — because
the crash is a property of the restart, not the test.

## Fixes

Three, of increasing depth:

1. **Do not publish the cache before `Init`** — move
   `blobpool.NewCache(eth.blobTxPool)` after `txpool.New`. One line, removes the
   only reader that exists during `Init` (`getByVhash` has exactly one caller),
   and closes both failure modes in practice.
2. **Guard `getByVhash`** — read the store under the same lock as the lookup and
   return nil when it is not set. Two lines. Fixes (1) above, but *not* the map
   race.
3. **Hold `p.lock` across `Init`.** The complete fix at pool level, and the only
   one that closes the map race. It is not a one-liner: `Init` calls
   `SetGasTip`, `convertLegacyTxs` and `convertLegacyLimbo`, all of which take
   `p.lock` themselves, so each needs splitting into a locking wrapper and an
   unlocked body.

The accompanying fix branch applies 1 and 2. `TestGetByVhashNilStore` passes
with them; `TestInitRaceAgainstCacheReader` still fails, because it calls
`getByVhash` directly and so is unaffected by the reordering — it is left in
place deliberately, as the standing demonstration that (3) is unresolved.
