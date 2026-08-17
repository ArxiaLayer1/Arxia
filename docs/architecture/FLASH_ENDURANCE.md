# Flash endurance model — T-Beam ledger storage

> **Status: theoretical model, written before the hardware bench.**
> Nothing in this document is implemented. `arxia-storage-flash` does
> not exist yet; the ESP32 target has no persistence. This model exists
> so that when the M3-6 bench runs, every observed number lands against
> a written prediction — if the field diverges from the model, we want
> to know immediately whether it is the model or the material that is
> wrong, not discover we never wrote the prediction down.

Every number below is tagged:

- **[datasheet]** — vendor specification
- **[measured]** — measured in this repository, command recorded
- **[derived]** — computed from tagged numbers, formula shown
- **[assumed]** — a choice or estimate the bench must confirm

## 1. Hardware ground truth

Target device: LilyGO TTGO T-Beam v1.1 (ESP32-DOWDQ6, SX1276 LoRa,
GPS) — the reference node of `docs/guides/HARDWARE_SETUP.md`.

| Parameter | Value | Tag |
|---|---|---|
| SPI NOR flash size | 4 MiB | [datasheet] |
| Erase sector | 4 KiB (1,024 sectors) | [datasheet] |
| Program page | 256 B | [datasheet] |
| Endurance | 100,000 P/E cycles min, per sector | [datasheet] |
| Data retention | 20 years | [datasheet] |
| Flash part | W25Q32JV-class | [assumed — read the marking off the bench unit; Winbond W25Q32JV and GigaDevice GD25Q32 both appear on v1.1 boards and both specify 100K cycles] |

Source: Winbond W25Q32JV datasheet (RevJ, 2024-12-24). NOR flash
erases to `0xFF` in 4 KiB units and programs in up to 256 B pages;
endurance is consumed by **erases**, so the whole model below reduces
to one question: *how many sector-erases per day does a transfer
workload cause?*

## 2. Write pattern per transfer

A transfer on the block-lattice is two blocks plus index maintenance.
From the ledger ingest path (`Ledger::add_block`):

| Item written | Size | Tag |
|---|---|---|
| SEND block, serialized | 193 B | [measured — protocol constant, `arxia-lattice` serialization] |
| RECEIVE block, serialized | 193 B | [measured — same] |
| `send_index` entry (add on SEND) | ~80 B | [derived — 64-hex-char hash key + destination + amount] |
| `send_index` tombstone + `consumed_sends` entry (on RECEIVE) | ~100 B | [derived] |
| Per-item storage overhead, 4 items | ~64 B | [assumed — sequential-storage item header + CRCs + word alignment, ~16 B/item; measure on bench] |

**Model constant: ~600 B of flash appends per completed transfer**
[derived]. Cross-check: the in-memory ledger retains 1,544 B per
transfer [measured — heap retention per completed transfer, HashMap
and String overhead included]; the ~2.6x gap [derived — 1,544 / 600]
is `HashMap`/`String` overhead that serialized storage does not pay,
so 600 B is consistent rather than optimistic.

An `Open` adds one 193 B block and a supply-accumulator update;
opens are rare relative to transfers and are ignored below (they only
make the numbers better).

## 3. Storage layout assumption

Two regions, because the two halves of ledger state have opposite
write behaviour:

- **Chain region** — blocks. Append-only: a block, once accepted, is
  never modified (only L2-finality pruning, planned, ever removes
  data). Modelled
  as a sequential log.
- **Hot region** — mutable state: `send_index` entries and
  tombstones, the supply accumulator, mount metadata. Small, rewritten
  constantly. Modelled as a key-value map over a few sectors.

This split is load-bearing. A single map holding everything would be
pathological for append-only data: sequential-storage's map reclaims
space by migrating every still-live item off a page before erasing it
(`map.rs`, `migrate_items`), so chain data — which never dies — would
be recopied on every wrap, and the copy cost would grow with chain
length. Append-only data goes in an append-only structure; the map
gets only the data that actually dies.

Region budget on the 4 MiB part [assumed — firmware image size to be
confirmed once `arxia-esp32` links against the storage stack]:

| Region | Size | Sectors |
|---|---|---|
| Firmware + headroom | ~1.75 MiB | — |
| Chain region | 2 MiB | 512 |
| Hot region | 64 KiB | 16 |
| Reserve (mount meta, scratch) | rest | — |

## 4. The wear model

sequential-storage advances through its flash range page by page and
erases each page exactly once per wrap — wear is uniform across the
region *by construction*, no wear-levelling table needed. So per-sector
cycles = region wraps.

For a log-structured region reclaimed by migrating live data (the map,
or the chain region once L2-finality pruning compacts it), the classic
write-amplification result applies:

```
WA = 1 / (1 - u)        u = live bytes / region bytes
```

Each wrap rewrites the live fraction `u` ahead of the erase, so raw
appends of `B` bytes/day cause `B x WA` bytes/day of physical writes:

```
sector_erases_per_day   = (B x WA) / 4096
cycles_per_sector_year  = 365 x sector_erases_per_day / sectors_in_region
lifetime_years          = 100,000 / cycles_per_sector_year
```

## 5. Predictions

Workloads [assumed — LoRa airtime caps a T-Beam mesh node well below
the top row; 10,000/day is a deliberate absurdity to bracket the
model]:

**Chain region, 2 MiB, 600 B/transfer.** The u and transfer-rate
columns are [assumed] scenario inputs; Erases/day and Lifetime are
[derived] from them via the section-4 formulas (e.g. row 1:
100 x 600 x 2 / 4096 = 29.3 erases/day; 100,000 / (365 x 29.3 / 512)
= ~4,800 years):

| Transfers/day | u (post-pruning) | WA | Erases/day | Lifetime |
|---|---|---|---|---|
| 100 | 0.5 | 2 | 29 | ~4,800 years |
| 1,000 | 0.5 | 2 | 293 | ~480 years |
| 1,000 | 0.9 | 10 | 1,465 | ~96 years |
| 10,000 | 0.9 | 10 | 14,650 | ~9.6 years |

**Hot region, 64 KiB, ~210 B/transfer of map traffic** [derived —
the two hot-path rows of section 2 (~80 + ~100 = ~180 B payload)
plus their share of the per-item overhead (2 hot writes x ~16 B =
~32 B); an earlier draft said ~150 B, which did not derive from the
tagged rows and is corrected here]. Live set is a few KiB, so
WA ~= 1. Wraps/day = rate x 210 / 65,536; lifetime =
100,000 / (365 x wraps/day) [derived]:

| Transfers/day | Wraps/day | Lifetime |
|---|---|---|
| 100 | 0.32 | ~860 years |
| 1,000 | 3.2 | ~86 years |
| 10,000 | 32 | ~8.6 years |

**Conclusion of the model: endurance is not the binding constraint at
any plausible testnet rate.** The binding constraint is **capacity**:
2 MiB / 600 B ~= 3,500 transfers [derived] before the chain region
is full and pruning must run — consistent with the earlier projection of
~2,400-7,100 transfers for the whole device [derived — same per-
transfer constants against candidate region sizes]. Pruning cadence, not wear, is what the storage
roadmap has to engineer for. Wear only becomes a design input if the
bench falsifies the model.

Secondary prediction worth pinning [derived]: at 1,000
transfers/day and u = 0.5 the model says ~3.2 wraps/day of the hot
region (so ~3.2 erases/day on each of its 16 sectors) and ~340
sector-erases/day in total (293 chain + 3.2 x 16 = 51 hot). These
are countable events.

## 6. What the bench must measure (M3-6)

Each line falsifies a tagged assumption above:

1. **Bytes appended per transfer** — instrument the flash driver;
   compare against the 600 B model constant (A: [derived] sizes,
   [assumed] overhead).
2. **Per-item overhead** — the real sequential-storage item cost on
   ESP32 word size, vs the assumed ~16 B.
3. **Sector-erase counter** — wrap the `NorFlash` implementation in a
   counting adapter and log erases per region per day. Compare against
   the table in section 5. **Divergence beyond 2x in either direction
   stops the test until attributed** — model error and hardware error
   have different fixes, and calibrating silently would defeat the
   purpose of having predictions.
4. **Flash part marking** — replace the [assumed] part-class row with
   the real chip and its datasheet.
5. **Power-loss durability** — pull the plug mid-batch, repeatedly.
   This is the layer no process-kill test can reach (see
   `arxia-storage-redb`'s documented limit: kill -9 proves
   crash-atomicity and process-death durability, not power-loss). The
   flash backend inherits the same `StorageBackend` atomicity
   contract, and the plug-pull is its kill-nine.
6. **Log length under scan** — count item reads per `scan_prefix`
   call and compare against the section-8 prediction. The term to
   watch is `n_log`, not `n_live`: it is the one that drifts with
   every overwrite until compaction, and it is the quantity the
   prediction stands or falls on.
7. **Batch write amplification** — count flash appends per
   `apply_batch` against the x2 payload prediction of section 8
   (journal + apply). The seal's cost is part of the wear model, not
   an implementation detail.

## 7. Design requirement carried forward to `arxia-storage-flash`

sequential-storage is power-fail safe **per item** (CRC-protected,
recoverable). The `StorageBackend` contract requires atomicity **per
batch** — a torn `add_block` batch is exactly the corruption the trait
documentation forbids (a `send_index` entry whose block was never
written is spendable value no chain records). `arxia-storage-flash`
therefore carries a batch seal on top of per-item safety: every
operation is journalled under a reserved key namespace, a commit
marker (carrying the operation count) is written as
the single commit point, the operations are applied, and the journal
and marker are cleared — with mount-time recovery replaying a marked
journal to completion and discarding an unmarked one. Its cut-point
sweeps live in the crate's `power_cut.rs`.

## 8. Scan and batch cost model (arxia-storage-flash)

Two costs the backend adds on top of raw appends, in the terms the
bench measures.

**Ordered scan.** The log iterates in write order; the trait promises
key order. The backend makes repeated passes, each collecting the
`SCAN_WINDOW` (= 8 [assumed], compile-time) smallest keys above the
last emitted, so a scan of `n_live` matching keys costs

```
ceil(n_live / SCAN_WINDOW) x n_log        item reads   [derived]
```

A pass that collects fewer keys than the window holds ends the scan
without another read of the log, so the formula is exact on the
dominant path; only when `n_live` is an exact multiple of
`SCAN_WINDOW` does one extra full-log pass confirm termination
[derived].

where `n_log` is the **entire log length, dead versions included** —
every overwrite of a live key grows `n_log` by one until compaction
reclaims the space. `n_live` is bounded by the working set; `n_log`
is bounded only by capacity, which is why measurement line 6 tracks
it directly. The realistic access pattern is one account chain under
its own prefix (tens of keys, one or two passes); a whole-store scan
is a conformance exercise, not a node operation [assumed — the bench
confirms the access pattern].

**Batch seal.** Every batched operation is written twice — once into
the journal, once applied — plus one marker item per batch:

```
appends(batch of k ops) = 2k + 1          items        [derived]
```

so a batch costs twice its payload in flash appends, and the
section-5 erase predictions for batch-heavy scenarios scale
accordingly. The journal and marker items are themselves reclaimed
by compaction like any other overwritten item.

**Recovery cost.** On the clean path a batch performs no RECOVERY
scans: a RAM health cell (three states - clean, pre-commit debris,
committed-pending) records what the journal may hold, set at mount and
after every successful batch [derived]. Only after an actual failure
does the next operation scan the log to finish or discard the
interrupted batch, which costs one full-log read - `n_log` item reads
- per recovery attempt [derived]. Mount always runs one such scan.

**Apply cost on the current happy path - what the bench WILL see.**
The successful batch does not, today, apply from the operations it
holds in RAM: after the marker lands it re-reads each of its `k`
journal entries from flash and applies from those, then removes each
entry - one point lookup plus one `remove_item` per operation, and
each of those is a log search (`remove_item` in particular walks the
log; the engine's own documentation flags it as slow). Steady-state
batch cost is therefore `2k + 1` appends PLUS on the order of `2k`
log searches [derived from the code as written]. This is not drift and
must not be attributed to the hardware: it is the current
implementation, and a follow-up issue replaces it by applying from the
validated in-RAM slice with the same erase-as-you-go capacity profile,
which removes the `k` re-reads and leaves the `k` removes. The bench
compares against THIS paragraph until that issue lands, then against
the revised figure.
