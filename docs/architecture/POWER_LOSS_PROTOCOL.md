# Power-loss protocol — the plug-pull bench for `arxia-storage-flash`

Written before any hardware execution, deliberately: the procedure
and the failure criteria are fixed first, so a surprising result
cannot be reclassified after the fact. This is the hardware half of
the batch-seal guarantee. The software half — every cut point across
a batch and across recovery leaving all-or-nothing — is proved by the
sweeps in `crates/arxia-storage-flash/tests/power_cut.rs`; what no
host test can reach is the physical layer those sweeps idealise: the
flash chip's own write buffers, voltage droop during an erase, and
firmware death at an arbitrary instruction. The plug-pull is to the
flash backend what kill-nine is to the redb backend, one layer lower.

## Test article

- LilyGO T-Beam v1.1 (ESP32-DOWDQ6, 4 MiB SPI NOR flash), powered
  over a supply that can be cut externally — not by firmware, not by
  the reset button. Cutting USB power at the hub or supply rail
  qualifies; pressing reset does not (it is a processor reset, not a
  power loss, and leaves the flash chip powered).
- Bench firmware: mounts `FlashStorage` on a dedicated flash region,
  then loops forever applying batches shaped like real transfers
  (two 193-byte blocks under chain keys plus an index entry — the
  same shape as the conformance fixture), each batch tagged with a
  monotonically increasing sequence number **that the firmware
  itself embeds inside every value it writes**. Batch keys rotate
  over a bounded window of slots (`slot = seq % SLOTS`) while the
  tags keep increasing: per-sequence keys would fill the region in
  minutes and then stop exercising anything, while a bounded live
  set keeps the log wrapping and reclaiming indefinitely — the wear
  traffic the endurance model prices. A slot overwrite is one
  batch, so the seal makes it atomic: after any cut a slot is
  wholly on its old sequence or wholly on its new one, and a mixed
  slot is precisely the partial-batch failure below. The store provides
  no sequence facility — its commit marker carries only an
  operation count and is gone once a batch lands — so every
  sequence number this protocol mentions, including the audit
  criteria below, is the firmware's own tag, recovered by parsing
  the values it wrote. A bench built without those tags cannot run
  this protocol.

  **This protocol is code**: `crates/arxia-flash-bench` implements
  the tagged batch, the boot-time audit, the failure criteria as an
  enum, and the boot decision, generic over the flash driver and the
  serial sink; it is tested on a host against the same
  fault-injecting mock the backend uses, and compiled for the
  bare-metal target by CI. The board firmware is a thin adapter that
  supplies the driver and the sink and calls `boot`. When this
  document and that crate disagree, the crate is the bug or this
  document is - never both correct.
- The erase/write counting adapter stays enabled; its numbers feed
  the endurance model comparison as a side product.

## Procedure

1. **Seed and verify.** Flash the bench firmware, let it complete at
   least one full batch, power-cycle cleanly once, and verify the
   store mounts and the invariant below holds. A bench that cannot
   pass a clean cycle has no business being plug-pulled.
2. **Pull.** With batch traffic running, cut power at an arbitrary
   moment. Vary the timing deliberately across rounds: immediately
   after boot, seconds in, minutes in — and do not synchronise the
   cuts to anything the firmware does (the redb kill-nine's cadence
   decorrelation, applied by hand).
3. **Restore and audit.** Power up. The firmware's first action on
   boot, before starting new traffic, is the audit:
   - the store mounts;
   - every key under the batch prefixes is walked, and for every
     sequence number present, the batch it belongs to is complete —
     both blocks and the index entry, byte-for-byte;
   - no key under the reserved `0x00` namespace is visible;
   - the highest complete sequence number is recorded and never
     decreases across the run — "recorded" meaning persisted on the
     medium by the firmware itself under its own key after every
     successful batch (RAM does not survive a cut), and echoed on the
     serial line so an operator can cross-check off-device.
   The audit result is written to serial output and logged off the
   device before traffic resumes.
4. **Repeat.** Minimum 100 pulls before the run counts as a result.
   Fewer proves nothing about a probabilistic window; the number is
   arbitrary but fixed here, in advance, so it cannot shrink to meet
   a deadline.

## What counts as failure

Any one occurrence of any of these ends the run as a **fail**:

- a partial batch after recovery: any sequence number for which some
  but not all of the batch's keys carry the new state;
- an unmountable store (mount error on a region that mounted before
  the cut);
- a reserved-namespace key visible to the audit walk;
- a committed batch lost: the highest complete sequence number
  observed after a cut is lower than one already recorded before it;
- a panic or hang during mount-time recovery.

A failed run stops the bench until the failure is attributed — chip
behaviour, driver, seal logic — because the fixes live in different
places and hammering on an unattributed failure produces nothing but
noise. Silent recalibration of the criteria is what this document
exists to prevent.

## What a pass does and does not prove

A pass proves the seal's guarantee survives real power loss on this
part, at this word size, under this traffic shape, for the sampled
cut instants. It does not prove endurance (that is the wear model's
bench, `FLASH_ENDURANCE.md` section 6), does not cover other flash
parts, and cannot exhaustively cover cut timing — it samples it. The
T-Beam bench is the final judge of the backend's fitness for M3-6,
and this protocol is the part of that judgement no host test can
render.
