//! Power-loss bench firmware for the LilyGO T-Beam v1.1 (ESP32).
//!
//! Every decision lives in `arxia-flash-bench` - the batch shape, the
//! sequence tags, the boot-time audit, the failure criteria, the boot
//! decision. This binary is the thin adapter the protocol document
//! promises: it hands that crate a real flash chip and a serial line,
//! and otherwise stays out of the way.
//!
//! The stack, bottom to top: `esp_storage::FlashStorage` (the SPI NOR
//! via ROM routines, blocking), a counting shim tallying every read,
//! write and erase for the endurance comparison, and
//! `BlockingAsync` - the adapter esp-storage's own documentation names
//! for exactly this composition - to the async traits the backend is
//! generic over. The backend's futures on a blocking driver complete
//! on their first poll (pinned by its `single_poll` tests), so no
//! executor exists here.
//!
//! Serial protocol, one line each, parseable off-device:
//! `AUDIT ... verdict=...` once per boot before any traffic;
//! `BATCH seq=N ok|committed|uncertain|refused` per batch;
//! `STATS seq=N reads=… writes=… erases=…` every [`STATS_EVERY`]
//! batches (counters since this boot - RAM does not survive a cut,
//! and the off-device log is what accumulates across the run);
//! `HALT ...` when the run stops, as the protocol requires on any
//! failure, leaving the evidence on the medium.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use arxia_flash_bench::{boot, run_one, BatchOutcome, BootDecision};
use embassy_embedded_hal::adapter::BlockingAsync;
use embedded_storage::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::main;
use esp_println::{println, Printer};

extern crate alloc;

// The app-descriptor the esp-idf second-stage bootloader expects.
esp_bootloader_esp_idf::esp_app_desc!();

/// The flash region the bench owns: the last mebibyte of the T-Beam's
/// 4 MiB part, addressed absolutely. The application image lives at
/// 0x10000 and is a few hundred kibibytes; nothing else in this
/// firmware touches flash. Commissioning erases the whole chip
/// (`espflash erase-flash`), so the first mount sees erased flash,
/// not another firmware's leftovers.
const RANGE: core::ops::Range<u32> = 0x30_0000..0x40_0000;

/// Batches between `STATS` lines.
const STATS_EVERY: u32 = 32;

static READS: AtomicU32 = AtomicU32::new(0);
static WRITES: AtomicU32 = AtomicU32::new(0);
static ERASES: AtomicU32 = AtomicU32::new(0);

/// The counting shim: every flash primitive tallied, then delegated
/// untouched. The tally is the bench's side product - the erase count
/// is what the endurance model's wrap arithmetic is checked against.
struct CountingFlash<T> {
    inner: T,
}

impl<T: ErrorType> ErrorType for CountingFlash<T> {
    type Error = T::Error;
}

impl<T: ReadNorFlash> ReadNorFlash for CountingFlash<T> {
    const READ_SIZE: usize = T::READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        READS.fetch_add(1, Ordering::Relaxed);
        self.inner.read(offset, bytes)
    }

    fn capacity(&self) -> usize {
        self.inner.capacity()
    }
}

impl<T: NorFlash> NorFlash for CountingFlash<T> {
    const WRITE_SIZE: usize = T::WRITE_SIZE;
    const ERASE_SIZE: usize = T::ERASE_SIZE;

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        WRITES.fetch_add(1, Ordering::Relaxed);
        self.inner.write(offset, bytes)
    }

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        ERASES.fetch_add(1, Ordering::Relaxed);
        self.inner.erase(from, to)
    }
}

impl<T: MultiwriteNorFlash> MultiwriteNorFlash for CountingFlash<T> {}

/// The run has ended; the evidence stays on the medium. The last
/// serial lines said why.
fn park() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[main]
fn main() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 98768);

    println!(
        "ARXIA-BENCH boot region={:#x}..{:#x}",
        RANGE.start, RANGE.end
    );

    let raw = esp_storage::FlashStorage::new(peripherals.FLASH);
    let flash = BlockingAsync::new(CountingFlash { inner: raw });

    // The protocol's boot: mount, audit, report, decide - the audit
    // line is on the wire before any traffic exists to corrupt it.
    let mut out = Printer;
    let (mut store, decision) = match boot(flash, RANGE, &mut out) {
        Ok(pair) => pair,
        Err(_) => {
            // The AUDIT line already named the mount failure.
            println!("HALT unmountable");
            park();
        }
    };

    let mut seq = match decision {
        BootDecision::Resume { next_seq } => next_seq,
        BootDecision::Halt(verdict) => {
            println!("HALT {:?}", verdict);
            park();
        }
    };

    loop {
        let outcome = run_one(&mut store, &mut out, seq);
        if outcome == BatchOutcome::Refused {
            // No protocol outcome expects a refusal on this traffic;
            // stop and show it rather than hammer on it.
            println!("HALT refused seq={seq}");
            park();
        }
        if seq % STATS_EVERY == 0 {
            println!(
                "STATS seq={} reads={} writes={} erases={}",
                seq,
                READS.load(Ordering::Relaxed),
                WRITES.load(Ordering::Relaxed),
                ERASES.load(Ordering::Relaxed),
            );
        }
        seq = seq.wrapping_add(1);
    }
}
