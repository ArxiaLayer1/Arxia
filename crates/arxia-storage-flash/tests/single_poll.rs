//! The single-poll bridge, held to its word.
//!
//! `poll_once` is the crate's foundation: every operation crosses the
//! async boundary through it, and its contract is one poll, then a
//! typed fault - never a loop, never a hang. The risk register cites
//! this test as the enforcement of that guard; it exists so that the
//! citation is true.

use arxia_core::{ArxiaError, StorageFault};
use arxia_storage_flash::poll_once;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// A future that pends on its first poll and would complete on a
/// second - which `poll_once` must never grant it.
struct PendsOnce {
    polled: bool,
}

impl Future for PendsOnce {
    type Output = u32;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<u32> {
        if self.polled {
            Poll::Ready(42)
        } else {
            self.polled = true;
            Poll::Pending
        }
    }
}

#[test]
fn a_pending_future_is_a_typed_fault_never_a_second_poll() {
    match poll_once(PendsOnce { polled: false }) {
        Err(ArxiaError::Storage {
            fault: StorageFault::WouldBlock,
        }) => {}
        Ok(value) => panic!("a pending future must not yield a value, got {value}"),
        Err(other) => panic!("the fault must be WouldBlock, got: {other}"),
    }
}

#[test]
fn a_ready_future_passes_its_output_through() {
    assert!(matches!(poll_once(core::future::ready(7u8)), Ok(7)));
}
