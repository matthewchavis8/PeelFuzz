/// Harness builder functions that wrap C target functions for LibAFL.
use libafl::executors::ExitKind;
use libafl::inputs::{BytesInput, HasTargetBytes};
use libafl_bolts::AsSlice;

use crate::sanitizer_coverage::reset_coverage;
use crate::targets::{CTargetFn, CTargetStringFn};

/// Build a harness for byte-buffer targets.
pub fn bytes_harness(target_fn: CTargetFn) -> impl FnMut(&BytesInput) -> ExitKind {
    move |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();

        unsafe {
            reset_coverage();
            target_fn(buf.as_ptr(), buf.len());
        }

        ExitKind::Ok
    }
}

/// Build a harness for null-terminated string targets.
pub fn string_harness(target_fn: CTargetStringFn) -> impl FnMut(&BytesInput) -> ExitKind {
    move |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();

        // Append null terminator
        let mut owned = buf.to_vec();
        owned.push(0);

        unsafe {
            reset_coverage();
            target_fn(owned.as_ptr() as *const core::ffi::c_char);
        }

        ExitKind::Ok
    }
}
