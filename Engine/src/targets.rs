use libafl::executors::ExitKind;
use libafl::inputs::{BytesInput, HasTargetBytes};
use libafl_bolts::AsSlice;

use crate::sanitizer_coverage::reset_coverage;

/// Function pointer type for C target functions.
/// The target receives a pointer to input data and its length.
pub type CTargetFn = unsafe extern "C" fn(*const u8, usize);

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
