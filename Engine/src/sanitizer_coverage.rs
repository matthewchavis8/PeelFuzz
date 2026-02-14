use core::ptr::{addr_of_mut, write};

pub const MAP_SIZE: usize = 65536;

pub static mut SIGNALS: [u8; MAP_SIZE] = [0; MAP_SIZE];
pub static mut SIGNALS_PTR: *mut u8 = core::ptr::null_mut();

/// Initialize the signals pointer. Must be called once before fuzzing.
pub unsafe fn init_coverage() {
    unsafe {
        SIGNALS_PTR = addr_of_mut!(SIGNALS).cast::<u8>();
    }
}

/// Mark a coverage hit at the given index.
#[inline(always)]
pub unsafe fn mark_coverage(idx: usize) {
    unsafe {
        if idx < MAP_SIZE {
            write(SIGNALS_PTR.add(idx), 1);
        }
    }
}

/// Reset all coverage signals to zero between runs.
pub unsafe fn reset_coverage() {
    unsafe {
        core::ptr::write_bytes(SIGNALS_PTR, 0, MAP_SIZE);
    }
}

/// Called once at startup by the sanitizer runtime.
/// Assigns each guard a unique index into our coverage map.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, stop: *mut u32) {
    unsafe {
        if SIGNALS_PTR.is_null() {
            init_coverage();
        }

        if start == stop || *start != 0 {
            return;
        }

        let mut idx = 1u32;
        while start < stop {
            *start = idx;
            idx += 1;
            start = start.add(1);
        }
    }
}

/// Called at every instrumented edge in the target.
/// Routes hits into our coverage map.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(guard: *mut u32) {
    unsafe {
        let idx = *guard as usize;
        if idx == 0 {
            return;
        }
        mark_coverage(idx % MAP_SIZE);
    }
}
