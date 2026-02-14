//! PeelFuzz Engine - LibAFL-based fuzzing library for C/C++ targets
//!
//! Provides a C ABI for integrating LibAFL fuzzing into native applications,
//! and a Rust-side `PeelFuzzer` builder for ergonomic configuration.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(dead_code)]

pub mod sanitizer_coverage;

#[cfg(feature = "std")]
pub mod config;
#[cfg(feature = "std")]
mod engine;
#[cfg(feature = "std")]
mod harness;
#[cfg(feature = "std")]
mod monitors;
#[cfg(feature = "std")]
mod schedulers;
#[cfg(feature = "std")]
pub mod targets;

#[cfg(feature = "std")]
pub use engine::PeelFuzzer;

#[cfg(feature = "std")]
use std::time::Duration;

#[cfg(feature = "std")]
use config::{HarnessType, PeelFuzzConfig, SchedulerType};

/// Main entry point: run the fuzzer with a full config struct.
#[cfg(feature = "std")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peel_fuzz_run(config: *const PeelFuzzConfig) {
    unsafe {
        let cfg = &*config;
        let timeout = Duration::from_millis(cfg.timeout_ms_or_default());
        let crash_dir = cfg.crash_dir_or_default();
        let seed_count = cfg.seed_count_or_default();

        match cfg.harness_type {
            HarnessType::ByteSize => {
                let target_fn: targets::CTargetFn = core::mem::transmute(cfg.target_fn);
                let h = harness::bytes_harness(target_fn);
                build_and_run(
                    h,
                    cfg.scheduler_type,
                    timeout,
                    &crash_dir,
                    seed_count,
                    cfg.use_tui,
                );
            }
            HarnessType::String => {
                let target_fn: targets::CTargetStringFn = core::mem::transmute(cfg.target_fn);
                let h = harness::string_harness(target_fn);
                build_and_run(
                    h,
                    cfg.scheduler_type,
                    timeout,
                    &crash_dir,
                    seed_count,
                    cfg.use_tui,
                );
            }
        }
    }
}

#[cfg(feature = "std")]
unsafe fn build_and_run(
    harness: impl FnMut(&libafl::inputs::BytesInput) -> libafl::executors::ExitKind,
    scheduler_type: SchedulerType,
    timeout: Duration,
    crash_dir: &str,
    seed_count: usize,
    use_tui: bool,
) {
    let mut builder = PeelFuzzer::new(harness)
        .scheduler(scheduler_type)
        .timeout(timeout)
        .crash_dir(crash_dir)
        .seed_count(seed_count);

    if use_tui {
        builder = builder.use_tui();
    }

    unsafe { builder.run() };
}

/// Backwards-compatible entry point: fuzz a C target that takes a byte buffer and its length.
#[cfg(feature = "std")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fuzz_byte_size(target_fn: targets::CTargetFn) {
    unsafe {
        let config = PeelFuzzConfig {
            harness_type: HarnessType::ByteSize,
            target_fn: target_fn as *const core::ffi::c_void,
            scheduler_type: SchedulerType::Queue,
            timeout_ms: 0,
            crash_dir: core::ptr::null(),
            seed_count: 0,
            core_count: 0,
            use_tui: false,
        };
        peel_fuzz_run(&config);
    }
}
