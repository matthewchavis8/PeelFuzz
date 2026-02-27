#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
mod allocator;

pub mod sanitizer_coverage;
pub mod config;
mod engine;
mod harness;
mod monitors;
mod schedulers;
pub mod targets;
pub use engine::PeelFuzzer;
use core::time::Duration;
use config::{HarnessType, PeelFuzzConfig, SchedulerType};

/// Main entry point: run the fuzzer with a full config struct.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peel_fuzz_run(config: *const PeelFuzzConfig) {
    unsafe {
        let cfg = &*config;
        let timeout = Duration::from_millis(cfg.timeout_ms_or_default());
        let fuzz_duration = Duration::from_secs(cfg.timer_sec_or_default());
        let crash_dir = cfg.crash_dir_or_default();
        let seed_count = cfg.seed_count_or_default();
        let core_count = cfg.core_count_or_default();

        match cfg.harness_type {
            HarnessType::ByteSize => {
                let target_fn: targets::CTargetFn = core::mem::transmute(cfg.target_fn);
                let h = harness::bytes_harness(target_fn);
                build_and_run(
                    h,
                    cfg.scheduler_type,
                    timeout,
                    fuzz_duration,
                    &crash_dir,
                    seed_count,
                    core_count,
                );
            }
            HarnessType::String => {
                let target_fn: targets::CTargetStringFn = core::mem::transmute(cfg.target_fn);
                let h = harness::string_harness(target_fn);
                build_and_run(
                    h,
                    cfg.scheduler_type,
                    timeout,
                    fuzz_duration,
                    &crash_dir,
                    seed_count,
                    core_count,
                );
            }
        }
    }
}

unsafe fn build_and_run(
    harness: impl FnMut(&libafl::inputs::BytesInput) -> libafl::executors::ExitKind,
    scheduler_type: SchedulerType,
    timeout: Duration,
    fuzz_duration: Duration,
    crash_dir: &str,
    seed_count: usize,
    core_count: usize,
) {
    let builder = PeelFuzzer::new(harness)
        .scheduler(scheduler_type)
        .timeout(timeout)
        .fuzz_duration(fuzz_duration)
        .crash_dir(crash_dir)
        .seed_count(seed_count)
        .core_count(core_count);

    unsafe { builder.run() };
}

// --- no_std required symbols ---

#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// LibAFL requires a time source in no_std mode. This stub returns 0.
/// Override this symbol with a real hardware timer for your MCU/SoC
/// (e.g., read a cycle counter or peripheral timer register).
#[cfg(not(feature = "std"))]
#[unsafe(no_mangle)]
pub extern "C" fn external_current_millis() -> u64 {
    0
}
