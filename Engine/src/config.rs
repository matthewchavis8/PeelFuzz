/// Configuration types for the PeelFuzz C ABI boundary.

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarnessType {
    ByteSize = 0,
    String = 1,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerType {
    Queue = 0,
    Weighted = 1,
}

#[repr(C)]
pub struct PeelFuzzConfig {
    pub harness_type: HarnessType,
    pub target_fn: *const core::ffi::c_void,
    pub scheduler_type: SchedulerType,
    /// Executor timeout in milliseconds. 0 = default (1000ms).
    pub timeout_ms: u64,
    /// Path for crash outputs. Null = "./crashes".
    pub crash_dir: *const i8,
    /// Number of initial seed inputs. 0 = default (8).
    pub seed_count: u32,
    /// Number of cores for parallel fuzzing. 0 = auto-detect (all available cores).
    pub core_count: u32,
}

impl PeelFuzzConfig {
    pub fn timeout_ms_or_default(&self) -> u64 {
        if self.timeout_ms == 0 {
            1000
        } else {
            self.timeout_ms
        }
    }

    pub fn seed_count_or_default(&self) -> usize {
        if self.seed_count == 0 {
            8
        } else {
            self.seed_count as usize
        }
    }

    pub fn core_count_or_default(&self) -> usize {
        if self.core_count == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        } else {
            self.core_count as usize
        }
    }

    pub fn crash_dir_or_default(&self) -> String {
        if self.crash_dir.is_null() {
            "./crashes".to_string()
        } else {
            unsafe {
                core::ffi::CStr::from_ptr(self.crash_dir)
                    .to_string_lossy()
                    .into_owned()
            }
        }
    }
}
