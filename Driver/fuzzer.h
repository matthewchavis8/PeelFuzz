#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {
  // Harness types
  typedef enum {
    HARNESS_BYTES = 0,
    HARNESS_STRING = 1
  } HarnessType;

  // Scheduler types
  typedef enum {
    SCHEDULER_QUEUE = 0,
    SCHEDULER_WEIGHTED = 1
  } SchedulerType;

  // Full configuration structure
  typedef struct {
    HarnessType harness_type;
    void* target_fn;
    SchedulerType scheduler_type;
    uint64_t timeout_ms;      // 0 = default (1000ms)
    const char* crash_dir;    // NULL = "./crashes"
    uint32_t seed_count;      // 0 = default (8)
    uint32_t core_count;      // 0 = auto-detect (all available cores)
  } PeelFuzzConfig;

  // Main fuzzing entry point
  void peel_fuzz_run(const PeelFuzzConfig* config);
}
