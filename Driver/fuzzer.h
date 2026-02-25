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
    HarnessType     harness_type;
    void*           target_fn;
    SchedulerType   scheduler_type;
    uint64_t        timeout_ms;      // 0 = default (1000ms)
    uint64_t        timer_sec;       // 0 = default (1000ms)
    const char*     crash_dir;       // NULL = "./crashes"
    uint32_t        seed_count;      // 0 = default (8)
    uint32_t        core_count;      // 0 = auto-detect (all available cores)
  } PeelFuzzConfig;

  // Main fuzzing entry point
  void peel_fuzz_run(const PeelFuzzConfig* config);
}

// C++ wrapper around rust ABI
class PeelFuzz {
  private:
    PeelFuzzConfig m_config {};

  public:
    PeelFuzz(
      HarnessType type, void* targetFn, SchedulerType schedType,
      uint64_t timeoutMs, uint32_t seedCnt, uint32_t coreCnt = 0
    ) {
      m_config.harness_type   = type;
      m_config.target_fn      = targetFn;
      m_config.scheduler_type = schedType;
      m_config.timeout_ms     = timeoutMs;
      m_config.seed_count     = seedCnt;
      m_config.core_count     = coreCnt;
    }

    void runFuzzer(uint32_t duration) {
      m_config.timer_sec = duration;
      peel_fuzz_run(&m_config);
    }
};
