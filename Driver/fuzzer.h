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

enum class FuzzDuration : uint64_t {
  OneMins       = 60,
  FiveMins      = OneMins * 5,
  TenMins       = OneMins * 10,
  TwentyMins    = OneMins * 20,
  ThirtyMins    = OneMins * 30,
  FourtyMins    = OneMins * 40,
  FiftyMins     = OneMins * 50,
  
  OneHr         = OneMins * 60,
  TwoHr         = OneHr   * 2,
  FourHr        = OneHr   * 4,
  EightHr       = OneHr   * 8,
  SixteenHr     = OneHr   * 16,
  TwentyFourHr  = OneHr   * 24,
};

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
    
    // NO COPYING prevents multiple Fuzzers using the same crash dir and same target
    PeelFuzz(const PeelFuzz&)             = delete;
    PeelFuzz& operator=(const PeelFuzz&)  = delete;

    void runFuzzer(uint64_t duration) {
      m_config.timer_sec = duration;
      peel_fuzz_run(&m_config);
    }
    
    void runFuzzer(FuzzDuration duration) {
      m_config.timer_sec = static_cast<uint64_t>(duration);
      peel_fuzz_run(&m_config);
    }
};
