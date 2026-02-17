# PeelFuzz

A cross-language fuzzing framework that bridges Rust's LibAFL fuzzing engine to C++ targets through a stable C ABI layer. PeelFuzz enables coverage-guided fuzzing of C++ code in any environment, from standard applications to bare-metal embedded systems.

## Overview

PeelFuzz provides a three-layer architecture for fuzzing C++ code:

1. **Engine (Rust)**: LibAFL-based fuzzing engine that generates inputs and implements coverage instrumentation hooks
2. **Driver (C++)**: Wrapper API around the Rust engine's C ABI - this is what developers call from their code
3. **Target (C++)**: Your code being fuzzed - the Engine passes generated inputs through the Driver to your target function

The framework uses function pointers to route fuzzer-generated inputs to arbitrary C++ target functions, making it flexible enough to fuzz system calls, protocol parsers, library functions, or any code that accepts byte buffers.

**Multicore fuzzing is enabled by default** - PeelFuzz automatically detects and uses all available CPU cores for maximum performance.

## Project Structure

```
PeelFuzz/
├── Engine/             # Layer 1: Rust/LibAFL fuzzing engine
│   ├── src/
│   │   ├── lib.rs                    # Main entry point and C ABI exports
│   │   ├── engine.rs                 # PeelFuzzer builder and macro implementations
│   │   ├── config.rs                 # Configuration types for C ABI boundary
│   │   ├── harness.rs                # Harness wrappers for different input types
│   │   ├── targets.rs                # C function pointer types
│   │   ├── monitors.rs               # Monitor creation and statistics output
│   │   ├── schedulers.rs             # Scheduler re-exports
│   │   └── sanitizer_coverage.rs     # Coverage hook implementations
│   └── Cargo.toml
├── Driver/             # Layer 2: C++ API wrapper (header-only)
│   ├── fuzzer.h                      # C API interface (what developers use)
│   └── CMakeLists.txt
├── Examples/           # Layer 3: Your fuzz targets
│   └── Bug1/
│       ├── bug1.cpp                  # Multi-gate fuzzing target example
│       └── makefile                  # Build configuration with coverage flags
└── Docs/
    └── VISION.md                     # Detailed architecture documentation
```

## Prerequisites

- CMake 3.20 or higher
- C++17 compatible compiler
- Rust toolchain (cargo, rustc)
- Clang with sanitizer coverage support

## Critical: Coverage Instrumentation Requirements

**PeelFuzz requires all target code to be compiled with `-fsanitize-coverage=trace-pc-guard`.**

The Rust engine implements the sanitizer coverage hooks (`__sanitizer_cov_trace_pc_guard` and `__sanitizer_cov_trace_pc_guard_init`) in `Engine/src/sanitizer_coverage.rs`. These hooks are called by the compiler-inserted instrumentation to track code coverage during fuzzing. Without this flag, the fuzzer will run but coverage-guided feedback will not work, severely limiting effectiveness.

## Quick Start

**1. Build PeelFuzz** (builds both Rust Engine and C++ Driver):

```bash
cmake --preset=Release && cmake --build Release
```

This produces a single static library: `Release/libPeelFuzz.a`

**2. Write a fuzz target**:

```cpp
#include "Driver/fuzzer.h"

void my_target(const uint8_t* data, size_t size) {
    // Your code to fuzz
    if (size > 0 && data[0] == 'X') {
        int* crash = nullptr;
        *crash = 42;  // Bug!
    }
}

int main() {
    PeelFuzzConfig config = {
        .harness_type   = HARNESS_BYTES,
        .target_fn      = (void*)my_target,
        .scheduler_type = SCHEDULER_QUEUE,
        .timeout_ms     = 0,        // Use defaults
        .crash_dir      = nullptr,  // Use default "./crashes"
        .seed_count     = 0,        // Use default (8 seeds)
        .core_count     = 0,        // Auto-detect all cores (multicore by default)
    };
    peel_fuzz_run(&config);
    return 0;
}
```

**3. Compile with required coverage instrumentation**:

```bash
clang++ -std=c++17 \
  -fsanitize-coverage=trace-pc-guard \
  -fsanitize=fuzzer-no-link \
  my_target.cpp -o fuzzer \
  -LRelease -lPeelFuzz -lpthread -ldl -lm
```

**4. Run**:

```bash
./fuzzer
```

See `Examples/Bug1/` for a complete working example.

## Build Instructions

PeelFuzz uses CMake to build both the Rust Engine and C++ Driver in one command. The build process:
1. Compiles the Rust fuzzing engine (`Engine/`) using Cargo
2. Compiles the C++ driver wrappers (`Driver/`)
3. Merges both into a single static library: `libPeelFuzz.a`

### CMake Presets

**Release** (recommended for fuzzing):
```bash
cmake --preset=Release && cmake --build Release
```
- Output: `Release/libPeelFuzz.a`
- Flags: `-O3` (maximum performance)

**Debug** (for development):
```bash
cmake --preset=Debug && cmake --build Debug
```
- Output: `Debug/libPeelFuzz.a`
- Flags: `-fsanitize=address -fsanitize=undefined -g`
- Use for debugging PeelFuzz itself

**Important**: The CMake build handles the fuzzer library. Your fuzz targets must be compiled separately with `-fsanitize-coverage=trace-pc-guard` for coverage-guided fuzzing to work.

## Configuration Reference

The `PeelFuzzConfig` struct provides full control over fuzzer behavior:

```cpp
PeelFuzzConfig config = {
    .harness_type   = HARNESS_BYTES,     // or HARNESS_STRING
    .target_fn      = (void*)my_target,
    .scheduler_type = SCHEDULER_QUEUE,   // or SCHEDULER_WEIGHTED
    .timeout_ms     = 1000,              // Timeout per input (0 = default 1000ms)
    .crash_dir      = "./crashes",       // Crash output dir (nullptr = "./crashes")
    .seed_count     = 8,                 // Initial seeds (0 = default 8)
    .core_count     = 0,                 // CPU cores (0 = auto-detect all cores)
};
peel_fuzz_run(&config);
```

### Multi-Core Fuzzing (Default)

**PeelFuzz uses all available CPU cores by default** for maximum performance. Each core runs an independent fuzzer process with shared corpus synchronization.

**Core count behavior**:
- `core_count = 0`: **Auto-detect and use all available cores** (default, recommended)
- `core_count = 1`: Single-core mode (opt-in, useful for debugging)
- `core_count = N`: Use exactly N cores

Implementation: Each fuzzer process gets its own coverage map (copy-on-write), and interesting inputs are automatically shared between all instances via shared memory.

**Example - Minimal configuration (uses all cores)**:
```cpp
PeelFuzzConfig config = {
    .harness_type   = HARNESS_BYTES,
    .target_fn      = (void*)my_target,
    .scheduler_type = SCHEDULER_QUEUE,
    .timeout_ms     = 0,
    .crash_dir      = nullptr,
    .seed_count     = 0,
    .core_count     = 0,  // Multicore by default!
};
```

## Architecture

### Component Flowchart

![PeelFuzz Architecture Flowchart](fuzzingArchitecture.png)

### Fuzz Loop Sequence
<img width="1024" height="791" alt="PeelFuzzFlow drawio" src="https://github.com/user-attachments/assets/962be761-f471-482d-8e10-aa0a7f8bb18f" />



### Three-Layer Design

PeelFuzz uses a three-layer design to bridge Rust fuzzing to C++ targets:

**Layer 1 - Engine (Rust)**:
- LibAFL-based fuzzer with input generation, corpus management, and coverage tracking
- Implements sanitizer coverage hooks (`__sanitizer_cov_trace_pc_guard`) to receive coverage feedback
- Handles multicore parallelism with automatic CPU detection
- Exports C ABI functions for cross-language integration

**Layer 2 - Driver (C++)**:
- Wrapper API around the Rust engine's C ABI
- This is the interface developers use: `#include "Driver/fuzzer.h"` and `peel_fuzz_run()`
- Provides type-safe configuration via `PeelFuzzConfig` struct

**Layer 3 - Target (C++)**:
- Your code being fuzzed (e.g., parsers, validators, protocol handlers)
- Must be compiled with `-fsanitize-coverage=trace-pc-guard` for coverage feedback

**Build Output**: CMake merges the Rust engine and C++ driver into a single static library (`libPeelFuzz.a`) for simple linking.

For detailed architecture information, including function pointer mechanism and environment support (std/no_std), see [Docs/VISION.md](Docs/VISION.md).

## API Reference

### PeelFuzzConfig Fields

| Field | Type | Description | Default (when 0/null) |
|-------|------|-------------|----------------------|
| `harness_type` | `HarnessType` | `HARNESS_BYTES` (0) or `HARNESS_STRING` (1) | N/A (required) |
| `target_fn` | `void*` | Function pointer to fuzz target | N/A (required) |
| `scheduler_type` | `SchedulerType` | `SCHEDULER_QUEUE` (0) or `SCHEDULER_WEIGHTED` (1) | N/A (required) |
| `timeout_ms` | `uint64_t` | Timeout per input in milliseconds | 1000ms |
| `crash_dir` | `const char*` | Directory for crash artifacts | `"./crashes"` |
| `seed_count` | `uint32_t` | Number of initial random seeds | 8 |
| `core_count` | `uint32_t` | CPU cores for parallel fuzzing | Auto-detect (all cores) |

**Important**: `target_fn` must match the selected `harness_type`:
- `HARNESS_BYTES`: `void target(const uint8_t* data, size_t size)`
- `HARNESS_STRING`: `void target(const char* str)` (null-terminated)

## Advanced Configuration

### Cargo Features

The Rust Engine supports optional features configured via `Engine/Cargo.toml`:

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | Yes | Standard library support (required for most use cases) |
| `fork` | Yes | Enables multi-core fuzzing (Unix/Linux only, **required for multicore**) |

**Note**: The `fork` feature is enabled by default, so multicore fuzzing works out of the box. Disable it only for single-core embedded/bare-metal targets.

To modify features, edit `Engine/Cargo.toml` and rebuild.

## Troubleshooting

**Issue**: Fuzzer runs but makes no progress finding bugs

**Solution**: Ensure target code is compiled with `-fsanitize-coverage=trace-pc-guard`. Without coverage instrumentation, the fuzzer cannot observe which inputs explore new code paths.

**Issue**: Linker errors about undefined sanitizer symbols

**Solution**: Add `-fsanitize=fuzzer-no-link` to compilation flags (not just `-fsanitize=fuzzer`, which tries to add its own main function).

**Issue**: Crashes immediately on startup

**Solution**: Ensure `libPeelFuzz.a` is built first. Run `cmake --preset=Release && cmake --build Release` from the project root.

**Issue**: Fuzzer runs in single-core mode instead of multicore

**Solution**: Check that the `fork` feature is enabled in `Engine/Cargo.toml` (it is by default) and rebuild. Multicore requires Unix/Linux. On macOS/BSD, you may need to adjust system limits for shared memory segments. Set `core_count = 0` in your config to auto-detect cores.

## Contributing

This project is under active development. Contributions welcome for:

- Additional harness patterns in `Engine/src/harness.rs`
- Example fuzz targets demonstrating different use cases
- Documentation improvements
- Performance optimizations

## License

See [LICENSE](LICENSE) for details.

## Acknowledgments

Built on [LibAFL](https://github.com/AFLplusplus/LibAFL), a state-of-the-art fuzzing framework developed by the AFL++ team.
