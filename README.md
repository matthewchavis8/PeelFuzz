# PeelFuzz

A cross-language fuzzing framework that bridges Rust's LibAFL fuzzing engine to C++ targets through a stable C ABI layer. PeelFuzz enables coverage-guided fuzzing of C++ code in any environment, from standard applications to bare-metal embedded systems.

## Overview

PeelFuzz provides a three-layer architecture for fuzzing C++ code:

1. **Engine**: Rust/LibAFL fuzzing engine with coverage instrumentation hooks
2. **Driver**: C++ wrapper library around the C ABI
3. **Examples**: Working examples demonstrating usage patterns

The framework uses function pointers to route fuzzer-generated inputs to arbitrary C++ target functions, making it flexible enough to fuzz system calls, protocol parsers, library functions, or any code that accepts byte buffers.

## Project Structure

```
PeelFuzz/
├── Engine/             # Rust/LibAFL fuzzing engine
│   ├── src/
│   │   ├── lib.rs                    # Main entry point and C ABI exports
│   │   ├── engine.rs                 # PeelFuzzer builder and macro implementations
│   │   ├── config.rs                 # Configuration types for C ABI boundary
│   │   ├── harness.rs                # Harness wrappers for different input types
│   │   ├── targets.rs                # C function pointer types
│   │   ├── monitors.rs               # Monitor creation (console + TUI)
│   │   ├── schedulers.rs             # Scheduler re-exports
│   │   └── sanitizer_coverage.rs     # Coverage hook implementations
│   └── Cargo.toml
├── Driver/             # C++ wrapper library
│   ├── fuzzer.h                      # C API interface and C++ wrappers
│   ├── fuzzer.cpp                    # Wrapper implementations
│   └── CMakeLists.txt
├── Examples/           # Working examples
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

## Build Instructions

A single CMake command builds the Rust engine and C++ driver, then merges everything into one static library:

```bash
cmake --preset=Release
cmake --build Release
```

This produces `Release/libPeelFuzz.a` containing:
- LibAFL fuzzing logic
- Coverage instrumentation hooks
- C ABI entry points
- C++ driver wrappers

**Note**: The CMake presets provide sanitizers and optimization flags, but the critical `-fsanitize-coverage=trace-pc-guard` flag must be added when compiling your fuzz targets (see Usage section below).

### CMake Presets

**Debug**:
- Build directory: `Debug/`
- Flags: `-fsanitize=address -fsanitize=undefined -g`
- Use for: Development and debugging with sanitizer support

**Release**:
- Build directory: `Release/`
- Flags: `-O3`
- Use for: High-performance fuzzing campaigns

## Workflow

### Level 1: Basic Usage

Write a C++ target function and fuzz it:

```cpp
#include "Driver/fuzzer.h"

void my_target(const uint8_t* data, size_t size) {
    // Your code to fuzz
    if (size >= 4 && data[0] == 'B' && data[1] == 'U' &&
        data[2] == 'G' && data[3] == '!') {
        // Trigger a crash to test fuzzer
        int* p = nullptr;
        *p = 42;
    }
}

int main() {
    fuzz_byte_size(my_target);
    return 0;
}
```

Compile with **required** coverage instrumentation:

```bash
clang++ -std=c++17 \
  -fsanitize-coverage=trace-pc-guard \
  -fsanitize=fuzzer-no-link \
  my_target.cpp -o fuzzer \
  -LRelease -lPeelFuzz -lpthread -ldl -lm
```

Run the fuzzer:

```bash
./fuzzer
```

### Level 2: Advanced Configuration with `peel_fuzz_run`

For full control over the fuzzer, use the `peel_fuzz_run` C API with a `PeelFuzzConfig` struct:

```cpp
#include <cstdint>
#include <cstddef>

// PeelFuzz C ABI types
extern "C" {
    enum HarnessType  { ByteSize = 0, String = 1 };
    enum SchedulerType { Queue = 0, Weighted = 1 };

    struct PeelFuzzConfig {
        HarnessType    harness_type;
        const void*    target_fn;
        SchedulerType  scheduler_type;
        uint64_t       timeout_ms;   // 0 = default (1000ms)
        const char*    crash_dir;    // NULL = "./crashes"
        uint32_t       seed_count;   // 0 = default (8)
        uint32_t       core_count;   // 0 or 1 = single-core
        bool           use_tui;
    };

    void peel_fuzz_run(const PeelFuzzConfig* config);
}

void my_target(const uint8_t* data, size_t len) {
    // ... your target code ...
}

int main() {
    PeelFuzzConfig config = {
        .harness_type   = ByteSize,
        .target_fn      = (const void*)my_target,
        .scheduler_type = Weighted,
        .timeout_ms     = 2000,        // 2 second timeout per input
        .crash_dir      = "./crashes",
        .seed_count     = 16,
        .core_count     = 4,           // Use 4 cores
        .use_tui        = false,
    };
    peel_fuzz_run(&config);
    return 0;
}
```

### Multi-Core Fuzzing

PeelFuzz supports parallel fuzzing across multiple CPU cores using LibAFL's fork-based `Launcher`. Set `core_count` in `PeelFuzzConfig` to the number of cores you want to use:

- `core_count = 0` or `1`: single-core (default)
- `core_count = N` (where N > 1): spawns N fuzzer processes with shared-memory corpus synchronization

Each child process gets its own coverage map (copy-on-write after `fork()`), and corpus entries are automatically shared between instances via LLMP shared memory.

### Level 3: Extending Rust Harnesses

For custom input handling or structured fuzzing, extend the harness functions in `Engine/src/harness.rs`:

```rust
/// Example: Harness for structured input
pub fn structured_harness(target_fn: CTargetFn) -> impl FnMut(&BytesInput) -> ExitKind {
    move |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();

        // Add custom preprocessing here
        let processed = preprocess_input(buf);

        unsafe {
            reset_coverage();
            target_fn(processed.as_ptr(), processed.len());
        }

        ExitKind::Ok
    }
}
```

### Level 4: Creating C++ Wrappers

Add convenience wrappers in the Driver layer for common patterns. For example, `Driver/fuzzer.h` includes `fuzz_wrap()` that adapts integer-based targets:

```cpp
typedef void(*wrapFn)(int input);

void fuzz_wrap(wrapFn target) {
    auto adapter = [target](const uint8_t* data, size_t len) {
        if (len >= sizeof(int)) {
            int value;
            std::memcpy(&value, data, sizeof(int));
            target(value);
        }
    };
    fuzz_byte_size(adapter);
}
```

## Usage Examples

### Complete Example: Examples/Bug1

The Bug1 example demonstrates a multi-gate fuzzing target with complex constraints. It shows:

- Header parsing with magic values
- CRC and checksum validation
- Multiple execution paths (version 1, 2, 3)
- Arithmetic constraints and cryptographic checks

**Build and run**:

```bash
# Build PeelFuzz first
cmake --preset=Release
cmake --build Release

# Build and run the example
cd Examples/Bug1/
make
./bug1
```

**Compilation flags** (from `makefile`):

```makefile
CXXFLAGS=-std=c++17 -O1 -g -fno-omit-frame-pointer \
  -fsanitize=fuzzer-no-link \
  -fsanitize-coverage=trace-pc-guard
```

The `-fsanitize-coverage=trace-pc-guard` flag is **mandatory** for coverage feedback.

### Simple Example

```cpp
#include <cstring>
#include "Driver/fuzzer.h"

// Fuzz a simple parsing function
void parse_command(const uint8_t* data, size_t len) {
    if (len < 4) return;

    if (data[0] == 'C' && data[1] == 'M' &&
        data[2] == 'D' && data[3] == ':') {
        // Process command
        uint8_t cmd_type = data[4];
        // ... handle different command types
    }
}

int main() {
    fuzz_byte_size(parse_command);
    return 0;
}
```

Compile:

```bash
clang++ -std=c++17 -fsanitize-coverage=trace-pc-guard \
  your_target.cpp -o fuzzer \
  -LRelease -lPeelFuzz -lpthread -ldl -lm
```

## Architecture

For detailed architecture information, including the three-layer design, function pointer mechanism, and environment support (std/no_std), see [Docs/VISION.md](Docs/VISION.md).

Key architectural points:

- **Rust Engine**: LibAFL-based fuzzer with input generation, corpus management, coverage tracking, time feedback, and multi-core parallelism
- **C ABI Layer**: Stable interface between Rust and C++ via `extern "C"` functions
- **C++ Driver**: Function pointer routing and environment abstraction
- **Coverage Hooks**: Rust implementation of `__sanitizer_cov_trace_pc_guard` enables coverage-guided fuzzing
- **Single Library**: CMake merges the Rust engine and C++ driver into one `libPeelFuzz.a` for simple linking

## API Reference

### C API (from Driver/fuzzer.h)

```c
// Simple entry point — fuzz a byte buffer target with default settings
typedef void(*CTargetFn)(const uint8_t* data, size_t len);
void fuzz_byte_size(CTargetFn target_fn);

// Convenience wrapper for integer-input targets
typedef void(*wrapFn)(int input);
void fuzz_wrap(wrapFn target);
```

### Advanced C API (from Engine)

```c
// Full configuration entry point
void peel_fuzz_run(const PeelFuzzConfig* config);
```

See the `PeelFuzzConfig` struct fields:

| Field | Type | Description |
|-------|------|-------------|
| `harness_type` | `HarnessType` | `ByteSize` (0) or `String` (1) |
| `target_fn` | `const void*` | Function pointer to the fuzz target |
| `scheduler_type` | `SchedulerType` | `Queue` (0) or `Weighted` (1) |
| `timeout_ms` | `uint64_t` | Timeout per input in ms (0 = 1000ms default) |
| `crash_dir` | `const char*` | Crash output path (NULL = "./crashes") |
| `seed_count` | `uint32_t` | Number of initial seeds (0 = 8 default) |
| `core_count` | `uint32_t` | Number of cores (0 or 1 = single-core) |
| `use_tui` | `bool` | Enable TUI monitor (requires `tui` feature) |

## Cargo Features

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | Yes | Standard library support |
| `fork` | Yes | Multi-core fuzzing via `Launcher` |
| `tui` | No | Terminal UI monitor |

## Troubleshooting

**Issue**: Fuzzer runs but makes no progress finding bugs

**Solution**: Ensure target code is compiled with `-fsanitize-coverage=trace-pc-guard`. Without coverage instrumentation, the fuzzer cannot observe which inputs explore new code paths.

**Issue**: Linker errors about undefined sanitizer symbols

**Solution**: Add `-fsanitize=fuzzer-no-link` to compilation flags (not just `-fsanitize=fuzzer`, which tries to add its own main function).

**Issue**: Crashes immediately on startup

**Solution**: Ensure `libPeelFuzz.a` is built first. Run `cmake --preset=Release && cmake --build Release` from the project root.

**Issue**: Multi-core fuzzer fails to launch

**Solution**: Ensure the `fork` feature is enabled (it is by default). The system must support `fork()` and shared memory. Check that the requested `core_count` does not exceed available cores.

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
