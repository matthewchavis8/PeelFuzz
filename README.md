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
│   │   ├── lib.rs                    # Main entry point and fuzzer setup
│   │   ├── targets.rs                # Harness wrappers for different input types
│   │   └── sanitizer_coverage.rs     # Coverage hook implementations
│   └── Cargo.toml
├── Driver/             # C++ wrapper library
│   ├── fuzzer.h                      # C API interface and C++ wrappers
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

### 1. Build the Rust Engine

```bash
cd Engine/
cargo build --release
```

This produces `Engine/target/release/libPeelFuzz.a` containing:
- LibAFL fuzzing logic
- Coverage instrumentation hooks
- C ABI entry points

### 2. Build the C++ Driver Layer

```bash
# Configure with Debug preset (AddressSanitizer, UBSan, debug symbols)
cmake --preset=Debug
cd Debug/
make

# Or configure with Release preset (optimizations enabled)
cmake --preset=Release
cd Release/
make
```

This produces the static library:
- `Debug/Driver/libdriver.a` or `Release/Driver/libdriver.a`

**Note**: The CMake presets provide sanitizers and optimization flags, but the critical `-fsanitize-coverage=trace-pc-guard` flag must be added when compiling your fuzz targets (see Usage section below).

#### CMake Presets

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
  Release/Driver/libdriver.a \
  Engine/target/release/libPeelFuzz.a \
  -pthread -ldl -lm
```

Run the fuzzer:

```bash
./fuzzer
```

### Level 2: Extending Rust Harnesses

For custom input handling or structured fuzzing, extend the harness functions in `Engine/src/targets.rs`:

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

Then add a corresponding C ABI function in `Engine/src/lib.rs`:

```rust
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fuzz_structured(target_fn: targets::CTargetFn) {
    run_fuzzer(targets::structured_harness(target_fn));
}
```

### Level 3: Creating C++ Wrappers

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
  Release/Driver/libdriver.a \
  Engine/target/release/libPeelFuzz.a \
  -pthread -ldl -lm
```

## Architecture

For detailed architecture information, including the three-layer design, function pointer mechanism, and environment support (std/no_std), see [Docs/VISION.md](Docs/VISION.md).

Key architectural points:

- **Rust Engine**: LibAFL-based fuzzer with input generation, corpus management, and coverage tracking
- **C ABI Layer**: Stable interface between Rust and C++ via `extern "C"` functions
- **C++ Driver**: Function pointer routing and environment abstraction
- **Coverage Hooks**: Rust implementation of `__sanitizer_cov_trace_pc_guard` enables coverage-guided fuzzing

## API Reference

### C API (from Driver/fuzzer.h)

```c
typedef void(*CTargetFn)(const uint8_t* data, size_t len);
void fuzz_byte_size(CTargetFn target_fn);
```

### Rust API (from Engine/src/lib.rs)

```rust
pub unsafe extern "C" fn fuzz_byte_size(target_fn: targets::CTargetFn);
```

## Troubleshooting

**Issue**: Fuzzer runs but makes no progress finding bugs

**Solution**: Ensure target code is compiled with `-fsanitize-coverage=trace-pc-guard`. Without coverage instrumentation, the fuzzer cannot observe which inputs explore new code paths.

**Issue**: Linker errors about undefined sanitizer symbols

**Solution**: Add `-fsanitize=fuzzer-no-link` to compilation flags (not just `-fsanitize=fuzzer`, which tries to add its own main function).

**Issue**: Crashes immediately on startup

**Solution**: Ensure both the Rust engine and C++ driver are built before linking. Run `cargo build --release` in `Engine/` and `make` in `Debug/` or `Release/` first.

## Contributing

This project is under active development. Contributions welcome for:

- Additional harness patterns in `Engine/src/targets.rs`
- Example fuzz targets demonstrating different use cases
- Documentation improvements
- Performance optimizations

## License

See [LICENSE](LICENSE) for details.

## Acknowledgments

Built on [LibAFL](https://github.com/AFLplusplus/LibAFL), a state-of-the-art fuzzing framework developed by the AFL++ team.
