# PeelFuzz

> **Note:** "PeelFuzz" is a temporary working name. It reflects the idea of "peeling back layers" - bridging multiple language layers (Rust → C ABI → C++) to expose powerful fuzzing capabilities to C++ code.

A cross-language fuzzing framework that brings the power of Rust's LibAFL to C++ codebases, supporting any environment from standard applications to bare-metal embedded systems.

## Why PeelFuzz?

PeelFuzz is designed with one core principle: **fuzz anything, anywhere**.

Unlike traditional fuzzing solutions that are tightly coupled to specific environments or require significant code modifications, PeelFuzz can fuzz:

- **System calls** - Test low-level OS interfaces
- **Library functions** - Validate public APIs and internal implementations
- **Embedded firmware** - Fuzz bare-metal code without a standard library
- **Protocol parsers** - Find bugs in network protocol implementations
- **File format handlers** - Discover vulnerabilities in file parsing code
- **Kernel modules** - Test kernel-space code safely
- **Any C++ function** - If it has a signature compatible with `void func(const uint8_t* data, size_t size)`, it can be fuzzed

The key insight is that **extensibility through simplicity** - by accepting function pointers to arbitrary C++ code, PeelFuzz becomes a universal fuzzing platform rather than a specialized tool.

## Key Features

### 🎯 Universal Function Fuzzing

PeelFuzz can target any C++ function through a simple function pointer interface:

```cpp
// Fuzz a system call wrapper
void test_syscall(const uint8_t* data, size_t size) {
    // Your syscall invocation here
}

// Fuzz a protocol parser
void test_protocol_parser(const uint8_t* data, size_t size) {
    parse_network_packet(data, size);
}

// Fuzz a file format handler
void test_image_decoder(const uint8_t* data, size_t size) {
    decode_image_buffer(data, size);
}

// Register any of them with PeelFuzz
peelfuzz::fuzz_target(test_syscall);
```

This pattern enables **unlimited extensibility** - you're not constrained by what the fuzzer "knows" about. You adapt your code to the fuzzer's simple interface, and the fuzzer handles the rest.

### 🔧 Environment Agnostic

Works in both standard and no_std C++ environments:

- ✅ Standard C++ applications with full `std` library
- ✅ Embedded systems with custom or no standard library
- ✅ Kernel-space code
- ✅ Bare-metal firmware
- ✅ Safety-critical systems with restricted runtime environments

### ⚡ Powered by LibAFL

Built on [LibAFL](https://github.com/AFLplusplus/LibAFL), a state-of-the-art fuzzing library:

- Advanced mutation strategies
- Coverage-guided fuzzing
- Efficient corpus management
- Proven track record in finding real-world vulnerabilities

### 🌉 Stable Cross-Language Bridge

Leverages a C ABI compatibility layer to provide:

- Stable interface between Rust and C++
- No Rust knowledge required for C++ users
- Predictable behavior across compiler versions
- Safe memory management across language boundaries

## Architecture

PeelFuzz uses a three-layer architecture:

```
┌─────────────────────────────┐
│  Rust/LibAFL Engine         │  ← Input generation, fuzzing logic
└──────────────┬──────────────┘
               │
┌──────────────▼──────────────┐
│  C ABI Layer                │  ← Stable compatibility bridge
└──────────────┬──────────────┘
               │
┌──────────────▼──────────────┐
│  C++ Fuzzer Library         │  ← Function pointer routing
└──────────────┬──────────────┘
               │
┌──────────────▼──────────────┐
│  Your C++ Code              │  ← System calls, libraries, anything
└─────────────────────────────┘
```

For detailed architecture information, see [VISION.md](VISION.md).

## The Extensibility Pattern

PeelFuzz's power comes from its **function pointer pattern**:

1. **Simple Interface**: Target functions accept raw bytes (`const uint8_t* data, size_t size`)
2. **Your Adapter**: You write a thin wrapper that adapts the fuzzer input to your function's needs
3. **Unlimited Targets**: The fuzzer doesn't need to "understand" your code - you control how inputs are interpreted

This pattern means:

- Want to fuzz syscalls? Write an adapter that calls `syscall()` with fuzzer data
- Want to fuzz a C++ class? Write an adapter that instantiates the class and calls methods
- Want to fuzz structured data? Write an adapter that interprets bytes as your structure
- Want to fuzz multiple related functions? Write an adapter that routes to different functions based on input

The fuzzer generates bytes. You decide what those bytes mean. This is **extensibility by design**.

## Use Cases

### System Call Fuzzing

```cpp
void fuzz_syscall_interface(const uint8_t* data, size_t size) {
    if (size < sizeof(syscall_args)) return;

    // Interpret fuzzer input as syscall arguments
    auto* args = reinterpret_cast<const syscall_args*>(data);

    // Invoke the syscall
    syscall(args->number, args->arg1, args->arg2, args->arg3);
}
```

### Protocol Parsing

```cpp
void fuzz_http_parser(const uint8_t* data, size_t size) {
    http_parser parser;
    parser.parse(data, size);  // Find parsing bugs
}
```

### Embedded Firmware

```cpp
void fuzz_uart_handler(const uint8_t* data, size_t size) {
    // Simulate UART input in a no_std environment
    for (size_t i = 0; i < size; i++) {
        uart_receive_byte(data[i]);
    }
}
```

### File Format Handlers

```cpp
void fuzz_image_decoder(const uint8_t* data, size_t size) {
    image_decoder decoder;
    decoder.decode(data, size);  // Find memory corruption bugs
}
```

## Getting Started

> **Status**: Under active development. API subject to change.

```cpp
#include <peelfuzz/peelfuzz.h>

void my_fuzz_target(const uint8_t* data, size_t size) {
    // Your code to fuzz
    process_input(data, size);
}

int main() {
    peelfuzz::fuzz_target(my_fuzz_target);
    return 0;
}
```

More detailed usage examples coming soon.

## Roadmap

- [ ] Core LibAFL integration (Rust)
- [ ] C ABI compatibility layer
- [ ] C++ library with function pointer routing
- [ ] Support for std environments
- [ ] Support for no_std environments
- [ ] Coverage instrumentation
- [ ] Sanitizer integration (ASan, MSan, UBSan)
- [ ] Parallel fuzzing support
- [ ] Corpus management utilities
- [ ] Example fuzz targets
- [ ] Documentation and tutorials

## Why "PeelFuzz"? (Temporary Name)

The name reflects the layered architecture - we "peel back" language boundaries:

1. **Peel** back from C++ to C (ABI layer)
2. **Peel** back from C to Rust (FFI boundary)
3. Expose the **fuzzing** core (LibAFL)

Each layer is carefully peeled away to expose powerful fuzzing capabilities to C++ developers, regardless of their environment constraints.

We're open to better names! Suggestions welcome.

## Design Philosophy

1. **Simplicity over complexity** - Simple interfaces enable unlimited use cases
2. **Extensibility over specialization** - Support any function rather than specific patterns
3. **Portability over convenience** - Work everywhere, even in constrained environments
4. **Safety where it matters** - Use Rust's safety for the fuzzing engine, controlled interaction with C++
5. **Performance by default** - Minimal overhead, maximum throughput

## Contributing

PeelFuzz is in early development. We welcome:

- Design feedback and suggestions
- Bug reports and feature requests
- Code contributions (Rust, C++, documentation)
- Use case examples and test targets

## License

See [LICENSE](LICENSE) for details.

## Acknowledgments

Built on the excellent work of:

- [LibAFL](https://github.com/AFLplusplus/LibAFL) - The fuzzing engine powering PeelFuzz
- The Rust and C++ communities

---

**Disclaimer**: PeelFuzz is experimental software under active development. Use at your own risk.
