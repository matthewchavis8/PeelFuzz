# PeelFuzz Architecture Vision

## Project Overview

PeelFuzz is a cross-language fuzzing framework designed to fuzz C++ code in any environment, including both standard (`std`) and embedded/bare-metal (`no_std`) contexts. By leveraging Rust's powerful LibAFL fuzzing engine and bridging it to C++ through a carefully designed multi-layer architecture, PeelFuzz enables robust, efficient fuzzing of C++ codebases without requiring the target code to be rewritten in Rust.

### Key Goals

- **Universal C++ Fuzzing**: Support fuzzing of C++ code regardless of the target environment (std or no_std)
- **Cross-Language Integration**: Leverage Rust's LibAFL while maintaining compatibility with C++ targets
- **ABI Compatibility**: Bridge the gap between Rust and C++ through a stable C ABI layer
- **Flexibility**: Allow users to fuzz arbitrary C++ functions via function pointers

## Architecture Layers

PeelFuzz consists of three distinct architectural layers, each serving a specific purpose in the fuzzing pipeline:

### 1. Core Fuzzer Engine (Rust/LibAFL)

The foundation of PeelFuzz is built on LibAFL, a high-performance fuzzing library written in Rust.

**Responsibilities:**
- Generate fuzzer inputs using LibAFL's input generation strategies
- Manage the fuzzing campaign (corpus, coverage tracking, mutation strategies)
- Handle the core fuzzing logic and orchestration
- Provide instrumentation and feedback mechanisms

**Why LibAFL?**
- Proven, state-of-the-art fuzzing engine
- Excellent performance characteristics
- Modular design allows customization
- Active development and community support

### 2. C ABI Compatibility Layer

A critical intermediary layer that provides a stable bridge between Rust and C++.

**Responsibilities:**
- Expose C-style wrapper functions with stable ABI
- Marshall data between Rust and C++ representations
- Translate Rust function calls to C-compatible function pointers
- Provide a stable interface that both Rust and C++ can interact with

**Why This Layer Exists:**
The Rust ABI is not stable and is not directly compatible with C++. While C++ can interoperate with C through `extern "C"`, it cannot directly call Rust functions. The C ABI serves as a universal compatibility layer that both languages can interface with reliably.

**Key Characteristics:**
- Uses `extern "C"` calling conventions
- No name mangling
- Predictable memory layout
- Stable across compiler versions

### 3. C++ Fuzzer Library

The user-facing layer that integrates with C++ target code.

**Responsibilities:**
- Wrap LibAFL fuzzer functions in a C++-friendly API
- Accept function pointers to target C++ code
- Route fuzzer-generated inputs to the correct target functions
- Support both `std` and `no_std` C++ environments
- Provide a simple, ergonomic interface for C++ developers

**Environment Support:**
- **std environment**: Full standard library support, dynamic allocation, exception handling
- **no_std environment**: Minimal runtime, suitable for embedded systems, bare-metal, or kernel code

## Data Flow Between Layers

The fuzzing process flows through the layers as follows:

```
┌─────────────────────────────────────────┐
│   Rust/LibAFL Fuzzing Engine           │
│   - Input generation                    │
│   - Corpus management                   │
│   - Coverage feedback                   │
└──────────────┬──────────────────────────┘
               │
               │ Fuzzer input (bytes)
               ▼
┌─────────────────────────────────────────┐
│   C ABI Compatibility Layer             │
│   - extern "C" functions                │
│   - Data marshalling                    │
│   - Stable interface                    │
└──────────────┬──────────────────────────┘
               │
               │ C-compatible function call
               ▼
┌─────────────────────────────────────────┐
│   C++ Fuzzer Library                    │
│   - Function pointer management         │
│   - Input routing                       │
│   - Environment abstraction             │
└──────────────┬──────────────────────────┘
               │
               │ Invokes user function pointer
               ▼
┌─────────────────────────────────────────┐
│   Target C++ Code                       │
│   - User-defined functions to fuzz      │
│   - Can be std or no_std                │
└─────────────────────────────────────────┘
```

## Component Responsibilities

### Rust Library (Core Engine)

The Rust component is responsible for:

1. **Input Generation**: Using LibAFL's mutation strategies and input generators to create test cases
2. **Fuzzing Loop**: Managing the main fuzzing loop, deciding when to mutate, when to execute targets
3. **Feedback Collection**: Gathering coverage information and other feedback from target execution
4. **Corpus Management**: Maintaining and evolving the corpus of interesting inputs
5. **C Interface Exposure**: Providing C-compatible functions that the C++ layer can call

### C++ Library (Core Driver)

The C++ component is responsible for:

1. **API Surface**: Providing a clean, idiomatic C++ API for users to integrate fuzzing
2. **Function Pointer Management**: Accepting and storing function pointers to target C++ functions
3. **Input Routing**: Receiving fuzzer inputs from the C ABI layer and routing them to the appropriate target function
4. **Environment Abstraction**: Abstracting away differences between std and no_std environments
5. **Integration Utilities**: Providing helper functions for common fuzzing patterns

### C ABI Layer (Compatibility Bridge)

The C ABI layer is responsible for:

1. **Interface Stability**: Providing a stable interface that won't change with compiler updates
2. **Type Translation**: Converting between Rust types and C-compatible types
3. **Calling Convention**: Ensuring correct calling conventions between Rust and C++
4. **Memory Safety**: Managing ownership and lifetime of data passed across the boundary

## Function Pointer Mechanism

The function pointer mechanism is central to PeelFuzz's design, allowing users to specify arbitrary C++ functions to fuzz.

### How It Works

1. **Registration**: The user provides a function pointer to their target C++ function
   ```cpp
   void my_target_function(const uint8_t* data, size_t size);
   // Register with PeelFuzz
   peelfuzz::register_target(my_target_function);
   ```

2. **Storage**: The C++ library stores this function pointer and associates it with fuzzing configuration

3. **Input Generation**: The Rust/LibAFL engine generates fuzzer inputs (byte arrays)

4. **Cross-ABI Transfer**: Inputs are passed through the C ABI layer as raw pointers and sizes

5. **Invocation**: The C++ library receives the input and invokes the registered function pointer
   ```cpp
   // Inside PeelFuzz C++ library
   (*target_function)(fuzzer_input_data, fuzzer_input_size);
   ```

6. **Feedback**: Execution results (crashes, coverage, etc.) flow back through the layers to LibAFL

### Benefits of This Approach

- **Flexibility**: Users can fuzz any function that matches the signature
- **Non-intrusive**: No need to modify target code
- **Type Safety**: C++ type system enforced at registration time
- **Performance**: Function pointer invocation is extremely fast

## Environment Support

### std Environment

In standard C++ environments, PeelFuzz can leverage:

- Dynamic memory allocation (`new`, `delete`, `std::vector`, etc.)
- Standard library containers and algorithms
- Exception handling
- RTTI (Run-Time Type Information)
- File I/O and system calls
- Threading and synchronization primitives

**Use Cases:**
- Application-level code fuzzing
- Library fuzzing with full standard library support
- Complex data structure fuzzing

### no_std Environment

In no_std environments, PeelFuzz operates without the C++ standard library:

- No dynamic allocation (or custom allocators only)
- No exceptions (must use error codes or `noexcept`)
- No RTTI
- No standard library dependencies
- Minimal runtime requirements

**Use Cases:**
- Embedded systems fuzzing
- Kernel code fuzzing
- Bare-metal firmware fuzzing
- Safety-critical systems where standard library is prohibited
- Bootloader and driver fuzzing

## Design Rationale

### Why LibAFL?

1. **Performance**: Written in Rust with performance as a first-class concern
2. **Modularity**: Flexible architecture allows customization for different use cases
3. **Modern Features**: Supports latest fuzzing techniques (structure-aware fuzzing, feedback-driven mutation, etc.)
4. **Cross-platform**: Works on multiple operating systems and architectures
5. **Active Development**: Well-maintained with regular updates

### Why C ABI Layer is Necessary

1. **ABI Stability**: Rust's ABI is unstable and can change between compiler versions
2. **Language Interop**: C is the universal language for FFI (Foreign Function Interface)
3. **Predictability**: C calling conventions are well-defined and stable
4. **Toolchain Independence**: C ABI works regardless of Rust or C++ compiler versions
5. **Safety**: Provides clear boundary for ownership and lifetime management

### Benefits of This Architecture

1. **Best of Both Worlds**: Combines Rust's memory safety and LibAFL's power with C++'s ubiquity
2. **Minimal Target Modification**: C++ code can be fuzzed with minimal changes
3. **Environment Flexibility**: Same fuzzer works in std and no_std contexts
4. **Maintainability**: Clear separation of concerns across layers
5. **Extensibility**: Easy to add new features at the appropriate layer
6. **Performance**: Minimal overhead from cross-language calls
7. **Safety**: Rust's memory safety for the fuzzing engine, with controlled interaction with C++

## Future Considerations

- **Custom Feedback Mechanisms**: Allow C++ code to provide custom feedback to LibAFL
- **Structure-Aware Fuzzing**: Support for fuzzing with structured inputs (protobuf, JSON, etc.)
- **Parallel Fuzzing**: Multi-process or multi-threaded fuzzing campaigns
- **Snapshot/Restore**: Fast reset mechanisms for stateful fuzzing
- **Coverage Instrumentation**: Multiple coverage tracking strategies (edge coverage, path coverage, etc.)
- **Integration with Sanitizers**: ASan, MSan, UBSan integration for better bug detection

## Conclusion

PeelFuzz's three-layer architecture provides a robust, flexible solution for fuzzing C++ code in any environment. By carefully bridging Rust's LibAFL with C++ through a stable C ABI, PeelFuzz enables developers to leverage state-of-the-art fuzzing technology regardless of their deployment constraints.
