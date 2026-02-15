cmake_minimum_required(VERSION 3.20)

project(
  PeelFuzz
  VERSION 0.0.1
  LANGUAGES CXX
)

if(NOT DEFINED CMAKE_CXX_STANDARD)
	set(CMAKE_CXX_STANDARD 17)
endif()

# Export ClangD
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- Rust engine (cargo build) ---
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CARGO_PROFILE "debug")
  set(CARGO_FLAGS "")
else()
  set(CARGO_PROFILE "release")
  set(CARGO_FLAGS "--release")
endif()

set(RUST_LIB "${CMAKE_SOURCE_DIR}/Engine/target/${CARGO_PROFILE}/libPeelFuzz.a")

add_custom_command(
  OUTPUT ${RUST_LIB}
  COMMAND cargo build ${CARGO_FLAGS}
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/Engine"
  COMMENT "Building Rust engine (${CARGO_PROFILE})"
)

add_custom_target(rust_engine DEPENDS ${RUST_LIB})

# --- C++ Driver (object library) ---
add_subdirectory(Driver)

# --- Copy Rust library as final libPeelFuzz.a ---
# (Driver is header-only, no objects to merge)
set(MERGED_LIB "${CMAKE_BINARY_DIR}/libPeelFuzz.a")

add_custom_command(
  OUTPUT ${MERGED_LIB}
  COMMAND ${CMAKE_COMMAND} -E copy "${RUST_LIB}" "${MERGED_LIB}"
  DEPENDS rust_engine driver
  COMMENT "Creating libPeelFuzz.a (Rust Engine + header-only Driver)"
)

add_custom_target(PeelFuzz ALL DEPENDS ${MERGED_LIB})
