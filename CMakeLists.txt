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

# --- Merge into single libPeelFuzz.a ---
set(MERGED_LIB "${CMAKE_BINARY_DIR}/libPeelFuzz.a")
set(RUST_EXTRACT_DIR "${CMAKE_BINARY_DIR}/_rust_objs")

add_custom_command(
  OUTPUT ${MERGED_LIB}
  COMMAND ${CMAKE_COMMAND} -E rm -rf "${RUST_EXTRACT_DIR}"
  COMMAND ${CMAKE_COMMAND} -E make_directory "${RUST_EXTRACT_DIR}"
  COMMAND ${CMAKE_COMMAND} -E chdir "${RUST_EXTRACT_DIR}" ar x "${RUST_LIB}"
  COMMAND sh -c "ar crs ${MERGED_LIB} ${RUST_EXTRACT_DIR}/*.o $<TARGET_OBJECTS:driver>"
  COMMAND ${CMAKE_COMMAND} -E rm -rf "${RUST_EXTRACT_DIR}"
  DEPENDS rust_engine driver
  COMMENT "Merging Rust + Driver objects into libPeelFuzz.a"
)

add_custom_target(PeelFuzz ALL DEPENDS ${MERGED_LIB})
