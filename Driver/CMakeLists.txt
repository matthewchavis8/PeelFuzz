# Header-only library - all implementation is in the Rust Engine
add_library(driver INTERFACE)

target_include_directories(driver INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
