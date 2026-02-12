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

# Adding subdirectories
add_subdirectory(Driver)

# create a static lib
add_library(PeelFuzz STATIC
  peelfuzz.cpp
)

# link to other static libs
target_link_libraries(PeelFuzz
  PUBLIC
  driver
)
