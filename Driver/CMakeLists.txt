add_library(driver
  OBJECT
  fuzzer.cpp
)

target_include_directories(driver PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
