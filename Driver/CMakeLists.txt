add_library(driver 
  STATIC 
  fuzzer.cpp
)

target_link_libraries(driver
  PRIVATE
  "${CMAKE_SOURCE_DIR}/Engine/target/release/libPeelFuzz.a"
)
