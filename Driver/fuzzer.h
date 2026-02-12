#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {
  typedef void(*CTargetFn)(const uint8_t* data, size_t len);
  void fuzz_byte_size(CTargetFn target_fn);
}

typedef void(*wrapFn)(int input);

void fuzz_wrap(wrapFn target);
