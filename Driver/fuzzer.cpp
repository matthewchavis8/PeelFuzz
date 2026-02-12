#include "fuzzer.h"

#include <cstring>
#include <iostream>

static wrapFn target_fn = nullptr;

static void wrapper(const uint8_t* data, size_t len) {
  int input{};
  if (len < 2) {
  }
  std::memcpy(&input, data, sizeof(int));

  std::cout << "Sending " << data << '\n';
  target_fn(input);
}

void fuzz_wrap(wrapFn target) {
  target_fn = target;
  fuzz_byte_size(wrapper);
}
