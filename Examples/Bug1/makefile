CXX=clang++
CXXFLAGS=-std=c++17 -O1 -g -fno-omit-frame-pointer \
  -fsanitize=fuzzer-no-link \
  -fsanitize-coverage=trace-pc-guard

DRIVER_LIB=../../Release/Driver/libdriver.a
RUST_LIB=../../Engine/target/release/libPeelFuzz.a


default:
	$(CXX) $(CXXFLAGS) bug1.cpp -o bug1 \
	  $(DRIVER_LIB) $(RUST_LIB) -pthread -ldl -lm

run:
	./bug1
