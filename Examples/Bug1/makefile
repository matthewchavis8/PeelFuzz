CXX=clang++
CXXFLAGS=-std=c++17 -O1 -g -fno-omit-frame-pointer \
  -fsanitize=fuzzer-no-link \
  -fsanitize-coverage=trace-pc-guard

PEELFUZZ_LIB=../../Release/libPeelFuzz.a


default:
	$(CXX) $(CXXFLAGS) bug1.cpp -o bug1 \
	  $(PEELFUZZ_LIB) -pthread -ldl -lm

run:
	./bug1
