CXX=clang++
# -O2 for better performance (or -O3 for maximum speed)
# Remove -g for release builds (debug symbols slow things down)
CXXFLAGS=-std=c++17 -O3 -fno-omit-frame-pointer \
  -fsanitize=address,undefined \
  -fsanitize=fuzzer-no-link \
  -fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp

SRC=bug1.cpp
EXE=bug1

PEELFUZZ_LIB=../../Release/libPeelFuzz.a


default:
	$(CXX) $(CXXFLAGS) $(SRC) -o $(EXE) \
	  $(PEELFUZZ_LIB) -pthread -ldl -lm

run:
	./$(EXE)
