# Dedicated to the Public Domain under the Unlicense: https://unlicense.org/UNLICENSE

all:		# Default Rule

MAYBE_CLANG	!= clang++ --version 2>/dev/null | grep -q 'clang.* [1-9][0-9]\+\.' && echo clang++
CXX		:= $(if $(MAYBE_CLANG), $(MAYBE_CLANG), $(CXX))
OPTIMIZE	:= -O3 \
		-ffast-math -fno-finite-math-only -funroll-loops -ftree-vectorize -minline-all-stringops -march=native -fno-strict-overflow -fno-strict-aliasing \
		-march=native # -march=x86-64-v3 -march=x86-64-v2 -march=x86-64

# == mwc256 ==
mwc256: main.cc Makefile
	$(CXX) -std=gnu++17 -Wall $(OPTIMIZE) $< -o mwc256
mwc256: mwc256.hh
clean: ; rm -f ./mwc256
all: mwc256

# == check ==
check: mwc256
	./mwc256 --check

# == dieharder ==
dieharder: mwc256
	./mwc256 | dieharder -a -g 200
