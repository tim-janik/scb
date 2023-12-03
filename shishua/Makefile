# This Source Code Form is licensed MPL-2.0: http://mozilla.org/MPL/2.0

all:		# Default Rule

MAYBE_CLANG	!= clang++ --version 2>/dev/null | grep -q 'clang.* [1-9][0-9]\+\.' && echo clang++
CXX		:= $(if $(MAYBE_CLANG), $(MAYBE_CLANG), $(CXX))
OPTIMIZE	:= -O3 -march=native # -march=x86-64-v3 -march=x86-64-v2 -march=x86-64

# == shishua ==
shishua: main.cc Makefile
	$(CXX) -std=gnu++17 -Wall $(OPTIMIZE) $< -o shishua
shishua: shishua.cc shishua.hh shishua-sse2.hh shishua-avx2.hh
clean: ; rm -f ./shishua
all: shishua

# == check ==
check: shishua
	./shishua --check

# == dieharder ==
dieharder: shishua
	./shishua | dieharder -a -g 200
