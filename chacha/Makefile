# This Source Code Form is licensed MPL-2.0: http://mozilla.org/MPL/2.0

all:		# Default Rule

MAYBE_CLANG	!= clang++ --version 2>/dev/null | grep -q 'clang.* [1-9][0-9]\+\.' && echo clang++
CXX		:= $(if $(MAYBE_CLANG), $(MAYBE_CLANG), $(CXX))
OPTIMIZE	:= -O3 -march=native

# == chacha ==
chacha: main.cc Makefile
	$(CXX) -std=gnu++17 -Wall $(OPTIMIZE) $< -o chacha
chacha: chacha.cc chacha.hh
clean: ; rm -f ./chacha
all: chacha

# == check ==
check: chacha
	./chacha --check

# == dieharder ==
dieharder: chacha
	./chacha | dieharder -a -g 200
