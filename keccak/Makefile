# Dedicated to the Public Domain under the Unlicense: https://unlicense.org/UNLICENSE

all:		# Default Rule

MAYBE_CLANG	!= clang++ --version 2>/dev/null | grep -q 'clang.* [1-9][0-9]\+\.' && echo clang++
CXX		:= $(if $(MAYBE_CLANG), $(MAYBE_CLANG), $(CXX))
OPTIMIZE	:= -O3 -march=native

# == keccak ==
keccak: main.cc Makefile
	$(CXX) -std=gnu++17 -Wall $(OPTIMIZE) $< -o keccak
keccak: keccak.hh keccak.cc
clean: ; rm -f ./keccak
all: keccak

# == check ==
check: keccak
	./keccak --check

# == dieharder ==
dieharder: keccak
	./keccak | dieharder -a -g 200
