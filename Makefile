# This Source Code Form is licensed MPL-2.0: http://mozilla.org/MPL/2.0

all:		# Default Rule

SUBDIRS	:= keccak chacha shishua

all clean check:
	 @ true $(foreach DIR, $(SUBDIRS), && $(MAKE) -C "$(DIR)" "$@" )
