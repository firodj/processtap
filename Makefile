CFLAGS = -Wall `python-config --includes`
LDFLAGS = `python-config --libs`

all: processtap_pin.so

## processtap api
processtap.o: processtap.c processtap.h
	$(CC) $(CFLAGS) -fPIC -c -o processtap.o processtap.c

bloomfilter.o: bloomfilter.c bloomfilter.h
	$(CC) $(CFLAGS) -fPIC -c -o bloomfilter.o bloomfilter.c

## pin
TARGET_COMPILER = gnu
INCL = ./include
PIN_KIT = ./pin-2.8-33586-gcc.3.4.6-ia32_intel64-linux
PIN_HOME = $(PIN_KIT)/source/tools
include $(PIN_HOME)/makefile.gnu.config
CXXFLAGS = -I$(INCL) -Werror $(DBG) $(OPT) -MMD

processtap_pin.o : processtap_pin.cc processtap.h
	${CXX} ${COPT} $(CXXFLAGS) ${PIN_CXXFLAGS} ${OUTOPT}$@ $<

processtap_pin$(PINTOOL_SUFFIX) : processtap_pin.o processtap.o bloomfilter.o $(PIN_LIBNAMES)
	${CXX} $(PIN_LDFLAGS) $(LINK_DEBUG) processtap_pin.o processtap.o bloomfilter.o ${LINK_OUT}$@ \
		${PIN_LPATHS} $(PIN_LIBS) $(EXTRA_LIBS) $(DBG) $(LDFLAGS)

clean:
	rm -f processtap.o bloomfilter.o processtap_pin.o processtap_pin.d

clean-all: clean
	rm -f processtap_pin$(PINTOOL_SUFFIX)

.PHONY: clean clean-all
