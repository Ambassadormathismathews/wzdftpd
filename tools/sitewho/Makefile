include ../../src/Makefile.config


ifeq ($(PLATFORM),Linux)
CC=gcc-3.2
else
CC=gcc
endif
CFLAGS=-g -I../../src -Wall -Wstrict-prototypes -DSSL_SUPPORT=${SSL_SUPPORT}
#LDFLAGS=-L../../src -lwzd -ldl -lpthread -Wl,-rpath,../../src  -Wl,-rpath,.

all: sitewho

debug: sitewho
release: sitewho

install: release
	install --mode=755 sitewho $(DESTDIR)/tools

installdebug: debug
	install --mode=755 sitewho $(DESTDIR)-debug/tools

uninstall: release
	rm -f $(DESTDIR)/tools/sitewho

clean:
	@rm -f sitewho.o

distclean: clean
	@rm -f sitewho

sitewho: sitewho.o

sitewho.o: sitewho.c
