include ../../src/Makefile.config


ifeq ($(PLATFORM),Linux)
CC=gcc-3.2
else
CC=gcc
endif
CFLAGS=-g -I../../src -Wall -Wstrict-prototypes -DSSL_SUPPORT=${SSL_SUPPORT}
#LDFLAGS=-L../../src -lwzd -ldl -lpthread -Wl,-rpath,../../src  -Wl,-rpath,.

all: siteuptime

debug: siteuptime
release: siteuptime

install: release
	install --mode=755 siteuptime $(DESTDIR)/tools

installdebug: debug
	install --mode=755 siteuptime $(DESTDIR)-debug/tools

uninstall: release
	rm -f $(DESTDIR)/tools/siteuptime

clean:
	@rm -f siteuptime.o

distclean: clean
	@rm -f siteuptime

siteuptime: siteuptime.o

siteuptime.o: siteuptime.c
