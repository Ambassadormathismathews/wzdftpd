#EDIT ME !
SSL_SUPPORT=1


ifeq ($(PLATFORM),Linux)
CC=gcc-3.2
else
CC=gcc
endif
CFLAGS=-g -I../../src -Wall -Wstrict-prototypes -DSSL_SUPPORT=${SSL_SUPPORT}
#LDFLAGS=-L../../src -lwzd -ldl -Wl,-rpath,../../src

all: sitewho

debug: sitewho
release: sitewho

clean:
	@rm -f sitewho.o

distclean: clean
	@rm -f sitewho

sitewho: sitewho.o

sitewho.o: sitewho.c
