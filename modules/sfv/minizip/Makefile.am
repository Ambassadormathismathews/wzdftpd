noinst_LTLIBRARIES = libminizip.la

if USE_ZLIB
EXTRA_ZLIB = -lz
endif

libminizip_la_SOURCES = \
	crypt.h \
	ioapi.c \
	ioapi.h \
	unzip.c \
	unzip.h 

libminizip_la_CFLAGS = $(EXTRA_ZLIB)

