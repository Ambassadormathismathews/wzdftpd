
#libexecdir = ${pkgdatadir}/modules
libdir = ${pkgdatadir}/modules

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src

if USE_ZLIB
EXTRA_ZLIB = -lz
endif

#libexec_LTLIBRARIES = libwzd_sfv.la
lib_LTLIBRARIES = libwzd_sfv.la

libwzd_sfv_la_SOURCES = libwzd_sfv.c libwzd_sfv_zip.c libwzd_sfv_zip.h
libwzd_sfv_la_LDFLAGS = -no-undefined -avoid-version -module -L../../src/ -L../../src/.libs/ -lwzd $(EXTRA_ZLIB)
