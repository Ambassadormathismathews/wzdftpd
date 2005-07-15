
#libexecdir = ${pkgdatadir}/modules
libdir = ${pkgdatadir}/modules

INCLUDES = -I$(top_srcdir)

if USE_ZLIB
EXTRA_ZLIB = -lz
endif

#libexec_LTLIBRARIES = libwzd_sfv.la
lib_LTLIBRARIES = libwzd_sfv.la

libwzd_sfv_la_SOURCES = libwzd_sfv.c libwzd_sfv.h libwzd_sfv_zip.c libwzd_sfv_zip.h
libwzd_sfv_la_LIBADD = ../../libwzd-core/libwzd_core.la
libwzd_sfv_la_LDFLAGS = -no-undefined -avoid-version -module $(EXTRA_ZLIB) $(WZD_SSL_LIBS) @CRYPT_FLAGS@ @PTHREAD_CFLAGS@ @PTHREAD_LIBS@
