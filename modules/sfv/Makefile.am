SUBDIRS = minizip

#libexecdir = ${pkgdatadir}/modules
libdir = ${pkgdatadir}/modules

INCLUDES = -I$(top_srcdir)

if USE_ZLIB
EXTRA_ZLIB = -lz
endif

#libexec_LTLIBRARIES = libwzd_sfv.la
lib_LTLIBRARIES = libwzd_sfv.la

libwzd_sfv_la_SOURCES = \
	libwzd_sfv_indicators.c libwzd_sfv_indicators.h \
	libwzd_sfv_main.c libwzd_sfv_main.h \
	libwzd_sfv_sfv.c libwzd_sfv_sfv.h \
	libwzd_sfv_site.c libwzd_sfv_site.h \
	libwzd_sfv_zip.c libwzd_sfv_zip.h
libwzd_sfv_la_LIBADD = ../../libwzd-core/libwzd_core.la minizip/libminizip.la
libwzd_sfv_la_LDFLAGS = -no-undefined -avoid-version -module $(EXTRA_ZLIB) $(WZD_SSL_LIBS) @CRYPT_FLAGS@ @PTHREAD_CFLAGS@ @PTHREAD_LIBS@
