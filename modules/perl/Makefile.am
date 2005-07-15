
libdir = ${pkgdatadir}/modules

INCLUDES = -I$(top_srcdir) $(WZD_PERL_INCLUDES)

lib_LTLIBRARIES = libwzd_perl.la

libwzd_perl_la_SOURCES = libwzd_perl.c
libwzd_perl_la_LIBADD = ../../libwzd-core/libwzd_core.la
libwzd_perl_la_LDFLAGS = -no-undefined -avoid-version -module $(WZD_PERL_LIBS) $(WZD_SSL_LIBS) @CRYPT_FLAGS@ @PTHREAD_CFLAGS@ @PTHREAD_LIBS@
