
#libexecdir = ${pkgdatadir}/backends
libdir = ${pkgdatadir}/backends

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src

#libexec_LTLIBRARIES = libwzdplaintext.la
lib_LTLIBRARIES = libwzdplaintext.la

libwzdplaintext_la_SOURCES = libplaintext_main.c
libwzdplaintext_la_LDFLAGS = -no-undefined -avoid-version -module $(WZD_SSL_LIBS) @CRYPT_FLAGS@ @PTHREAD_CFLAGS@ @PTHREAD_LIBS@

AM_CPPFLAGS = $(WZD_SSL_INCLUDES)
