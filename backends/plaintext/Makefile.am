
#libexecdir = ${pkgdatadir}/backends
libdir = ${pkgdatadir}/backends

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src

#libexec_LTLIBRARIES = libwzdplaintext.la
lib_LTLIBRARIES = libwzdplaintext.la

libwzdplaintext_la_SOURCES = libplaintext_main.c
libwzdplaintext_la_LDFLAGS = -no-undefined -avoid-version -module @CRYPT_FLAGS@
