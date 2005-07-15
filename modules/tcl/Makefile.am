
libdir = ${pkgdatadir}/modules

INCLUDES = -I$(top_srcdir) $(WZD_TCL_INCLUDES)

lib_LTLIBRARIES = libwzd_tcl.la

libwzd_tcl_la_SOURCES = libwzd_tcl.c
libwzd_tcl_la_LIBADD = ../../libwzd-core/libwzd_core.la
libwzd_tcl_la_LDFLAGS = -no-undefined -avoid-version -module $(WZD_TCL_LIBS) $(WZD_SSL_LIBS) @CRYPT_FLAGS@ @PTHREAD_CFLAGS@ @PTHREAD_LIBS@
