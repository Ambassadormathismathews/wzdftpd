
libdir = ${pkgdatadir}/modules

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src $(WZD_TCL_INCLUDES)

lib_LTLIBRARIES = libwzd_tcl.la

libwzd_tcl_la_SOURCES = libwzd_tcl.c
libwzd_tcl_la_LDFLAGS = -no-undefined -avoid-version -module -L../../src/ -L../../src/.libs/ -lwzd $(WZD_TCL_LIBS)
