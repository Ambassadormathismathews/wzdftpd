
#libexecdir = ${pkgdatadir}/modules
libdir = ${pkgdatadir}/modules

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src

#libexec_LTLIBRARIES = libwzd_test.la
lib_LTLIBRARIES = libwzd_test.la

libwzd_test_la_SOURCES = libwzd_test.c
libwzd_test_la_LDFLAGS = -no-undefined -avoid-version -module -L../../src/ -lwzd 
