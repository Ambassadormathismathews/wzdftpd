
#libexecdir = ${pkgdatadir}/modules
libdir = ${pkgdatadir}/modules

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src

#libexec_LTLIBRARIES = libwzd_sfv.la
lib_LTLIBRARIES = libwzd_sfv.la

libwzd_sfv_la_SOURCES = libwzd_sfv.c
libwzd_sfv_la_LDFLAGS = -no-undefined -avoid-version -module -L../../src/ -L../../src/.libs/ -lwzd 
