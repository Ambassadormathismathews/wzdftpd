
libdir = ${pkgdatadir}/modules

AM_CFLAGS = $(WZD_AVAHI_CFLAGS) $(WZD_HOWL_CFLAGS)
INCLUDES = -I$(top_srcdir)

lib_LTLIBRARIES = libwzd_zeroconf.la

libwzd_zeroconf_la_SOURCES = libwzd_zeroconf.c libwzd_zeroconf.h
libwzd_zeroconf_la_LIBADD = ../../libwzd-core/libwzd_core.la
libwzd_zeroconf_la_LDFLAGS = -no-undefined -avoid-version -module $(WZD_HOWL_LIBS) $(WZD_AVAHI_LIBS) @PTHREAD_CFLAGS@ @PTHREAD_LIBS@
