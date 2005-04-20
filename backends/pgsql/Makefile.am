libdir = ${pkgdatadir}/backends

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src -I$(top_srcdir)/libwzd-base $(WZD_PGSQL_INCLUDES) $(WZD_SSL_INCLUDES)

lib_LTLIBRARIES = libwzdpgsql.la

EXTRA_DIST = libpgsql.h

libwzdpgsql_la_SOURCES = libpgsql_main.c libpgsql_user.c libpgsql_group.c
libwzdpgsql_la_LDFLAGS = -no-undefined -avoid-version -module $(WZD_SSL_LIBS) @CRYPT_FLAGS@ $(WZD_PGSQL_LIBS) -lm -export-symbols-regex wzd_

