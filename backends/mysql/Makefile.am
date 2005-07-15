libdir = ${pkgdatadir}/backends

INCLUDES = -I$(top_srcdir) $(WZD_MYSQL_INCLUDES) $(WZD_SSL_INCLUDES)

#libexec_LTLIBRARIES = libwzdplaintext.la
lib_LTLIBRARIES = libwzdmysql.la

EXTRA_DIST = libmysql.h tables.sql dropall.sql UPGRADING

#libwzdmysql_la_HEADERS = libmysql.h
libwzdmysql_la_SOURCES = libmysql_main.c libmysql_user.c libmysql_group.c
libwzdmysql_la_LDFLAGS = -no-undefined -avoid-version -module $(WZD_SSL_LIBS) @CRYPT_FLAGS@ $(WZD_MYSQL_LIBS) -lm -export-symbols-regex wzd_

