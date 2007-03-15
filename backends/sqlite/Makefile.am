libdir = ${pkgdatadir}/backends

INCLUDES = -I$(top_srcdir) $(WZD_SQLITE3_INCLUDES) $(WZD_SSL_INCLUDES)

#libexec_LTLIBRARIES = libwzdplaintext.la
lib_LTLIBRARIES = libwzdsqlite.la

EXTRA_DIST = 00-create_table.sql 00-create_users_and_groups.sq

#libwzdmysql_la_HEADERS = libmysql.h
libwzdsqlite_la_SOURCES = libsqlite_main.c libsqlite_user.c libsqlite_group.c
libwzdsqlite_la_LDFLAGS = -no-undefined -avoid-version -module $(WZD_SSL_LIBS) @CRYPT_FLAGS@ $(WZD_SQLITE3_LIBS) -lm -export-symbols-regex wzd_

