libdir = ${pkgdatadir}/backends

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src -I/usr/local/include/mysql

#libexec_LTLIBRARIES = libwzdplaintext.la
lib_LTLIBRARIES = libwzdmysql.la

libwzdmysql_la_SOURCES = libmysql_main.c
libwzdmysql_la_LDFLAGS = -no-undefined -avoid-version -module @CRYPT_FLAGS@ -L/usr/local/lib/mysql -lmysqlclient -lz -lcrypt -lm

