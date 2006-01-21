
libdir = ${pkgdatadir}/modules

INCLUDES = -I$(top_srcdir) $(WZD_PERL_INCLUDES)

lib_LTLIBRARIES = libwzd_debug.la

libwzd_debug_la_SOURCES = libwzd_debug.c \
	debug_commands.c debug_commands.h \
	debug_modules.c debug_modules.h
libwzd_debug_la_LIBADD = ../../libwzd-core/libwzd_core.la
libwzd_debug_la_LDFLAGS = -no-undefined -avoid-version -module $(WZD_SSL_LIBS) @CRYPT_FLAGS@ @PTHREAD_CFLAGS@ @PTHREAD_LIBS@
