
LIBWZD_CURRENT=1
LIBWZD_REVISION=1
LIBWZD_AGE=0

LT_VERSION_INFO=${LIBWZD_CURRENT}:${LIBWZD_REVISION}:${LIBWZD_AGE}

lib_LTLIBRARIES = libwzd.la

libwzd_ladir = ${prefix}/include/wzdftpd

libwzd_la_HEADERS = \
	libwzd.h

libwzd_la_SOURCES = \
	${libwzd_la_HEADERS} \
	libwzd.c

libwzd_la_LDFLAGS = @PTHREAD_CFLAGS@ @PTHREAD_LIBS@ -version-info ${LT_VERSION_INFO} -module -no-undefined

AM_CPPFLAGS = $(WZD_SSL_INCLUDES) -DWZD_MULTITHREAD -D_REENTRANT @PTHREAD_CFLAGS@
