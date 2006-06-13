
noinst_LTLIBRARIES = libwzd_auth.la

libwzd_auth_ladir = ${prefix}/include/wzdftpd/libwzd-auth

INCLUDES = -I$(top_srcdir) $(WZD_PAM_INCLUDES) $(WZD_SSL_INCLUDES) $(WZD_KRB5_INCLUDES)

libwzd_auth_la_HEADERS = \
	wzd_auth.h \
	wzd_base64.h \
	wzd_crypt.h \
	wzd_krb5.h \
	wzd_md5.h \
	wzd_md5crypt.h \
	wzd_pam.h \
	wzd_sha1.h \
	wzd_tls.h

libwzd_auth_la_SOURCES = \
	wzd_auth.c \
	wzd_base64.c \
	wzd_crypt.c \
	wzd_krb5.c \
	wzd_md5.c \
	wzd_md5crypt.c \
	wzd_pam.c \
	wzd_sha1.c \
	wzd_sha1_hash.c \
	wzd_tls.c

libwzd_auth_la_LDFLAGS = $(WZD_PAM_LIBS) $(WZD_SSL_LIBS) $(WZD_KRB5_LIBS)
