libdir = ${pkgdatadir}/backends

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src $(WZD_PAM_INCLUDES)

lib_LTLIBRARIES = libwzdpam.la

libwzdpam_la_SOURCES = libpam_main.c
libwzdpam_la_LDFLAGS = -no-undefined -avoid-version -module @CRYPT_FLAGS@ $(WZD_PAM_LIBS) -lm

