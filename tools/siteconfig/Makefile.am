
INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src

bin_PROGRAMS = siteconfig

siteconfig_SOURCES = siteconfig.c

siteconfig_LDFLAGS = @SSL_LDFLAGS@ -no-undefined -L../../src/ -lwzd @DL_FLAGS@

AM_CPPFLAGS = -DSSL_SUPPORT=1
