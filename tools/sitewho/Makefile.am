
INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src

bin_PROGRAMS = sitewho

sitewho_SOURCES = sitewho.c

sitewho_LDFLAGS = @SSL_LDFLAGS@

AM_CPPFLAGS = -DSSL_SUPPORT=1
