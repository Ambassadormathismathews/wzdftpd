AUTOMAKE_OPTIONS = 1.5  # Require Automake 1.5 or better.

if HAVE_PERL
  MAYBE_PERL = libwzd-perl
endif

SUBDIRS = ac-helpers m4 libwzd-base libwzd-auth libwzd-core wzdftpd libwzd backends modules $(MAYBE_PERL) tools init.d doc man redhat tests

bin_SCRIPTS = wzd-config

m4macrodir = $(datadir)/aclocal
m4macro_DATA = wzd.m4

EXTRA_DIST = bootstrap \
	Permissions.ReadMeFirst \
	TLS.ReadMeFirst wzd_tls.cnf UPGRADING \
	$(m4macro_DATA)

doxy:
	doxygen doxygen.cfg


