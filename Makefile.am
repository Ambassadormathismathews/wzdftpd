
SUBDIRS = ac-helpers m4 src backends modules tools init.d doc man

bin_SCRIPTS = wzd-config

m4macrodir = $(datadir)/aclocal
m4macro_DATA = wzd.m4

EXTRA_DIST = bootstrap \
	Permissions.ReadMeFirst \
	TLS.ReadMeFirst wzd_tls.cnf \
	$(m4macro_DATA)

#check_symlinks:
#	(cd src && make check_symlinks) || exit 1


