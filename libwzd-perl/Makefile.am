
EXTRA_DIST = ext/Makefile.PL.in ext/ppport.h ext/wzdftpd.pm ext/wzdftpd.xs

ext: ext/Makefile ext/wzdftpd.pm ../libwzd/libwzd.la
	cd ext && $(MAKE)

ext/Makefile: ext/Makefile.PL ext/wzdftpd.pm ext/wzdftpd.xs
	cd ext && $(PERL) Makefile.PL $(PERLFLAGS) $(PERL_MAKE_OPTIONS)


all-local: ext

install-data-local: all-local
	echo "Installing wzdftpd.pm"; \
	cd ext && $(MAKE) install PREFIX=${e_prefix} SITEPREFIX=${e_prefix}

clean-local:
	cd ext && test -f Makefile && $(MAKE) clean || true \
	cd ext && rm -f Makefile.old
