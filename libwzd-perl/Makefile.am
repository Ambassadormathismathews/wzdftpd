
EXTRA_DIST = ext/Makefile.PL.in ext/ppport.h ext/wzdftpd.pm ext/wzdftpd.xs

PERL_MAKE_OPTIONS = PREFIX=${e_prefix} SITEPREFIX=${e_prefix}

ext: ext/Makefile ext/wzdftpd.pm ../libwzd/libwzd.la
	cd ext && $(MAKE) LD_RUN_PATH=""

ext/Makefile: ext/Makefile.PL ext/wzdftpd.pm ext/wzdftpd.xs
	cd ext && $(PERL) Makefile.PL $(PERLFLAGS) $(PERL_MAKE_OPTIONS) INSTALLDIRS=vendor


all-local: ext

install-data-local: all-local
	echo "Installing wzdftpd.pm"; \
	cd ext && $(MAKE) install

clean-local:
	cd ext && test -f Makefile && $(MAKE) clean || true \
	cd ext && rm -f Makefile.old

## Evil Hack (TM)
#uninstall-local:
#	cd ext && \
#	  `$(MAKE) uninstall | grep unlink | sed -e 's#/usr#${prefix}#' -e 's#unlink#rm -f#'`
