ALL_SGML_FILES=commands_reference.sgml common_backends.sgml common_modules.sgml \
	cookies_reference.sgml introduction.sgml sitebot.sgml license.sgml \
	faq.sgml wzdftpd.sgml config.sgml appendix_bugs.sgml \
	programming_modules.sgml freebsd_notes.sgml custom_commands.sgml \
	appendix_ref.sgml
HTML_DEPS=html_head.html html_tail.html
MAIN_SGML_FILE=wzdftpd.sgml
EXAMPLES=zip_simple.tcl zip_simple.pl

JW = @JW@

if HAVE_JW

all: html

html: wzdftpd-doc/index.html
php: wzdftpd-doc/index.php

pdf: wzdftpd-doc/wzdftpd.pdf

html-online: html
	./fix_css.sh wzdftpd-doc

php-online: php
	./fix_css.sh wzdftpd-doc

wzdftpd-doc/index.php: $(ALL_SGML_FILES) $(HTML_DEPS) $(EXAMPLES) wzd_custom.dsl
	$(JW) -d wzd_custom.dsl#php -o wzdftpd-doc -b html $(MAIN_SGML_FILE)

wzdftpd-doc/index.html: $(ALL_SGML_FILES) $(HTML_DEPS) $(EXAMPLES) wzd_custom.dsl
	if [ ! -d wzdftpd-doc ]; then mkdir wzdftpd-doc; fi; \
	$(JW) -d wzd_custom.dsl#html -o wzdftpd-doc -b html $(MAIN_SGML_FILE)

wzdftpd-doc/wzdftpd.pdf: $(ALL_SGML_FILES) $(EXAMPLES)
	if [ ! -d wzdftpd-doc ]; then mkdir wzdftpd-doc; fi; \
	$(JW) -o wzdftpd-doc -b pdf $(MAIN_SGML_FILE)

clean:
	rm -f wzdftpd-doc/*.html wzdftpd-doc/*.php wzdftpd-doc/*.pdf wzdftpd-doc/*.out

distclean: clean

endif

EXTRA_DIST = $(ALL_SGML_FILES) $(HTML_DEPS) $(MAIN_SGML_FILE) $(EXAMPLES) fix_css.sh add_header_footer.pl wzd_custom.dsl
