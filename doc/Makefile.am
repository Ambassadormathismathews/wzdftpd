DOC_XML_FILES=commands_reference.sgml common_backends.sgml common_modules.sgml \
	cookies_reference.sgml introduction.sgml sitebot.sgml license.sgml \
	faq.sgml wzdftpd.sgml config.sgml appendix_bugs.sgml \
	programming_modules.sgml freebsd_notes.sgml custom_commands.sgml \
	appendix_ref.sgml authentication.sgml
DEV_XML_FILES = dev-architecture.xml dev-memory.xml
HTML_DEPS=html_head.html html_tail.html
DOC_MAIN_XML_FILE=wzdftpd.sgml
DEV_MAIN_XML_FILE = wzdftpd-dev.xml
EXAMPLES=zip_simple.tcl zip_simple.pl

JW = @JW@

if HAVE_JW

all: html

html: wzdftpd-doc/index.html wzdftpd-dev/index.html
php: wzdftpd-doc/index.php

pdf: wzdftpd-doc/wzdftpd.pdf wzdftpd-dev/wzdftpd-dev.pdf

html-online: html
	./fix_css.sh wzdftpd-doc

php-online: php
	./fix_css.sh wzdftpd-doc

wzdftpd-doc/index.php: $(DOC_MAIN_XML_FILE) $(DOC_XML_FILES) $(HTML_DEPS) $(EXAMPLES) wzd_custom.dsl
	$(JW) -d $(srcdir)/wzd_custom.dsl#php -o wzdftpd-doc -b html $(srcdir)/$(DOC_MAIN_XML_FILE)

wzdftpd-doc/index.html: $(DOC_MAIN_XML_FILE) $(DOC_XML_FILES) $(HTML_DEPS) $(EXAMPLES) wzd_custom.dsl
	if [ ! -d wzdftpd-doc ]; then mkdir wzdftpd-doc; fi; \
	$(JW) -d $(srcdir)/wzd_custom.dsl#html -o wzdftpd-doc -b html $(srcdir)/$(DOC_MAIN_XML_FILE)

wzdftpd-doc/wzdftpd.pdf: $(DOC_MAIN_XML_FILE) $(DOC_XML_FILES) $(EXAMPLES)
	if [ ! -d wzdftpd-doc ]; then mkdir wzdftpd-doc; fi; \
	$(JW) -o wzdftpd-doc -b pdf $(srcdir)/$(DOC_MAIN_XML_FILE)

wzdftpd-dev/index.html: $(DEV_MAIN_XML_FILE) $(DEV_XML_FILES) $(HTML_DEPS) $(EXAMPLES) wzd_custom.dsl
	if [ ! -d wzdftpd-dev ]; then mkdir wzdftpd-dev; fi; \
	$(JW) -d $(srcdir)/wzd_custom.dsl#html -o wzdftpd-dev -b html $(srcdir)/$(DEV_MAIN_XML_FILE)

wzdftpd-dev/wzdftpd-dev.pdf: $(DEV_MAIN_XML_FILE) $(DEV_XML_FILES) $(EXAMPLES)
	if [ ! -d wzdftpd-dev ]; then mkdir wzdftpd-dev; fi; \
	$(JW) -o wzdftpd-dev -b pdf $(srcdir)/$(DEV_MAIN_XML_FILE)

clean-local:
	rm -f wzdftpd-doc/*.html wzdftpd-doc/*.php wzdftpd-doc/*.pdf wzdftpd-doc/*.out
	rm -f wzdftpd-dev/*.html wzdftpd-dev/*.php wzdftpd-dev/*.pdf wzdftpd-dev/*.out

else

clean-local:

endif

EXTRA_DIST = $(DOC_MAIN_XML_FILE) $(DOC_XML_FILES)$ $(DEV_MAIN_XML_FILE) $(DEV_XML_FILES) $(HTML_DEPS) $(EXAMPLES) fix_css.sh add_header_footer.pl wzd_custom.dsl
