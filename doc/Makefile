ALL_SGML_FILES=commands_reference.sgml common_backends.sgml common_modules.sgml \
	cookies_reference.sgml introduction.sgml sitebot.sgml license.sgml \
	faq.sgml wzdftpd.sgml config.sgml appendix_bugs.sgml \
	programming_modules.sgml
MAIN_SGML_FILE=wzdftpd.sgml

all: html

html: wzdftpd-doc/index.html

pdf: wzdftpd-doc/wzdftpd.pdf

wzdftpd-doc/index.html: $(ALL_SGML_FILES)
	jw -o wzdftpd-doc -b html $(MAIN_SGML_FILE)

wzdftpd-doc/wzdftpd.pdf: $(ALL_SGML_FILES)
	jw -o wzdftpd-doc -b pdf $(MAIN_SGML_FILE)

clean:
	@rm -f wzdftpd-doc/*.html wzdftpd-doc/*.pdf wzdftpd-doc/*.out

distclean: clean
