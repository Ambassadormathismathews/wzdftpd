ALL_SGML_FILES=commands_reference.sgml common_backends.sgml common_modules.sgml cookies_reference.sgml installation.sgml wzdFTPd.sgml
MAIN_SGML_FILE=wzdFTPd.sgml

all: html

html: wzdFTPd-doc/index.html

pdf: wzdFTPd-doc/wzdFTPd.pdf

wzdFTPd-doc/index.html: $(ALL_SGML_FILES)
	jw -o wzdFTPd-doc -b html $(MAIN_SGML_FILE)

wzdFTPd-doc/wzdFTPd.pdf: $(ALL_SGML_FILES)
	jw -o wzdFTPd-doc -b pdf $(MAIN_SGML_FILE)

clean:
	@rm -f wzdFTPd-doc/*.html wzdFTPd-doc/*.pdf wzdFTPd-doc/*.out

distclean: clean
