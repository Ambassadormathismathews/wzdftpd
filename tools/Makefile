include ../src/Makefile.config

SUBDIRS = sitewho siteuptime

#ifeq ($(PLATFORM),Linux)
#SUBDIRS += sitewho siteuptime
#endif

debug:
	make recursive 'RECURSIVE_TARGET=debug'

all:
	make recursive 'RECURSIVE_TARGET=all'

release:
	make recursive 'RECURSIVE_TARGET=release'

install:
	mkdir -p -m 755 $(DESTDIR)/tools; \
	make recursive 'RECURSIVE_TARGET=install'

installdebug:
	mkdir -p -m 755 $(DESTDIR)-debug/tools; \
	make recursive 'RECURSIVE_TARGET=installdebug'

uninstall:
	make recursive 'RECURSIVE_TARGET=uninstall'; \
	rmdir $(DESTDIR)/tools;

clean:
	make recursive 'RECURSIVE_TARGET=clean'

distclean:
	make recursive 'RECURSIVE_TARGET=distclean'

recursive:
	@CWD=`pwd`; \
	for i in $(SUBDIRS); do \
		(cd $$CWD/$$i && $(MAKE) $(RECURSIVE_TARGET)) || exit 1; \
	done
