PLATFORM:=$(shell uname)
SUBDIRS =

ifeq ($(PLATFORM),Linux)
SUBDIRS += sitewho
endif

debug:
	make recursive 'RECURSIVE_TARGET=debug'

all:
	make recursive 'RECURSIVE_TARGET=all'

release:
	make recursive 'RECURSIVE_TARGET=release'

clean:
	make recursive 'RECURSIVE_TARGET=clean'

distclean:
	make recursive 'RECURSIVE_TARGET=distclean'

recursive:
	@CWD=`pwd`; \
	for i in $(SUBDIRS); do \
		(cd $$CWD/$$i && $(MAKE) $(RECURSIVE_TARGET)) || exit 1; \
	done
