SUBDIRS = plaintext

debug:
	make recursive 'RECURSIVE_TARGET=debug'

all:
	make recursive 'RECURSIVE_TARGET=all'

clean:
	make recursive 'RECURSIVE_TARGET=clean'

distclean:
	make recursive 'RECURSIVE_TARGET=distclean'

recursive:
	@CWD=`pwd`; \
	for i in $(SUBDIRS); do \
		(cd $$CWD/$$i && $(MAKE) $(RECURSIVE_TARGET)) || exit 1; \
	done
