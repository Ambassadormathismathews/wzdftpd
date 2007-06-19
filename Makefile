# This Makefile is not used to build wzdftpd, but to
# create the distribution. See the "help" target for details.

##### you may want to remove this
#CMAKE_CC = -DCMAKE_C_COMPILER=/usr/lib/ccache/cc
ifeq ($(NJOBS),)
NJOBS=1
endif
#####

ifneq ($(CFLAGS),)
EXTRA_CMAKE_FLAGS += -DCMAKE_C_FLAGS="$(CFLAGS)" -DCMAKE_VERBOSE_MAKEFILE=1
endif

ifneq ($(PREFIX),)
CMAKE_PREFIX = -DCMAKE_INSTALL_PREFIX="$(PREFIX)"
endif

all: build/Makefile
	$(MAKE) -C build -j $(NJOBS) $(MAKE_FLAGS) all

DISTNAME=wzdftpd-$(shell cat VERSION)

build/Makefile:
	@-mkdir build 2>/dev/null
	cd build && cmake .. $(EXTRA_CMAKE_FLAGS) $(CMAKE_PREFIX) $(CMAKE_CC)

clean:
	rm -rf build tmp

doxy: doxygen.cfg
	doxygen doxygen.cfg

ifneq ($(PREFIX),)
install: build/Makefile
	cd build && cmake .. $(EXTRA_CMAKE_FLAGS) $(CMAKE_PREFIX) $(CMAKE_CC) && $(MAKE) $(MAKE_FLAGS) install
endif

package: ../$(DISTNAME).tar.gz
	rm -rf tmp
	mkdir tmp
	cp ../$(DISTNAME).tar.gz tmp/wzdftpd_$(shell cat VERSION).orig.tar.gz
	tar -x -z -C tmp -f ../$(DISTNAME).tar.gz
	rm -rf tmp/$(DISTNAME)/debian && cp -r debian tmp/$(DISTNAME)/
	cp Makefile tmp/$(DISTNAME)/
	cd tmp/$(DISTNAME) && debuild
	rm -rf tmp/$(DISTNAME)

porcus: build/Makefile
	make -j $(NJOBS) PREFIX=/home/pollux/DEL-CMAKE EXTRA_CMAKE_FLAGS="-DDEBUG=1 -DWITH_IPV6=ON -DWITH_GnuTLS=ON -DWITH_PAM=ON -DCMAKE_VERBOSE_MAKEFILE=0  -DCMAKE_C_FLAGS=\"-W -Wall -Wextra -Wno-unused-parameter\"" install

release:
	@if test -f ../$(DISTNAME).tar.gz ; then echo $(DISTNAME).tar.gz exists, not overwritting ; exit 1; fi
	rm -rf tmp
	mkdir tmp
	svn export . tmp/$(DISTNAME)
	tar -f - -c -C tmp $(DISTNAME) | gzip -9 > ../$(DISTNAME).tar.gz
	rm -rf tmp

tags:
	ctags -R libwzd-core wzdftpd libwzd

test: build/Makefile
	cd build && make test

help:
	@echo "The following targets are valid for this Makefile:"
	@echo "... all     : create a build directory and make wzdftpd in this directory"
	@echo "... doxy    : build doxygen documentation"
	@echo "... install : install files in the temporary location defined at the top of the Makefile"
	@echo "... packages: create debian packages in tmp/ subdirectory"
	@echo "... release : create an archive for distribution"
	@echo "... test    : run unit tests"
	@echo "The following Makefile variable can be specified:"
	@echo "... NJOBS   : number of parallel make builds (default: $(NJOBS))"
	@echo "... PREFIX  : installation prefix (default: $(PREFIX))"

.PHONY: all clean doxy help install porcus tags test release
