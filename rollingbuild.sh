#!/bin/sh

NAME="wzdftpd"

TEST_RESULTS=$1
test -z "$TEST_RESULTS" && TEST_RESULTS=results.log

# Exit immediately if command fails
set -e

# Print command executed to stdout
set -v

# Pull in config scripts
PATH=$AUTO_BUILD_ROOT/bin:$PATH
export PATH

# Clean up build area
[ -f Makefile ] && make -k maintainer-clean ||:

./bootstrap || exit 1

# Configure the build
./configure --prefix=$AUTO_BUILD_ROOT

# Make
make


if [ -z "$SKIP_TESTS" -o "$SKIP_TESTS" = "0" ]; then
  make check TEST_VERBOSE=1 | tee $TEST_RESULTS
fi


make install

rm -f $NAME-*.tar.gz
make dist

if [ -x /usr/bin/rpmbuild ]; then
  rpmbuild -ta --clean $NAME-*.tar.gz
fi

if [ -x /usr/bin/fakeroot ]; then
  fakeroot debian/rules clean
  fakeroot debian/rules DESTDIR=$HOME/package-root/debian binary
fi

exit 0
