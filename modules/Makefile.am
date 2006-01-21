AUTOMAKE_OPTIONS = 1.5	# Require Automake 1.5 or better.

if HAVE_PERL
  MAYBE_PERL = perl
endif

if HAVE_TCL
  MAYBE_TCL = tcl
endif

if HAVE_ZEROCONF
  MAYBE_ZEROCONF = zeroconf
endif

SUBDIRS = debug sfv test $(MAYBE_PERL) $(MAYBE_TCL) $(MAYBE_ZEROCONF)

# we need to include all subdirs in distribution, else the next
# ./configure will fail because it won't be able to find
# $SOMEDIR/Makefile.in
DIST_SUBDIRS = debug sfv test perl tcl zeroconf
