
INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src

bin_PROGRAMS = siteuptime

siteuptime_SOURCES = siteuptime.c

siteuptime_LDFLAGS = $(WZD_SSL_LIBS)

AM_CPPFLAGS = $(WZD_SSL_INCLUDES)

if USE_ICC
# Workaround for compilation with icc
siteuptime.o: siteuptime.c
@AMDEP_TRUE@	source='$<' object='$@' libtool=no @AMDEPBACKSLASH@
@AMDEP_TRUE@	depfile='$(DEPDIR)/$*.Po' tmpdepfile='$(DEPDIR)/$*.TPo' @AMDEPBACKSLASH@
@AMDEP_TRUE@	$(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
	$(COMPILE) -c -I/usr/include `test -f '$<' || echo '$(srcdir)/'`$<

siteuptime.lo: siteuptime.c
@AMDEP_TRUE@	source='$<' object='$@' libtool=yes @AMDEPBACKSLASH@
@AMDEP_TRUE@	depfile='$(DEPDIR)/$*.Plo' tmpdepfile='$(DEPDIR)/$*.TPlo' @AMDEPBACKSLASH@
@AMDEP_TRUE@	$(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
	$(LTCOMPILE) -c -I/usr/include -o $@ `test -f '$<' || echo '$(srcdir)/'`$<
endif
