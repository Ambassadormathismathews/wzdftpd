
INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src

bin_PROGRAMS = siteconfig

siteconfig_SOURCES = siteconfig.c

siteconfig_LDFLAGS = -no-undefined -L../../src -L../../src/.libs -lwzd $(WZD_SSL_LIBS) @PTHREAD_CFLAGS@ @PTHREAD_LIBS@ @DL_FLAGS@

AM_CPPFLAGS = $(WZD_SSL_INCLUDES)

if USE_ICC
# Workaround for compilation with icc
siteconfig.o: siteconfig.c
@AMDEP_TRUE@	source='$<' object='$@' libtool=no @AMDEPBACKSLASH@
@AMDEP_TRUE@	depfile='$(DEPDIR)/$*.Po' tmpdepfile='$(DEPDIR)/$*.TPo' @AMDEPBACKSLASH@
@AMDEP_TRUE@	$(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
	$(COMPILE) -c -I/usr/include `test -f '$<' || echo '$(srcdir)/'`$<

siteconfig.lo: siteconfig.c
@AMDEP_TRUE@	source='$<' object='$@' libtool=yes @AMDEPBACKSLASH@
@AMDEP_TRUE@	depfile='$(DEPDIR)/$*.Plo' tmpdepfile='$(DEPDIR)/$*.TPlo' @AMDEPBACKSLASH@
@AMDEP_TRUE@	$(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
	$(LTCOMPILE) -c -I/usr/include -o $@ `test -f '$<' || echo '$(srcdir)/'`$<
endif
