
INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/libwzd

bin_PROGRAMS = sitewho

sitewho_SOURCES = sitewho.c

sitewho_LDADD = $(top_srcdir)/libwzd/libwzd.la
sitewho_LDFLAGS = -no-undefined $(WZD_SSL_LIBS) @PTHREAD_CFLAGS@ @PTHREAD_LIBS@ @DL_FLAGS@

AM_CPPFLAGS = $(WZD_SSL_INCLUDES) -DWZD_MULTITHREAD -D_REENTRANT @PTHREAD_CFLAGS@

if USE_ICC
# Workaround for compilation with icc
sitewho.o: sitewho.c
@AMDEP_TRUE@	source='$<' object='$@' libtool=no @AMDEPBACKSLASH@
@AMDEP_TRUE@	depfile='$(DEPDIR)/$*.Po' tmpdepfile='$(DEPDIR)/$*.TPo' @AMDEPBACKSLASH@
@AMDEP_TRUE@	$(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
	$(COMPILE) -c -I/usr/include `test -f '$<' || echo '$(srcdir)/'`$<

sitewho.lo: sitewho.c
@AMDEP_TRUE@	source='$<' object='$@' libtool=yes @AMDEPBACKSLASH@
@AMDEP_TRUE@	depfile='$(DEPDIR)/$*.Plo' tmpdepfile='$(DEPDIR)/$*.TPlo' @AMDEPBACKSLASH@
@AMDEP_TRUE@	$(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
	$(LTCOMPILE) -c -I/usr/include -o $@ `test -f '$<' || echo '$(srcdir)/'`$<
endif
