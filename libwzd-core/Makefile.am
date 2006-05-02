SUBDIRS = arch

lib_LTLIBRARIES = libwzd_core.la

libwzd_core_ladir = ${e_prefix}/include/wzdftpd/libwzd-core

libwzd_core_la_HEADERS = \
	ls.h             \
	wzd_action.h     \
	wzd_all.h        \
	wzd_backend.h    \
	wzd_cache.h      \
	wzd_ClientThread.h \
	wzd_commands.h   \
	wzd_configfile.h \
	wzd_configloader.h \
	wzd_crc32.h  	 \
	wzd_crontab.h	 \
	wzd_data.h       \
	wzd_debug.h      \
	wzd_dir.h	 \
	wzd_events.h	 \
	wzd_file.h       \
	wzd_fs.h         \
	wzd_hardlimits.h \
	wzd_ip.h         \
	wzd_libmain.h    \
	wzd_log.h        \
	wzd_messages.h   \
	wzd_misc.h       \
	wzd_mod.h        \
	wzd_mutex.h      \
	wzd_perm.h       \
	wzd_ratio.h      \
	wzd_section.h    \
	wzd_shm.h        \
	wzd_site.h       \
	wzd_site_group.h \
	wzd_site_user.h  \
	wzd_socket.h     \
	wzd_string.h     \
	wzd_structs.h    \
	wzd_threads.h    \
	wzd_tls.h        \
	wzd_types.h      \
	wzd_user.h       \
	wzd_utf8.h       \
	wzd_vars.h       \
	wzd_vfs.h

libwzd_core_la_SOURCES = \
	${libwzd_core_la_HEADERS} \
	inet_ntop.c      \
	inet_pton.c      \
	ls.c             \
	wzd_action.c     \
	wzd_all.c        \
	wzd_backend.c    \
	wzd_cache.c      \
	wzd_ClientThread.c \
	wzd_commands.c   \
	wzd_configfile.c \
	wzd_configloader.c \
	wzd_crc32.c      \
	wzd_crontab.c    \
	wzd_data.c       \
	wzd_debug.c      \
	wzd_dir.c	 \
	wzd_events.c	 \
	wzd_file.c       \
	wzd_fs.c         \
	wzd_ip.c         \
	wzd_libmain.c    \
	wzd_log.c        \
	wzd_messages.c   \
	wzd_misc.c       \
	wzd_mod.c        \
	wzd_mutex.c      \
	wzd_perm.c       \
	wzd_ratio.c      \
	wzd_section.c    \
	wzd_shm.c        \
	wzd_site.c       \
	wzd_site_group.c \
	wzd_site_user.c  \
	wzd_socket.c     \
	wzd_string.c     \
	wzd_threads.c    \
	wzd_tls.c        \
	wzd_user.c       \
	wzd_utf8.c       \
	wzd_vars.c       \
	wzd_vfs.c


nodist_libwzd_core_la_SOURCES = wzd_cookie_lex.l

libwzd_core_la_LIBADD = ../libwzd-base/libwzd_base.la ../libwzd-auth/libwzd_auth.la
libwzd_core_la_LDFLAGS = @PTHREAD_CFLAGS@ @PTHREAD_LIBS@ -version-info $(LT_VERSION_INFO) -export-dynamic -no-undefined

AM_CPPFLAGS = -I$(top_srcdir) $(WZD_SSL_INCLUDES) -DWZD_MULTITHREAD -D_REENTRANT @PTHREAD_CFLAGS@

# them while "make clean", use CLEANFILES
CLEANFILES = wzd_cookie_lex.c

EXTRA_DIST = DOCS_XFERLOG_FORMAT wzd_cookie_lex.l

if USE_ICC
# Workaround for compilation with icc
wzd_shm.o: wzd_shm.c
@AMDEP_TRUE@	source='$<' object='$@' libtool=no @AMDEPBACKSLASH@
@AMDEP_TRUE@	depfile='$(DEPDIR)/$*.Po' tmpdepfile='$(DEPDIR)/$*.TPo' @AMDEPBACKSLASH@
@AMDEP_TRUE@	$(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
	$(COMPILE) -c -I/usr/include `test -f '$<' || echo '$(srcdir)/'`$<

wzd_shm.lo: wzd_shm.c
@AMDEP_TRUE@	source='$<' object='$@' libtool=yes @AMDEPBACKSLASH@
@AMDEP_TRUE@	depfile='$(DEPDIR)/$*.Plo' tmpdepfile='$(DEPDIR)/$*.TPlo' @AMDEPBACKSLASH@
@AMDEP_TRUE@	$(CCDEPMODE) $(depcomp) @AMDEPBACKSLASH@
	$(LTCOMPILE) -c -I/usr/include -o $@ `test -f '$<' || echo '$(srcdir)/'`$<
endif

