

#libexecdir = ${prefix}/lib
#libdir = ${prefix}/lib

#libexec_LTLIBRARIES = libwzd.la
lib_LTLIBRARIES = libwzd.la


libwzd_la_SOURCES =  \
	inet_ntop.c     \
	inet_pton.c     \
	wzd_backend.c   \
	wzd_backend.h   \
	wzd_cache.c     \
	wzd_cache.h     \
	wzd_crc32.c     \
	wzd_crc32.h  	\
	wzd_crontab.c   \
	wzd_crontab.h	\
	wzd_debug.c     \
	wzd_debug.h     \
	wzd_dir.c	\
	wzd_dir.h	\
	wzd_libmain.c   \
	wzd_libmain.h   \
	wzd_log.c       \
	wzd_log.h       \
	wzd_md5.c       \
	wzd_md5.h       \
	wzd_messages.c  \
	wzd_messages.h  \
	wzd_misc.c      \
	wzd_misc.h      \
	wzd_mod.c       \
	wzd_mod.h       \
	wzd_section.c   \
	wzd_section.h   \
	wzd_shm.c       \
	wzd_shm.h       \
	wzd_strtok_r.c  \
	wzd_strtok_r.h  \
	wzd_types.h     \
	wzd_vfs.c       \
	wzd_vfs.h

nodist_libwzd_la_SOURCES = wzd_cookie_lex.l

libwzd_la_LDFLAGS = @PTHREAD_CFLAGS@ @PTHREAD_LIBS@ -avoid-version -module -no-undefined

sbin_PROGRAMS = wzdftpd

wzdftpd_SOURCES =    \
	list.c             \
	list.h             \
	ls.c               \
	ls.h               \
	stack.c            \
	stack.h            \
	wzd_action.c       \
	wzd_action.h       \
	wzd_ClientThread.c \
	wzd_ClientThread.h \
	wzd_data.c         \
	wzd_data.h         \
	wzd_file.c         \
	wzd_file.h         \
	wzd_hardlimits.h   \
	wzd_init.h         \
	wzd_main.c         \
	wzd_opts.h         \
	wzd_perm.c         \
	wzd_perm.h         \
	wzd_ratio.c        \
	wzd_ratio.h        \
	wzd_ServerThread.c \
	wzd_ServerThread.h \
	wzd_savecfg.c      \
	wzd_savecfg.h      \
	wzd_site.c         \
	wzd_site.h         \
	wzd_site_group.c   \
	wzd_site_group.h   \
	wzd_site_user.c    \
	wzd_site_user.h    \
	wzd_socket.c       \
	wzd_socket.h       \
	wzd_structs.h      \
	wzd_tls.c          \
	wzd_tls.h

nodist_wzdftpd_SOURCES = wzd_init_lex.l

wzdftpd_LDFLAGS = -L./ -L.libs/ -lwzd $(WZD_SSL_LIBS) @PTHREAD_CFLAGS@ @PTHREAD_LIBS@ @DL_FLAGS@

AM_CPPFLAGS = $(WZD_SSL_INCLUDES) -DWZD_MULTITHREAD -D_REENTRANT @PTHREAD_CFLAGS@

#dist_pkgdata_DATA = file_ginfo.txt  file_help.txt   file_swho.txt \
#	file_user.txt file_group.txt  file_rules.txt  \
#	file_users.txt  file_who.txt  file_groups.txt  \
#	file_vfs.txt \
#	users

#sysconfdir = ${prefix}/etc/wzdftpd

dist_sysconf_DATA = wzd.cfg wzd.pem \
	file_ginfo.txt  file_help.txt   file_swho.txt \
	file_user.txt file_group.txt  file_rules.txt  \
	file_users.txt  file_who.txt  file_groups.txt  \
	file_vfs.txt \
	users

install-data-hook:
	${INSTALL_PROGRAM} -m 775 -d @datadir@/wzdftpd/logs || true

uninstall-hook:
	rmdir --ignore-fail-on-non-empty @datadir@/wzdftpd/logs

# them while "make clean", use CLEANFILES
CLEANFILES = wzd_init_lex.c wzd_cookie_lex.c

EXTRA_DIST = DOCS_XFERLOG_FORMAT KNOWN_BUGS TODO wzd_cookie_lex.l wzd_init_lex.l

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
