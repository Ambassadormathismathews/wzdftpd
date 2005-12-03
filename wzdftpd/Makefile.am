
sbin_PROGRAMS = wzdftpd

wzdftpd_SOURCES =    \
	wzd_init.h         \
	wzd_main.c         \
	wzd_opts.h         \
	wzd_ServerThread.c \
	wzd_ServerThread.h

nodist_wzdftpd_SOURCES = wzd_init_lex.l

wzdftpd_DEPENDENCIES = ../libwzd-core/libwzd_core.la

wzdftpd_LDADD = ../libwzd-core/libwzd_core.la
wzdftpd_LDFLAGS = $(WZD_SSL_LIBS) @CRYPT_FLAGS@ @PTHREAD_CFLAGS@ @PTHREAD_LIBS@ @DL_FLAGS@

AM_CPPFLAGS = -I$(top_srcdir) $(WZD_SSL_INCLUDES) -DWZD_MULTITHREAD -D_REENTRANT @PTHREAD_CFLAGS@

dist_sysconf_DATA = wzd.cfg.sample wzd.pem \
	file_ginfo.txt  file_help.txt   file_swho.txt \
	file_user.txt file_group.txt  file_rules.txt  \
	file_users.txt  file_who.txt  file_groups.txt  \
	file_vfs.txt \
	users.sample

install-data-hook:
	${INSTALL_PROGRAM} -m 775 -d @e_localstatedir@/log/wzdftpd || true

uninstall-hook:
	rmdir --ignore-fail-on-non-empty @e_localstatedir@/log/wzdftpd || true

# them while "make clean", use CLEANFILES
CLEANFILES = wzd_init_lex.c

EXTRA_DIST = KNOWN_BUGS TODO wzd_init_lex.l

