

libexecdir = ${prefix}/lib

libexec_LTLIBRARIES = libwzd.la


libwzd_la_SOURCES =  \
	wzd_libmain.c   \
	wzd_libmain.h   \
	wzd_log.c       \
	wzd_log.h       \
	wzd_misc.c      \
	wzd_misc.h      \
	wzd_backend.c   \
	wzd_backend.h   \
	wzd_messages.c  \
	wzd_messages.h  \
	wzd_mod.c       \
	wzd_mod.h       \
	wzd_vfs.c       \
	wzd_vfs.h       \
	wzd_cache.c     \
	wzd_cache.h     \
	wzd_shm.c       \
	wzd_shm.h       \
	wzd_crontab.c   \
	wzd_crontab.h

libwzd_la_LDFLAGS = -avoid-version -module

sbin_PROGRAMS = wzdFTPd

wzdFTPd_SOURCES =    \
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
	wzd_crc32.c        \
	wzd_crc32.h        \
	wzd_data.c         \
	wzd_data.h         \
	wzd_file.c         \
	wzd_file.h         \
	wzd.h              \
	wzd_hardlimits.h   \
	wzd_init.h         \
	wzd_main.c         \
	wzd_perm.c         \
	wzd_perm.h         \
	wzd_ratio.c        \
	wzd_ratio.h        \
	wzd_section.c      \
	wzd_section.h      \
	wzd_ServerThread.c \
	wzd_ServerThread.h \
	wzd_site.c         \
	wzd_site.h         \
	wzd_site_user.c    \
	wzd_site_user.h    \
	wzd_socket.c       \
	wzd_socket.h       \
	wzd_structs.h      \
	wzd_tls.c          \
	wzd_tls.h          \
  wzd_init_lex.l

wzdFTPd_LDFLAGS = -lwzd -lssl -lpthread -lfl

AM_CPPFLAGS = -DSSL_SUPPORT=1 -DWZD_BUILD_NUM=20030331 -DWZD_VERSION_NUM=\"0.1rc4\" -DWZD_MULTITHREAD -D_REENTRANT
