include Makefile.config

WZD_BUILD_NUM=$(DATE_TAG)

COMMON_CFLAGS=-pipe -Wall -Wstrict-prototypes -DSSL_SUPPORT=$(SSL_SUPPORT) -DWZD_BUILD_NUM=$(WZD_BUILD_NUM) -DWZD_VERSION_NUM=\"$(WZD_VERSION_NUM)\"
COMMON_LIBS=

OBJS=wzd_main.o wzd_site.o wzd_site_user.o wzd_socket.o \
  wzd_ClientThread.o wzd_ServerThread.o wzd_init.o \
  ls.o wzd_data.o wzd_action.o wzd_file.o wzd_perm.o list.o stack.o
DOBJS=$(OBJS:%.o=%.do)
POBJS=$(OBJS:%.o=%.po)
SOURCES=$(OBJS:%.o=%.c)
LIBS=-ldl $(COMMON_LIBS)
WINLIBS=$(COMMON_LIBS) -lcrypto
CFLAGS=-O2 $(COMMON_CFLAGS)
DCFLAGS=-g -DDEBUG $(COMMON_CFLAGS)
PCFLAGS=-g -DDEBUG $(COMMON_CFLAGS) -Wcast-align -Wwrite-strings -Wconversion -Waggregate-return -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs

LIBWZD_SOURCES = wzd_libmain.c wzd_log.c wzd_misc.c wzd_backend.c wzd_messages.c wzd_mod.c wzd_vfs.c wzd_cache.c wzd_shm.c wzd_crontab.c
LIBWZD_OBJS = $(LIBWZD_SOURCES:%.c=%.o)
LIBWZD_DOBJS = $(LIBWZD_SOURCES:%.c=%.do)
LIBWZD_POBJS = $(LIBWZD_SOURCES:%.c=%.po)

ifeq ($(SSL_SUPPORT),1)
OBJS += wzd_tls.o
COMMON_LIBS += -lssl
endif

ifeq ($(WZD_MULTIPROCESS),1)
COMMON_CFLAGS += -DWZD_MULTIPROCESS
endif

ifeq ($(WZD_MULTITHREAD),1)
COMMON_CFLAGS += -DWZD_MULTITHREAD -D_REENTRANT
COMMON_LIBS += -lpthread
endif

ifeq ($(INTERNAL_SFV),1)
OBJS += wzd_crc32.o
COMMON_CFLAGS += -DINTERNAL_SFV=1
endif

ifeq ($(PLATFORM),Linux)
CC=gcc-3.2
LIBWZD = libwzd.so
EXEC=wzdFTPd
COMMON_LIBS += -L. -lwzd -Wl,-rpath,.
COMMON_CFLAGS += -march=i686 -ffast-math -mmmx -msse -mfpmath=sse
#COMMON_CFLAGS += -march=i586
else
CC=gcc
LIBWZD = libwzd.dll
EXEC=wzdFTPd.exe
COMMON_LIBS += -L. -llibwzd -Wl,-rpath,.
endif


.SUFFIXES: .c .o .do .po

all: debug

install: release
	install --mode=755 $(EXEC) $(LIBWZD) $(DESTDIR); \
	install --mode=600 wzd.cfg $(DESTDIR); \
	install --mode=644 file_help.txt file_swho.txt file_user.txt file_rules.txt file_users.txt file_who.txt $(DESTDIR)

uninstall:
	rm -f $(DESTDIR)/file_{help,swho,user,rules,users,who}.txt; \
	rm -f $(DESTDIR)/{$(EXEC),$(LIBWZD),wzd.cfg};

intel:
	$(MAKE) 'CC=icc' 'COMMON_CFLAGS=-w1 -DSSL_SUPPORT=$(SSL_SUPPORT) -DWZD_BUILD_NUM=$(WZD_BUILD_NUM) -DWZD_VERSION_NUM=\"$(WZD_VERSION_NUM)\"'

intel_release:
	$(MAKE) 'CC=icc' 'COMMON_CFLAGS=-w1 -DSSL_SUPPORT=$(SSL_SUPPORT) -DWZD_BUILD_NUM=$(WZD_BUILD_NUM) -DWZD_VERSION_NUM=\"$(WZD_VERSION_NUM)\"' release

release: $(OBJS) $(LIBWZD_OBJS)
ifeq ($(PLATFORM),Linux)
	$(CC) -shared -o $(LIBWZD) $(LIBWZD_OBJS) && \
	$(CC) $(CFLAGS) -o $(EXEC) $(OBJS) $(LIBS)
else
	$(CC) -shared -o $(LIBWZD) $(LIBWZD_OBJS) && \
	$(CC) $(CFLAGS) -o $(EXEC) $(OBJS) $(WINLIBS)
endif

debug: $(DOBJS) $(LIBWZD_DOBJS)
ifeq ($(PLATFORM),Linux)
	$(CC) -shared -o $(LIBWZD) $(LIBWZD_DOBJS) && \
	$(CC) -o $(EXEC) $(DOBJS) $(LIBS)
else
	$(CC) -shared -o $(LIBWZD) $(LIBWZD_DOBJS) && \
	$(CC) -o $(EXEC) $(DOBJS) $(WINLIBS)
endif

pedantic: $(POBJS) $(LIBWZD_POBJS)
ifeq ($(PLATFORM),Linux)
	$(CC) -shared -o $(LIBWZD) $(LIBWZD_POBJS) && \
	$(CC) $(PCFLAGS) -o $(EXEC) $(POBJS) $(LIBS)
else
	$(CC) -shared -o $(LIBWZD) $(LIBWZD_POBJS) && \
	$(CC) $(PCFLAGS) -o $(EXEC) $(POBJS) $(WINLIBS)
endif

check_symlinks:
	rm -f libwzdplaintext.so libwzd_sfv.so libwzd_test.so; \
	if [ -d ../backends/plaintext ]; then ln -s ../backends/plaintext/libwzdplaintext.so; fi; \
	if [ -d ../modules/sfv ]; then ln -s ../modules/sfv/libwzd_sfv.so; fi; \
	if [ -d ../modules/test ]; then ln -s ../modules/test/libwzd_test.so; fi

clean:
	rm -f *.o *.do *.po *~ core

distclean: clean
	rm -f $(EXEC) $(LIBWZD)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

.c.do:
	$(CC) $(DCFLAGS) -c -o $@ $<

.c.po:
	$(CC) $(PCFLAGS) -c -o $@ $<

###### dependancies
deps:
	rm -f Makefile.deps Makefile.deps2; \
	for obj in $(SOURCES) $(LIBWZD_SOURCES); do $(CC) -MM $$obj $(COMMON_CFLAGS) >> Makefile.deps; done; \
	sed s/\.o:/\.do:/g Makefile.deps >> Makefile.deps2; \
	sed s/\.o:/\.po:/g Makefile.deps >> Makefile.deps2; \
	cat Makefile.deps2 >> Makefile.deps; \
	rm -f Makefile.deps2

-include Makefile.deps

