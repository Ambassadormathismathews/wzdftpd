include Makefile.config

WZD_BUILD_NUM=$(DATE_TAG)

CC=gcc
LEX=flex

COMMON_CFLAGS=-pipe -Wall -Wstrict-prototypes -DWZD_BUILD_NUM=$(WZD_BUILD_NUM) -DWZD_VERSION_NUM=\"$(WZD_VERSION_NUM)\"
COMMON_LIBS=

SOURCES=wzd_main.c wzd_site.c wzd_site_user.c wzd_site_group.c wzd_socket.c \
  wzd_ClientThread.c wzd_ServerThread.c wzd_init.c \
  ls.c wzd_data.c wzd_action.c wzd_file.c wzd_perm.c list.c stack.c \
  wzd_ratio.c wzd_section.c
OBJS=$(SOURCES:%.c=%.o)
DOBJS=$(SOURCES:%.c=%.do)
POBJS=$(SOURCES:%.c=%.po)
LIBS=-ldl -lfl $(COMMON_LIBS)
WINLIBS=$(COMMON_LIBS) -lcrypto
CFLAGS=-O3 $(COMMON_CFLAGS)
DCFLAGS=-g -DDEBUG $(COMMON_CFLAGS)
PCFLAGS=-g -DDEBUG $(COMMON_CFLAGS) -Wcast-align -Wwrite-strings -Wconversion -Waggregate-return -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs

LIBWZD_SOURCES = wzd_libmain.c wzd_log.c wzd_misc.c wzd_backend.c wzd_messages.c wzd_mod.c wzd_vfs.c wzd_cache.c wzd_shm.c wzd_crontab.c
LIBWZD_OBJS = $(LIBWZD_SOURCES:%.c=%.o)
LIBWZD_DOBJS = $(LIBWZD_SOURCES:%.c=%.do)
LIBWZD_POBJS = $(LIBWZD_SOURCES:%.c=%.po)

ifeq ($(SSL_SUPPORT),1)
SOURCES += wzd_tls.c
COMMON_CFLAGS += -DSSL_SUPPORT
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
SOURCES += wzd_crc32.c
COMMON_CFLAGS += -DINTERNAL_SFV=1
endif

ifeq ($(PLATFORM),Linux)
LIBWZD = libwzd.so
EXEC=wzdFTPd
COMMON_LIBS += -L. -lwzd -Wl,-rpath,.
#COMMON_CFLAGS += -march=pentium4 -ffast-math -mmmx -msse -mfpmath=sse
#COMMON_CFLAGS += -march=pentium3
else
LIBWZD = libwzd.dll
EXEC=wzdFTPd.exe
COMMON_LIBS += -L. -llibwzd -Wl,-rpath,.
ifeq ($(WINSOCK_SUPPORT),1)
COMMON_CFLAGS += -DWINSOCK_SUPPORT
COMMON_LIBS += -lwsock32
WINLIBFLAGS = -lwsock32
endif

endif # !linux


.SUFFIXES: .c .o .do .po

all: debug

install: release
	install --mode=755 $(EXEC) $(LIBWZD) $(DESTDIR); \
	install --mode=600 wzd.cfg $(DESTDIR); \
	install --mode=644 file_help.txt file_swho.txt file_user.txt file_rules.txt file_users.txt file_who.txt $(DESTDIR)

installdebug: debug
	install --mode=755 $(EXEC) $(LIBWZD) $(DESTDIR)-debug; \
	install --mode=600 wzd.cfg $(DESTDIR)-debug; \
	install --mode=644 file_help.txt file_swho.txt file_user.txt file_rules.txt file_users.txt file_who.txt $(DESTDIR)-debug

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
	$(CC) -shared -o $(LIBWZD) $(LIBWZD_OBJS) $(WINLIBFLAGS) && \
	$(CC) $(CFLAGS) -o $(EXEC) $(OBJS) $(WINLIBS)
endif

debug: $(DOBJS) $(LIBWZD_DOBJS)
ifeq ($(PLATFORM),Linux)
	$(CC) -shared -o $(LIBWZD) $(LIBWZD_DOBJS) && \
	$(CC) -o $(EXEC) $(DOBJS) $(LIBS)
else
	$(CC) -shared -o $(LIBWZD) $(LIBWZD_DOBJS) $(WINLIBFLAGS) && \
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
	rm -f *.o *.do *.po *~ core wzd_init.c

distclean: clean
	rm -f $(EXEC) $(LIBWZD) wzd.log xferlog

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

.c.do:
	$(CC) $(DCFLAGS) -c -o $@ $<

.c.po:
	$(CC) $(PCFLAGS) -c -o $@ $<

wzd_init.c: wzd_init_lex.l
	$(LEX) -o$@ $^

###### dependancies
dep: deps

deps: wzd_init.c
	rm -f Makefile.deps Makefile.deps2; \
	for obj in $(SOURCES) $(LIBWZD_SOURCES); do $(CC) -MM $$obj $(COMMON_CFLAGS) >> Makefile.deps; done; \
	sed s/\.o:/\.do:/g Makefile.deps >> Makefile.deps2; \
	sed s/\.o:/\.po:/g Makefile.deps >> Makefile.deps2; \
	cat Makefile.deps2 >> Makefile.deps; \
	rm -f Makefile.deps2

-include Makefile.deps

