include Makefile.config

PLATFORM:=$(shell uname)

ifeq ($(PLATFORM),Linux)
CC=gcc-3.2
else
CC=gcc
endif

COMMON_CFLAGS=-Wall -Wstrict-prototypes -DSSL_SUPPORT=$(SSL_SUPPORT)
COMMON_LIBS=

OBJS=wzd_misc.o wzd_site.o wzd_socket.o wzd_backend.o wzd_messages.o \
  wzd_ClientThread.o wzd_ServerThread.o wzd_init.o wzd_log.o wzd_main.o \
  ls.o wzd_data.o wzd_action.o wzd_file.o wzd_perm.o wzd_shm.o wzd_crc32.o \
  wzd_mod.o wzd_vfs.o
DOBJS=$(OBJS:%.o=%.do)
POBJS=$(OBJS:%.o=%.po)
SOURCES=$(OBJS:%.o=%.c)
LIBS=-ldl $(COMMON_LIBS)
WINLIBS=$(COMMON_LIBS) -lcrypto
CFLAGS=-O2 $(COMMON_CFLAGS)
DCFLAGS=-g -DDEBUG $(COMMON_CFLAGS)
PCFLAGS=-g -DDEBUG $(COMMON_CFLAGS) -Wcast-align -Wwrite-strings -Wconversion -Waggregate-return -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs
EXEC=wzdFTPd.exe

ifeq ($(SSL_SUPPORT),1)
OBJS += wzd_tls.o
COMMON_LIBS += -lssl
endif


.SUFFIXES: .c .o .do .po

all: debug

release: $(OBJS)
ifeq ($(PLATFORM),Linux)
	$(CC) $(CFLAGS) -o $(EXEC) $(OBJS) $(LIBS)
else
	$(CC) $(CFLAGS) -o $(EXEC) $(OBJS) $(WINLIBS)
endif

debug: $(DOBJS)
ifeq ($(PLATFORM),Linux)
	$(CC) $(DCFLAGS) -o $(EXEC) $(DOBJS) $(LIBS)
else
	$(CC) $(DCFLAGS) -o $(EXEC) $(DOBJS) $(WINLIBS)
endif

pedantic: $(POBJS)
ifeq ($(PLATFORM),Linux)
	$(CC) $(PCFLAGS) -o $(EXEC) $(POBJS) $(LIBS)
else
	$(CC) $(PCFLAGS) -o $(EXEC) $(POBJS) $(WINLIBS)
endif

clean:
	rm -f *.o *.do *.po *~ core

distclean: clean
	rm -f $(EXEC)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

.c.do:
	$(CC) $(DCFLAGS) -c -o $@ $<

.c.po:
	$(CC) $(PCFLAGS) -c -o $@ $<

###### dependancies
deps:
	rm -f Makefile.deps Makefile.deps2; \
	for obj in $(SOURCES); do $(CC) -MM $$obj >> Makefile.deps; done; \
	sed s/\.o:/\.do:/g Makefile.deps >> Makefile.deps2; \
	sed s/\.o:/\.po:/g Makefile.deps >> Makefile.deps2; \
	cat Makefile.deps2 >> Makefile.deps; \
	rm -f Makefile.deps2

-include Makefile.deps

