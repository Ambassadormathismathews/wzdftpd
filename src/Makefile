CC=gcc
OBJS=wzd_backend.o wzd_messages.o wzd_ClientThread.o wzd_ServerThread.o wzd_init.o wzd_log.o wzd_main.o ls.o
DOBJS=$(OBJS:%.o=%.do)
POBJS=$(OBJS:%.o=%.po)
SOURCES=$(OBJS:%.o=%.c)
LIBS=-ldl
WINLIBS=-lws2_32
CFLAGS=-O2 -Wall -Wstrict-prototypes
DCFLAGS=-g -DDEBUG -Wall -Wstrict-prototypes
PCFLAGS=-g -DDEBUG -Wall -Wstrict-prototypes -Wcast-align -Wwrite-strings -Wconversion -Waggregate-return -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs
EXEC=wzdFTPs.exe

.SUFFIXES: .c .o .do .po

all: debug

release: $(OBJS)
	if [ `uname` = "Linux" ]; then $(CC) $(CFLAGS) -o $(EXEC) $(OBJS) $(LIBS); else $(CC) $(CFLAGS) -o $(EXEC) $(OBJS) $(WINLIBS); fi

debug: $(DOBJS)
	if [ `uname` = "Linux" ]; then $(CC) $(DCFLAGS) -o $(EXEC) $(DOBJS) $(LIBS); else $(CC) $(DCFLAGS) -o $(EXEC) $(DOBJS) $(WINLIBS); fi

pedantic: $(POBJS)
	if [ `uname` = "Linux" ]; then $(CC) $(PCFLAGS) -o $(EXEC) $(POBJS) $(LIBS); else $(CC) $(PCFLAGS) -o $(EXEC) $(POBJS) $(WINLIBS); fi

clean:
	rm -f $(OBJS) $(DOBJS) $(POBJS) *~

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

include Makefile.deps

