CC=gcc
OBJS=wzd_messages.o wzd_ClientThread.o wzd_ServerThread.o wzd_init.o wzd_log.o wzd_main.o
DOBJS=wzd_messages.do wzd_ClientThread.do wzd_ServerThread.do wzd_init.do wzd_log.do wzd_main.do
POBJS=wzd_messages.po wzd_ClientThread.po wzd_ServerThread.po wzd_init.po wzd_log.po wzd_main.po
LIBS=
WINLIBS=$(LIBS) -lws2_32
CFLAGS=-O2 -Wall -Wstrict-prototypes
DCFLAGS=-g -DDEBUG -Wall -Wstrict-prototypes
PCFLAGS=-g -DDEBUG -Wall -Wstrict-prototypes -Wcast-align -Wwrite-strings -Wconversion -Waggregate-return -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs
EXEC=wzdFTPs.exe

.SUFFIXES: .c .o .do .po

all: $(OBJS)
	if [ `uname` = "Linux" ]; then $(CC) $(CFLAGS) -o $(EXEC) $(OBJS) $(LIBS); else $(CC) $(CFLAGS) -o $(EXEC) $(OBJS) $(WINLIBS); fi

debug: $(DOBJS)
	$(CC) $(DCFLAGS) -o $(EXEC) $(DOBJS) $(LIBS)

pedantic: $(POBJS)
	$(CC) $(PCFLAGS) -o $(EXEC) $(POBJS) $(LIBS)

clean:
	rm -f $(OBJS) $(DOBJS) $(POBJS) $(EXEC) *~

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

.c.do:
	$(CC) $(DCFLAGS) -c -o $@ $<

.c.po:
	$(CC) $(PCFLAGS) -c -o $@ $<
