TARGET=libwzdplaintext.so
OBJS=libplaintext_main.o
DOBJS=$(OBJS:%.o=%.do)
POBJS=$(OBJS:%.o=%.po)
SOURCES=$(OBJS:%.o=%.c)

CFLAGS=-O2 -Wall -Wstrict-prototypes -I../../src
DCFLAGS=-g -DDEBUG -Wall -Wstrict-prototypes -I../../src
PCFLAGS=-g -DDEBUG -Wall -Wstrict-prototypes -Wcast-align -Wwrite-strings -Wconversion -Waggregate-return -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs -I../../src
LDFLAGS=-shared
WINLDFLAGS=-shared

CC=gcc

.SUFFIXES: .c .o .do .po

all: debug

release: $(OBJS)
	if [ `uname` = "Linux" ]; then $(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS); else $(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(WINLDFLAGS); fi

debug: $(DOBJS)
	if [ `uname` = "Linux" ]; then $(CC) $(DCFLAGS) -o $(TARGET) $(DOBJS) $(LDFLAGS); else $(CC) $(DCFLAGS) -o $(TARGET) $(DOBJS) $(WINLDFLAGS); fi

pedantic: $(POBJS)
	if [ `uname` = "Linux" ]; then $(CC) $(PCFLAGS) -o $(TARGET) $(POBJS) $(LDFLAGS); else $(CC) $(PCFLAGS) -o $(TARGET) $(POBJS) $(WINLDFLAGS); fi

clean:
	rm -f $(OBJS) $(DOBJS) $(POBJS) *~

distclean: clean
	rm -f $(TARGET)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

.c.do:
	$(CC) $(DCFLAGS) -c -o $@ $<

.c.po:
	$(CC) $(PCFLAGS) -c -o $@ $<


libplaintext_main.o: libplaintext_main.c
