PLATFORM := $(shell uname)

TARGET=libwzdplaintext.so
OBJS=libplaintext_main.o
DOBJS=$(OBJS:%.o=%.do)
POBJS=$(OBJS:%.o=%.po)
SOURCES=$(OBJS:%.o=%.c)

CFLAGS=-O2 -Wall -Wstrict-prototypes -I../../src
DCFLAGS=-g -DDEBUG -Wall -Wstrict-prototypes -I../../src
PCFLAGS=-g -DDEBUG -Wall -Wstrict-prototypes -Wcast-align -Wwrite-strings -Wconversion -Waggregate-return -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs -I../../src
LDFLAGS=-shared -lcrypt
WINLDFLAGS=-shared -lcrypt

ifeq ($(PLATFORM),Linux)
CC=gcc-3.1
else
CC=gcc
endif

.SUFFIXES: .c .o .do .po

all: debug

release: $(OBJS)
ifeq ($(PLATFORM),Linux)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)
else
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(WINLDFLAGS)
endif

debug: $(DOBJS)
ifeq ($(PLATFORM),Linux)
	$(CC) $(DCFLAGS) -o $(TARGET) $(DOBJS) $(LDFLAGS)
else
	$(CC) $(DCFLAGS) -o $(TARGET) $(DOBJS) $(WINLDFLAGS)
endif

pedantic: $(POBJS)
ifeq ($(PLATFORM),Linux)
	$(CC) $(PCFLAGS) -o $(TARGET) $(POBJS) $(LDFLAGS)
else
	$(CC) $(PCFLAGS) -o $(TARGET) $(POBJS) $(WINLDFLAGS)
endif

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
