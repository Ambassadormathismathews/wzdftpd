include ../../src/Makefile.config

TARGET=libwzd_test.so
OBJS=libwzd_test.o
DOBJS=$(OBJS:%.o=%.do)
POBJS=$(OBJS:%.o=%.po)
SOURCES=$(OBJS:%.o=%.c)

COMMON_FLAGS=-Wall -Wstrict-prototypes -I../../src
CFLAGS=-O2 $(COMMON_FLAGS)
DCFLAGS=-g -DDEBUG $(COMMON_FLAGS)
PCFLAGS=-g -DDEBUG -Wcast-align -Wwrite-strings -Wconversion -Waggregate-return -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs $(COMMON_FLAGS)
LDFLAGS=-shared -lcrypt
WINLDFLAGS=-shared -lcrypt -L../../src -llibwzd

CC=gcc

.SUFFIXES: .c .o .do .po

all: debug

intel:
	$(MAKE) 'CC=icc' 'COMMON_FLAGS=-w1 -I../../src'

install: release
	install --mode=755 $(TARGET) $(DESTDIR)

installdebug: debug
	install --mode=755 $(TARGET) $(DESTDIR)-debug

uninstall: release
	rm -f $(DESTDIR)/$(TARGET)

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

