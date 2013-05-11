SHELL=/bin/sh

CFLAGS?=-Wall

BINARY=igmpqd
SRCS=igmpqd.c daemon.c
HDRS=daemon.h

all: $(BINARY)

$(BINARY): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) $(LDFLAGS) -lnet $(SRCS) -o $(BINARY)

install: $(BINARY)
	install -d $(PREFIX)/sbin
	install -m 755 -t $(PREFIX)/sbin $(BINARY)

clean:
	$(RM) $(BINARY)
