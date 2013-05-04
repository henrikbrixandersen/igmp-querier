SHELL = /bin/sh

BINARY=src/igmp-querier
SRCS=src/main.c

all: $(BINARY)

$(BINARY): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -lnet $(SRCS) -o $(BINARY)

install: $(BINARY)
	install -d $(PREFIX)/sbin
	install -m 755 -t $(PREFIX)/sbin $(BINARY)

clean:
	$(RM) $(BINARY)
