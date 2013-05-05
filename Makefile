SHELL=/bin/sh

BINARY=igmpqd
SRCS=igmpqd.c

all: $(BINARY)

$(BINARY): $(SRCS)
	$(CC) $(CFLAGS) $(LDFLAGS) -lnet $(SRCS) -o $(BINARY)

install: $(BINARY)
	install -d $(PREFIX)/sbin
	install -m 755 -t $(PREFIX)/sbin $(BINARY)

clean:
	$(RM) $(BINARY)
