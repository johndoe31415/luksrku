.PHONY: all clean test_s test_c install parsers
all: luksrku

BUILD_REVISION := $(shell git describe --abbrev=10 --dirty --always --tags)
INSTALL_PREFIX := /usr/local/
CFLAGS := -Wall -Wextra -Wshadow -Wswitch -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes -Werror=implicit-function-declaration -Werror=format -Wno-unused-parameter
CFLAGS += -O3 -std=c11 -pthread -D_POSIX_SOURCE -D_POSIX_C_SOURCE=200112L -D_XOPEN_SOURCE=500 -DBUILD_REVISION='"$(BUILD_REVISION)"'
CFLAGS += `pkg-config --cflags openssl`
CFLAGS += -ggdb3 -DDEBUG -fsanitize=address -fsanitize=undefined -fsanitize=leak
PYPGMOPTS := ../Python/pypgmopts/pypgmopts

LDFLAGS := `pkg-config --libs openssl`

OBJS := luksrku.o editor.o util.o log.o keydb.o file_encryption.o uuid.o argparse_edit.o pgmopts.o openssl.o server.o argparse_server.o thread.o argparse_client.o client.o

parsers:
	$(PYPGMOPTS) -n edit parsers/parser_edit.py
	$(PYPGMOPTS) -n server parsers/parser_server.py
	$(PYPGMOPTS) -n client parsers/parser_client.py

install: all
	cp luksrku $(INSTALL_PREFIX)sbin/
	chown root:root $(INSTALL_PREFIX)sbin/luksrku
	chmod 755 $(INSTALL_PREFIX)sbin/luksrku

clean:
	rm -f $(OBJS) $(OBJS_CFG) luksrku

test_s: luksrku
	./luksrku server -vv base

test_c: luksrku
	./luksrku client -vv export 127.0.0.1

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

luksrku: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)
