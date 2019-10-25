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
TEST_PREFIX := local

OBJS := \
	argparse_client.o \
	argparse_edit.o \
	argparse_server.o \
	blacklist.o \
	client.o \
	editor.o \
	exec.o \
	file_encryption.o \
	keydb.o \
	log.o \
	luks.o \
	luksrku.o \
	openssl.o \
	pgmopts.o \
	server.o \
	signals.o \
	thread.o \
	udp.o \
	util.o \
	uuid.o \
	vaulted_keydb.o \
	vault.o

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
	./luksrku server -vv testdata/$(TEST_PREFIX)_server.bin

test_c: luksrku
	./luksrku client -vv --no-luks testdata/$(TEST_PREFIX)_client.bin

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

luksrku: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)
