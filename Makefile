.PHONY: all clean test testclient install
all: luksrku

BUILD_REVISION := $(shell git describe --abbrev=10 --dirty --always --tags)
INSTALL_PREFIX := /usr/local/
CFLAGS := -Wall -Wextra -Wshadow -Wswitch -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes -Werror=implicit-function-declaration -Werror=format -Wno-unused-parameter
CFLAGS += -O3 -std=c11 -pthread -D_POSIX_SOURCE -D_XOPEN_SOURCE=500 -DBUILD_REVISION='"$(BUILD_REVISION)"'
CFLAGS += `pkg-config --cflags openssl`
CFLAGS += -ggdb3 -DDEBUG -fsanitize=address -fsanitize=undefined -fsanitize=leak

LDFLAGS := `pkg-config --libs openssl`

OBJS := luksrku.o editor.o util.o log.o keydb.o file_encryption.o uuid.o

install: all
	cp luksrku $(INSTALL_PREFIX)sbin/
	chown root:root $(INSTALL_PREFIX)sbin/luksrku
	chmod 755 $(INSTALL_PREFIX)sbin/luksrku

clean:
	rm -f $(OBJS) $(OBJS_CFG) luksrku

test: luksrku
	./luksrku -v --server-mode -k server_key.bin

gdb: luksrku
	gdb --args ./luksrku -v --server-mode -k server_key.bin

testclient: luksrku
	./luksrku -v --client-mode -k client_keys.bin

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

luksrku: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)
