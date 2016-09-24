.PHONY: all clean test testclient derive install
all: luksrku luksrku-config

INSTALL_PREFIX := /usr/local/
OPENSSL_DIR := `pwd`/openssl-1.1.0a/
#OPENSSL_DIR := /home/joe/openssl/
#LIBDIR := /usr/lib/x86_64-linux-gnu/
LIBDIR := $(OPENSSL_DIR)
CFLAGS := -std=c11 -Wall -Wextra -O2 -pthread -D_POSIX_SOURCE -D_XOPEN_SOURCE=500 -Wmissing-prototypes -Wstrict-prototypes -Wno-unused-parameter -I$(OPENSSL_DIR)include
#CFLAGS += -g -DDEBUG
LDFLAGS := -L$(OPENSSL_DIR) -lcrypto -lssl 
#LDFLAGS := -static $(LIBDIR)libssl.a $(LIBDIR)libcrypto.a
#LDFLAGS := -static $(LIBDIR)libssl.a $(LIBDIR)libcrypto.a -ldl

OBJS := luksrku.o server.o log.o openssl.o client.o keyfile.o msg.o binkeyfile.o util.o cmdline.o luks.o exec.o blacklist.o
OBJS_CFG := luksrku-config.o keyfile.o binkeyfile.o parse-keyfile.o openssl.o log.o util.o

install: all
	strip luksrku luksrku-config
	cp luksrku luksrku-config $(INSTALL_PREFIX)sbin/
	chown root:root $(INSTALL_PREFIX)sbin/luksrku $(INSTALL_PREFIX)sbin/luksrku-config
	chmod 755 $(INSTALL_PREFIX)sbin/luksrku $(INSTALL_PREFIX)sbin/luksrku-config
	cp -a $(OPENSSL_DIR)libssl* $(OPENSSL_DIR)libcrypto* $(INSTALL_PREFIX)lib/
	ldconfig

clean:
	rm -f $(OBJS) $(OBJS_CFG) luksrku luksrku-config

valgrind: luksrku
	LD_LIBRARY_PATH=$(OPENSSL_DIR) valgrind --leak-check=full --show-leak-kinds=all ./luksrku -v --client-mode -k client_keys.bin
#LD_LIBRARY_PATH=$(OPENSSL_DIR) valgrind --leak-check=full --show-leak-kinds=all ./luksrku -v --server-mode -k server_key.bin

test: luksrku
	LD_LIBRARY_PATH=$(OPENSSL_DIR) ./luksrku -v --server-mode -k server_key.bin

gdb: luksrku
	LD_LIBRARY_PATH=$(OPENSSL_DIR) gdb --args ./luksrku -v --server-mode -k server_key.bin

testclient: luksrku
	LD_LIBRARY_PATH=$(OPENSSL_DIR) ./luksrku -v --client-mode -k client_keys.bin

derive: luksrku-config
	./luksrku-config server server_key.txt server_key.bin
	./luksrku-config client client_keys.txt client_keys.bin

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

luksrku: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

luksrku-config: $(OBJS_CFG)
	$(CC) $(CFLAGS) -o $@ $(OBJS_CFG) $(LDFLAGS)
