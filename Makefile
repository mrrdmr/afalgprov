MOD_DIR := $(shell openssl version -m | sed -n "s/.*\"\(.*\)\".*/\1/p")
CC := gcc
CFLAGS := -O2 -fPIC -shared -Wall -Wextra
LDFLAGS := -lcrypto

all: afalgprov.so

afalgprov.so: afalgprov.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

install: afalgprov.so
	install -d -m 0755 "$(MOD_DIR)"
	install -m 0755 afalgprov.so "$(MOD_DIR)/"

uninstall:
	rm -f "$(MOD_DIR)/afalgprov.so"

clean:
	rm -f afalgprov.so

.PHONY: all install uninstall clean
