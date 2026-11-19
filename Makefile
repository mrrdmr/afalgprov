MOD_DIR := $(shell openssl version -m | sed -n "s/.*\"\(.*\)\".*/\1/p")
CC := gcc
CFLAGS := -O2 -fPIC -shared -Wall -Wextra
LDFLAGS := -lcrypto

all: afalgprov.so

afalgprov.so: afalgprov.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

install: afalgprov.so
	install -m 0755 afalgprov.so "$(MOD_DIR)/"

clean:
	rm -f afalgprov.so
