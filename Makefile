##
# mega.co.nz plugin for Plowshare
##

# TODO:
# - check for openssl dev files (openssl/aes.h)
# - check for openssl libs (libcrypto.so)

# Paths you can override
PREFIX   = /usr/local
PLOWDIR ?= $(PREFIX)/share/plowshare4

# Compiler and tools
CC = gcc
CFLAGS = -Wall -O3 -s
INSTALL = install
RM = rm -f

# Files
SRC = src/crypto.c
OUT = mega

# Rules
compile: $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(OUT) -lcrypto

install: check_plowdir compile
	$(INSTALL) -d $(PLOWDIR)/plugins
	$(INSTALL) -m 644 module/mega.sh $(PLOWDIR)/modules/mega.sh
	$(INSTALL) -m 755 $(OUT) $(PLOWDIR)/plugins/mega
	@grep -q '^mega[[:space:]]' $(PLOWDIR)/modules/config || { \
	        echo "patching modules/config file" && \
	        echo "mega            |          | upload |        |      |       |" >> $(PLOWDIR)/modules/config; }

uninstall: check_plowdir
	$(RM) $(PLOWDIR)/plugins/mega
	$(RM) $(PLOWDIR)/modules/mega.sh
	@(grep -q '^mega[[:space:]]' $(PLOWDIR)/modules/config && \
	        echo "unpatching modules/config file" && \
	        sed -ie '/^mega[[:space:]]/d' $(PLOWDIR)/modules/config ) || true

# Note: sed -i is not BSD friendly!

clean:
	@$(RM) $(OUT)

check_plowdir:
	@test -f $(PLOWDIR)/core.sh || { echo "Invalid PLOWDIR, this is not a plowshare directory! Can't find core.sh. Abort."; false; }

.PHONY: install uninstall check_plowdir clean
