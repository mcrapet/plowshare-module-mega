##
# mega.co.nz plugin for Plowshare
# This Makefile follow GNU conventions and support the $(DESTDIR) variable.
##

# TODO:
# - check for openssl dev files (openssl/aes.h)
# - check for openssl libs (libcrypto.so)

# Paths you can override
PREFIX   = /usr
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
	$(INSTALL) -d $(DESTDIR)$(PLOWDIR)/plugins
	$(INSTALL) -m 755 $(OUT) $(DESTDIR)$(PLOWDIR)/plugins/mega
	$(INSTALL) -D -m 644 module/mega.sh $(DESTDIR)$(PLOWDIR)/modules/mega.sh
ifeq ($(DESTDIR),)
	@grep -q '^mega[[:space:]]' $(PLOWDIR)/modules/config || { \
	        echo 'patching modules/config file' && \
	        echo 'mega            | download | upload |        |      |       |' >> $(PLOWDIR)/modules/config; }
endif

uninstall: check_plowdir
	$(RM) $(PLOWDIR)/plugins/mega
	$(RM) $(PLOWDIR)/modules/mega.sh
ifeq ($(DESTDIR),)
	@(grep -q '^mega[[:space:]]' $(PLOWDIR)/modules/config && \
	        echo 'unpatching modules/config file' && \
	        sed -i -e '/^mega[[:space:]]/d' $(PLOWDIR)/modules/config ) || true
endif

# Note: sed -i is not BSD friendly!

clean:
	@$(RM) $(OUT)

check_plowdir:
ifeq ($(DESTDIR),)
	@test -f $(PLOWDIR)/core.sh || { echo 'Invalid PLOWDIR, this is not a plowshare directory! Can'\''t find core.sh. Abort.'; false; }
endif

name:
	@echo "git$$(date +%Y%m%d).$$(git log --pretty=format:%h -1 master)"

.PHONY: install uninstall check_plowdir clean
