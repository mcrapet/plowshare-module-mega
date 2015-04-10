bin_PROGRAMS = mega

if LOCAL_MODE
all-local:
	@echo 'Creating mega binary symlink to ~/.config/plowshare/exec'
	@$(MKDIR_P) $(HOME)/.config/plowshare/exec
	@$(LN_S) -f $(abs_builddir)/mega $(HOME)/.config/plowshare/exec/mega
endif

bindir = $(plowdir)/exec

mega_SOURCES = crypto.c
mega_CFLAGS = $(OPENSSL_CFLAGS)
mega_LDADD = $(OPENSSL_LIBS)
