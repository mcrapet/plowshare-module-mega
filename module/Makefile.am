moduledir = $(plowdir)/modules

module_SCRIPTS = mega.sh

EXTRA_DIST = $(module_SCRIPTS) config

if LOCAL_MODE
all-local:
	@echo 'Creating Plowshare module symlink'
	@$(LN_S) -f module/mega.sh $(top_srcdir)/mega.sh
	@$(LN_S) -f module/config  $(top_srcdir)/config
else
$(DESTDIR)$(moduledir)/config: $(srcdir)/config
	@$(INSTALL_SCRIPT) $< $@

install-data-hook: $(DESTDIR)$(moduledir)/config
	@grep -q '^mega[[:space:]]' $< || { \
		echo 'patching modules/config file' && \
		echo 'mega            | download | upload |        | list | probe |' >> $<; }

uninstall-hook: $(DESTDIR)$(moduledir)/config
	@grep -q '^mega[[:space:]]' $< && \
		echo 'unpatching modules/config file' && \
		mv $< $<.bak && sed -e '/^mega[[:space:]]/d' $<.bak > $< || true
endif
