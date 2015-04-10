moduledir = $(plowdir)/modules

module_DATA = mega.sh

EXTRA_DIST = $(module_DATA) config

if LOCAL_MODE
all-local:
	@echo 'Creating Plowshare module symlink'
	@$(LN_S) -f module/mega.sh $(top_srcdir)/mega.sh
	@$(LN_S) -f module/config  $(top_srcdir)/config
else
$(moduledir)/config:
	@cp config $@

install-data-hook: $(moduledir)/config
	@chmod a+x $(moduledir)/mega.sh
	@grep -q '^mega[[:space:]]' $< || { \
		echo 'patching modules/config file' && \
		echo 'mega            | download | upload |        | list | probe |' >> $<; }

uninstall-hook: $(moduledir)/config
	@grep -q '^mega[[:space:]]' $< && \
		echo 'unpatching modules/config file' && \
		mv $< $<.bak && sed -e '/^mega[[:space:]]/d' $<.bak > $< || true
endif
