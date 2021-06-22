OSMOCONF_FILES = \
	bankd_pcsc_slots.csv \
	$(NULL)

osmoconfdir = $(sysconfdir)/osmocom
osmoconf_DATA = $(OSMOCONF_FILES)

EXTRA_DIST = $(OSMOCONF_FILES)

CFG_FILES = find $(srcdir) -name '*.cfg*' -o -name '*.csv' | sed -e 's,^$(srcdir),,'

dist-hook:
	for f in $$($(CFG_FILES)); do \
		j="$(distdir)/$$f" && \
		$(INSTALL_DATA) -D $(srcdir)/$$f $$j; \
	done

install-data-hook:
	for f in $$($(CFG_FILES)); do \
		j="$(DESTDIR)$(docdir)/examples/$$f" && \
		$(INSTALL_DATA) -D $(srcdir)/$$f $$j; \
	done

uninstall-hook:
	@$(PRE_UNINSTALL)
	for f in $$($(CFG_FILES)); do \
		j="$(DESTDIR)$(docdir)/examples/$$f" && \
		$(RM) $$j; \
	done
