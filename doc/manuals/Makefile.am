EXTRA_DIST = \
    osmo-remsim-usermanual.adoc \
    osmo-remsim-usermanual-docinfo.xml \
    chapters

if BUILD_MANUALS
  ASCIIDOC = osmo-remsim-usermanual.adoc
  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.asciidoc.inc
  osmo-remsim-usermanual.pdf: $(srcdir)/chapters/*.adoc

  include $(OSMO_GSM_MANUALS_DIR)/build/Makefile.common.inc
endif
