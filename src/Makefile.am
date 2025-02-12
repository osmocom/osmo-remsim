SUBDIRS = rspro .
if BUILD_BANKD
SUBDIRS += bankd
endif
if BUILD_SERVER
SUBDIRS += server
endif
SUBDIRS += client

AM_CFLAGS = -Wall \
	    -I$(top_srcdir)/include \
	    -I$(top_builddir)/include \
	    -I$(top_srcdir)/include/osmocom/rspro \
	    $(OSMONETIF_CFLAGS) \
	    $(OSMOGSM_CFLAGS) \
	    $(OSMOCORE_CFLAGS) \
	    $(NULL)

RSPRO_LIBVERSION=2:1:0
lib_LTLIBRARIES = libosmo-rspro.la
libosmo_rspro_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(RSPRO_LIBVERSION)
# OSMONETIF_LIBS, OSMOGSM_LIBS not needed, we don't use any of its symbols, only the header above
libosmo_rspro_la_LIBADD = $(OSMOCORE_LIBS) \
			  rspro/libosmo-asn1-rspro.la
libosmo_rspro_la_SOURCES = rspro_util.c asn1c_helpers.c

noinst_HEADERS = debug.h rspro_util.h slotmap.h rspro_client_fsm.h \
		 asn1c_helpers.h
