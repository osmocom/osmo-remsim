SUBDIRS = rspro

AM_CFLAGS = -Wall -I$(top_srcdir)/include -I$(top_builddir)/include \
	    $(OSMOCORE_CFLAGS) $(ASN1C_CFLAGS)

RSPRO_LIBVERSION=0:0:0
lib_LTLIBRARIES = libosmo-rspro.la
libosmo_rspro_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(RSPRO_LIBVERSION)
libosmo_rspro_la_LIBADD = $(OSMOCORE_LIBS) $(ASN1C_LIBS) rspro/libosmo-asn1-rspro.la
libosmo_rspro_la_SOURCES = rspro_util.c
