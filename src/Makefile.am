SUBDIRS = rspro

AM_CFLAGS = -Wall -I$(top_srcdir)/include -I$(top_builddir)/include \
	    $(OSMOCORE_CFLAGS) $(OSMOGSM_CFLAGS) $(OSMOABIS_CFLAGS) \
	    $(ASN1C_CFLAGS) $(PCSC_CFLAGS)

RSPRO_LIBVERSION=0:0:0
lib_LTLIBRARIES = libosmo-rspro.la
libosmo_rspro_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(RSPRO_LIBVERSION)
libosmo_rspro_la_LIBADD = $(OSMOCORE_LIBS) $(OSMOGSM_LIBS) $(OSMOABIS_LIBS) \
			  $(ASN1C_LIBS) rspro/libosmo-asn1-rspro.la
libosmo_rspro_la_SOURCES = rspro_util.c rspro_client.c

noinst_HEADERS = bankd.h internal.h

bin_PROGRAMS = pcsc_test remsim-bankd

pcsc_test_SOURCES = driver_core.c driver_pcsc.c main.c
pcsc_test_LDADD = $(OSMOCORE_LIBS) \
		  $(ASN1C_LIBS) $(PCSC_LIBS) libosmo-rspro.la

remsim_bankd_SOURCES = bankd_slotmap.c bankd_main.c
remsim_bankd_LDADD = $(OSMOCORE_LIBS) \
		     $(ASN1C_LIBS) $(PCSC_LIBS) libosmo-rspro.la
