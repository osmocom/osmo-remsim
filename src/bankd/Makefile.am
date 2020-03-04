AM_CFLAGS = -Wall -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_srcdir)/src \
	    -I$(top_srcdir)/include/osmocom/rspro \
	    $(OSMOCORE_CFLAGS) $(OSMOGSM_CFLAGS) $(OSMOABIS_CFLAGS) \
	    $(PCSC_CFLAGS)

noinst_HEADERS = bankd.h internal.h

bin_PROGRAMS = osmo-remsim-bankd
noinst_PROGRAMS = pcsc_test

pcsc_test_SOURCES = driver_core.c driver_pcsc.c main.c
pcsc_test_LDADD = $(OSMOCORE_LIBS) \
		  $(PCSC_LIBS) $(top_builddir)/src/libosmo-rspro.la

osmo_remsim_bankd_SOURCES = ../slotmap.c ../rspro_client_fsm.c ../debug.c \
			  bankd_main.c bankd_pcsc.c
osmo_remsim_bankd_LDADD = $(OSMOCORE_LIBS) $(OSMOGSM_LIBS) $(OSMOABIS_LIBS) \
			  $(PCSC_LIBS) $(CSV_LIBS) $(top_builddir)/src/libosmo-rspro.la

# as suggested in http://lists.gnu.org/archive/html/automake/2009-03/msg00011.html
FORCE:
$(top_builddir)/src/libosmo-rspro.la: FORCE
	(cd $(top_builddir)/src && $(MAKE) $(AM_MAKEFLAGS) libosmo-rspro.la)
