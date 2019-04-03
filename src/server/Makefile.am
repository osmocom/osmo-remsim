
AM_CFLAGS = -Wall -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_srcdir)/src \
	    -I$(top_srcdir)/include/osmocom/rspro \
	    $(OSMOCORE_CFLAGS) $(OSMOGSM_CFLAGS) $(OSMOABIS_CFLAGS) \
	    $(ULFIUS_CFLAGS) $(JANSSON_CFLAGS)

noinst_HEADERS = rspro_server.h rest_api.h

bin_PROGRAMS = osmo-remsim-server

osmo_remsim_server_SOURCES = remsim_server.c rspro_server.c rest_api.c \
			     ../rspro_util.c ../slotmap.c ../debug.c
osmo_remsim_server_LDADD = $(OSMOCORE_LIBS) $(OSMOGSM_LIBS) $(OSMOABIS_LIBS) \
			   $(ULFIUS_LIBS) $(JANSSON_LIBS) \
			   $(top_builddir)/src/libosmo-rspro.la

# as suggested in http://lists.gnu.org/archive/html/automake/2009-03/msg00011.html
FORCE:
$(top_builddir)/src/libosmo-rspro.la: FORCE
	(cd $(top_builddir)/src && $(MAKE) $(AM_MAKEFLAGS) libosmo-rspro.la)
