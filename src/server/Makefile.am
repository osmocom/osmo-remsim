
AM_CFLAGS = -Wall -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_srcdir)/src \
	    -I$(top_srcdir)/include/osmocom/rspro \
	    $(OSMOCORE_CFLAGS) $(OSMOGSM_CFLAGS) $(OSMOABIS_CFLAGS) \
	    $(ULFIUS_CFLAGS) $(JANSSON_CFLAGS)

noinst_HEADERS = rspro_server.h rest_api.h

bin_PROGRAMS = remsim-server

remsim_server_SOURCES = remsim_server.c rspro_server.c rest_api.c ../rspro_util.c ../slotmap.c ../debug.c
remsim_server_LDADD = $(OSMOCORE_LIBS) $(OSMOGSM_LIBS) $(OSMOABIS_LIBS) \
		      $(ULFIUS_LIBS) $(JANSSON_LIBS) \
		      $(top_builddir)/src/libosmo-rspro.la
