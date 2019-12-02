SUBDIRS = rspro
if BUILD_BANKD
SUBDIRS += bankd
endif
if BUILD_SERVER
SUBDIRS += server
endif

AM_CFLAGS = -Wall -I$(top_srcdir)/include -I$(top_builddir)/include \
	    $(OSMOCORE_CFLAGS) $(OSMOGSM_CFLAGS) $(OSMOABIS_CFLAGS) \
	    $(PCSC_CFLAGS) $(USB_CFLAGS) $(OSMOSIM_CFLAGS) \
	    -I$(top_srcdir)/include/osmocom/rspro

RSPRO_LIBVERSION=1:0:0
lib_LTLIBRARIES = libosmo-rspro.la
libosmo_rspro_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(RSPRO_LIBVERSION)
libosmo_rspro_la_LIBADD = $(OSMOCORE_LIBS) $(OSMOGSM_LIBS) $(OSMOABIS_LIBS) \
			  rspro/libosmo-asn1-rspro.la
libosmo_rspro_la_SOURCES = rspro_util.c asn1c_helpers.c

noinst_HEADERS = debug.h client.h rspro_util.h slotmap.h rspro_client_fsm.h \
		 asn1c_helpers.h \
		 simtrace2/apdu_dispatch.h \
		 simtrace2/libusb_util.h \
		 simtrace2/simtrace2-discovery.h \
		 simtrace2/simtrace_prot.h \
		 simtrace2/simtrace_usb.h

bin_PROGRAMS = osmo-remsim-client-st2

remsim_client_SOURCES = remsim_client.c rspro_client_fsm.c debug.c
remsim_client_LDADD = $(OSMOCORE_LIBS) $(OSMOGSM_LIBS) $(OSMOABIS_LIBS) \
		     libosmo-rspro.la

osmo_remsim_client_st2_SOURCES = simtrace2-remsim_client.c \
				 rspro_client_fsm.c debug.c \
				 simtrace2/apdu_dispatch.c \
				 simtrace2/simtrace2-discovery.c \
				 simtrace2/libusb_util.c
osmo_remsim_client_st2_LDADD = $(OSMOCORE_LIBS) $(OSMOGSM_LIBS) $(OSMOABIS_LIBS) \
			       $(USB_LIBS) $(OSMOSIM_LIBS) libosmo-rspro.la
