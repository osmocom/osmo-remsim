SUBDIRS = rspro

AM_CFLAGS = -Wall -I$(top_srcdir)/include -I$(top_builddir)/include \
	    $(OSMOCORE_CFLAGS) $(OSMOGSM_CFLAGS) $(OSMOABIS_CFLAGS) \
	    $(PCSC_CFLAGS) $(USB_CFLAGS) $(OSMOSIM_CFLAGS) \
	    -I$(top_srcdir)/include/osmocom/rspro

RSPRO_LIBVERSION=0:0:0
lib_LTLIBRARIES = libosmo-rspro.la
libosmo_rspro_la_LDFLAGS = $(AM_LDFLAGS) -version-info $(RSPRO_LIBVERSION)
libosmo_rspro_la_LIBADD = $(OSMOCORE_LIBS) $(OSMOGSM_LIBS) $(OSMOABIS_LIBS) \
			  rspro/libosmo-asn1-rspro.la
libosmo_rspro_la_SOURCES = rspro_util.c

noinst_HEADERS = debug.h bankd.h client.h internal.h rspro_util.h slotmap.h \
		 simtrace2/apdu_dispatch.h \
		 simtrace2/libusb_util.h \
		 simtrace2/simtrace2-discovery.h \
		 simtrace2/simtrace_prot.h \
		 simtrace2/simtrace_usb.h

bin_PROGRAMS = pcsc_test remsim-bankd remsim-client simtrace2-remsim-client

pcsc_test_SOURCES = driver_core.c driver_pcsc.c main.c
pcsc_test_LDADD = $(OSMOCORE_LIBS) \
		  $(PCSC_LIBS) libosmo-rspro.la

remsim_bankd_SOURCES = slotmap.c bankd_main.c bankd_pcsc.c debug.c
remsim_bankd_LDADD = $(OSMOCORE_LIBS) $(OSMOGSM_LIBS) \
		     $(PCSC_LIBS) libosmo-rspro.la -lcsv

remsim_client_SOURCES = remsim_client.c remsim_client_fsm.c debug.c
remsim_client_LDADD = $(OSMOCORE_LIBS) $(OSMOGSM_LIBS) $(OSMOABIS_LIBS) \
		     libosmo-rspro.la

simtrace2_remsim_client_SOURCES = simtrace2-remsim_client.c remsim_client_fsm.c debug.c \
				  simtrace2/apdu_dispatch.c \
				  simtrace2/simtrace2-discovery.c \
				  simtrace2/libusb_util.c
simtrace2_remsim_client_LDADD = $(OSMOCORE_LIBS) $(OSMOGSM_LIBS) $(OSMOABIS_LIBS) $(USB_LIBS) $(OSMOSIM_LIBS)\
		     libosmo-rspro.la
