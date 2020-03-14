AM_CFLAGS = -Wall -I$(top_srcdir)/include -I/$(top_builddir)/include -I$(top_srcdir)/src \
	    $(OSMOCORE_CFLAGS) $(OSMOGSM_CFLAGS) $(OSMOABIS_CFLAGS) \
	    $(PCSC_CFLAGS) $(USB_CFLAGS) \
	    $(OSMOSIMTRACE2_CFLAGS) \
	    -I$(top_srcdir)/include/osmocom/rspro

bin_PROGRAMS = osmo-remsim-client-shell

osmo_remsim_client_shell_SOURCES = user_shell.c remsim_client_main.c \
				   remsim_client.c main_fsm.c ../rspro_client_fsm.c ../debug.c
osmo_remsim_client_shell_CFLAGS = $(AM_CFLAGS)
osmo_remsim_client_shell_LDADD = $(OSMOCORE_LIBS) $(OSMOGSM_LIBS) $(OSMOABIS_LIBS) \
		      $(top_builddir)/src/libosmo-rspro.la

if BUILD_CLIENT_IFDHANDLER
EXTRA_DIST=PkgInfo osmo-remsim-client-reader_conf.in
serialconf_DATA=osmo-remsim-client-reader_conf
bundledir=$(usbdropdir)/libifd-osmo-remsim-client.bundle/Contents
bundle_DATA=PkgInfo
bundlelinuxdir=$(bundledir)/Linux
bundlelinux_LTLIBRARIES = libifd_remsim_client.la
libifd_remsim_client_la_SOURCES = user_ifdhandler.c \
				   remsim_client.c main_fsm.c ../rspro_client_fsm.c ../debug.c
libifd_remsim_client_la_CFLAGS = $(AM_CFLAGS)
libifd_remsim_client_la_CPPFLAGS = $(PCSC_CFLAGS)
libifd_remsim_client_la_LDFLAGS = -no-undefined
libifd_remsim_client_la_LIBADD = $(OSMOCORE_LIBS) $(OSMOGSM_LIBS) $(OSMOABIS_LIBS) \
		      $(top_builddir)/src/libosmo-rspro.la
endif

if BUILD_CLIENT_ST2
bin_PROGRAMS += osmo-remsim-client-st2
osmo_remsim_client_st2_SOURCES = user_simtrace2.c remsim_client_main.c \
				 remsim_client.c main_fsm.c ../rspro_client_fsm.c ../debug.c
osmo_remsim_client_st2_CPPFLAGS = -DUSB_SUPPORT
osmo_remsim_client_st2_CFLAGS = $(AM_CFLAGS)
osmo_remsim_client_st2_LDADD = $(OSMOCORE_LIBS) $(OSMOGSM_LIBS) $(OSMOABIS_LIBS) \
			       $(OSMOUSB_LIBS) $(OSMOSIMTRACE2_LIBS) \
			       $(USB_LIBS) \
			       $(top_builddir)/src/libosmo-rspro.la
endif

noinst_HEADERS = client.h 
