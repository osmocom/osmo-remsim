AM_CFLAGS = -Wall \
	    -I$(top_srcdir)/include \
	    -I/$(top_builddir)/include \
	    -I$(top_srcdir)/src \
	    -I$(top_srcdir)/include/osmocom/rspro \
	    $(OSMOABIS_CFLAGS) \
	    $(OSMONETIF_CFLAGS) \
	    $(OSMOGSM_CFLAGS) \
	    $(OSMOCORE_CFLAGS) \
	    $(PCSC_CFLAGS) $(USB_CFLAGS) \
	    $(OSMOSIMTRACE2_CFLAGS) \
	    $(NULL)

bin_PROGRAMS = osmo-remsim-client-shell

osmo_remsim_client_shell_SOURCES = user_shell.c remsim_client_main.c \
				   remsim_client.c main_fsm.c ../rspro_client_fsm.c ../debug.c
osmo_remsim_client_shell_CFLAGS = $(AM_CFLAGS)
osmo_remsim_client_shell_LDADD = $(top_builddir)/src/libosmo-rspro.la \
				 $(OSMOABIS_LIBS) \
				 $(OSMONETIF_LIBS) \
				 $(OSMOGSM_LIBS) \
				 $(OSMOCORE_LIBS) \
				 $(NULL)

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
libifd_remsim_client_la_LIBADD = $(top_builddir)/src/libosmo-rspro.la \
				 $(OSMOABIS_LIBS) \
				 $(OSMONETIF_LIBS) \
				 $(OSMOGSM_LIBS) \
				 $(OSMOCORE_LIBS) \
				 $(NULL)
endif

if BUILD_CLIENT_ST2
bin_PROGRAMS += osmo-remsim-client-st2
osmo_remsim_client_st2_SOURCES = user_simtrace2.c remsim_client_main.c \
				 remsim_client.c main_fsm.c ../rspro_client_fsm.c ../debug.c
osmo_remsim_client_st2_CPPFLAGS = -DUSB_SUPPORT -DSIMTRACE_SUPPORT
osmo_remsim_client_st2_CFLAGS = $(AM_CFLAGS)
osmo_remsim_client_st2_LDADD = $(top_builddir)/src/libosmo-rspro.la \
			       $(OSMOABIS_LIBS) \
			       $(OSMONETIF_LIBS) \
			       $(OSMOSIMTRACE2_LIBS) \
			       $(OSMOGSM_LIBS) \
			       $(OSMOCORE_LIBS) \
			       $(OSMOUSB_LIBS) \
			       $(USB_LIBS) \
			       $(NULL)
endif

noinst_HEADERS = client.h
