AUTOMAKE_OPTIONS = foreign dist-bzip2

SUBDIRS = src include doc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libosmo-rspro.pc

EXTRA_DIST = asn1 .version README.md contrib/remsim-apitool.py

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir) \
	--with-usbdropdir=$$dc_install_base/$(usbdropdir) \
	--with-serialconfdir=$$dc_install_base/$(serialconfdir)

pkgcofigdir = $(libdir)/pkgconfig

@RELMAKE@

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
