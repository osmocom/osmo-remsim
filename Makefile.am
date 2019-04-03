AUTOMAKE_OPTIONS = foreign dist-bzip2

SUBDIRS = src include doc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libosmo-rspro.pc

EXTRA_DIST = asn1 .version README.md

pkgcofigdir = $(libdir)/pkgconfig

@RELMAKE@

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version
