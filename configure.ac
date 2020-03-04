AC_INIT([osmo-remsim],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[simtrace@lists.osmocom.org])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

LT_INIT

AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip 1.9 tar-ustar])
dnl tar-ustar: some asn1 filenames surpass the 99 char limit of tar, so we need
dnl to make tar allow longer filenames.


dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl include release helper
RELMAKE='-include osmo-release.mk'
AC_SUBST([RELMAKE])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_CC
AC_PROG_INSTALL

dnl check for pkg-config (explained in detail in libosmocore/configure.ac)
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

AC_CHECK_LIB(csv, csv_init, CSV_LIBS="-lcsv", [AC_MSG_ERROR([*** libcsv library not found!])])
AC_CHECK_HEADERS([csv.h])
AC_SUBST(CSV_LIBS)

PKG_CHECK_MODULES(OSMOCORE, libosmocore >= 1.3.0)
PKG_CHECK_MODULES(OSMOGSM, libosmogsm >= 0.11.0)
PKG_CHECK_MODULES(OSMOABIS, libosmoabis >= 0.8.0)

AC_ARG_ENABLE([remsim-server],[AS_HELP_STRING([--disable-remsim-server], [Build osmo-remsim-server])],
	[osmo_ac_build_server="$enableval"],[osmo_ac_build_server="yes"])
if test "$osmo_ac_build_server" = "yes"; then
	PKG_CHECK_MODULES(ULFIUS, libulfius)
	PKG_CHECK_MODULES(ORCANIA, liborcania)
	PKG_CHECK_MODULES(JANSSON, jansson)
	AC_DEFINE(BUILD_SERVER, 1, [Define if we want to build osmo-remsim-server])
fi
AM_CONDITIONAL(BUILD_SERVER, test "x$osmo_ac_build_server" = "xyes")
AC_SUBST(BUILD_SERVER)

AC_ARG_ENABLE([remsim-bankd],[AS_HELP_STRING([--disable-remsim-bankd], [Build osmo-remsim-bankd])],
	[osmo_ac_build_bankd="$enableval"],[osmo_ac_build_bankd="yes"])
if test "$osmo_ac_build_bankd" = "yes"; then
	AC_DEFINE(BUILD_BANKD, 1, [Define if we want to build osmo-remsim-bankd])
	PKG_CHECK_MODULES(OSMOSIM, libosmosim)
	PKG_CHECK_MODULES(PCSC, libpcsclite)
fi
AM_CONDITIONAL(BUILD_BANKD, test "x$osmo_ac_build_bankd" = "xyes")
AC_SUBST(BUILD_BANKD)

AC_ARG_ENABLE([remsim-client],[AS_HELP_STRING([--disable-remsim-client], [Build osmo-remsim-client])],
	[osmo_ac_build_client="$enableval"],[osmo_ac_build_client="yes"])
if test "$osmo_ac_build_client" = "yes"; then
	AC_DEFINE(BUILD_CLIENT, 1, [Define if we want to build osmo-remsim-client])
	PKG_CHECK_MODULES(OSMOSIM, libosmosim)
	PKG_CHECK_MODULES(OSMOUSB, libosmousb)
	PKG_CHECK_MODULES(OSMOSIMTRACE2, libosmo-simtrace2)
	PKG_CHECK_MODULES(USB, libusb-1.0)

	ifd_dropdir=`pkg-config --variable=usbdropdir libpcsclite`
	# allow user to override the dropdir for the PCSC driver bundle
	AC_ARG_WITH(usbdropdir, [--with-usbdropdir	PCSC bundle location],
				[usbdropdir="${withval}"], [usbdropdir="${ifd_dropdir}"])
	AC_SUBST(usbdropdir)
	_serialconfdir=`pkg-config --variable=serialconfdir libpcsclite`
	AC_ARG_WITH(serialconfdir, [--with-serialconfdir PCSC config directory location],
				[serialconfdir="${withval}"], [serialconfdir="${_serialconfdir}"])
	AC_SUBST(serialconfdir)
fi
AM_CONDITIONAL(BUILD_CLIENT, test "x$osmo_ac_build_client" = "xyes")
AC_SUBST(BUILD_CLIENT)


AC_CONFIG_MACRO_DIR([m4])

dnl checks for header files
AC_HEADER_STDC

AC_ARG_ENABLE(sanitize,
	[AS_HELP_STRING(
		[--enable-sanitize],
		[Compile with address sanitizer enabled],
	)],
	[sanitize=$enableval], [sanitize="no"])
if test x"$sanitize" = x"yes"
then
	CFLAGS="$CFLAGS -fsanitize=address -fsanitize=undefined"
	CPPFLAGS="$CPPFLAGS -fsanitize=address -fsanitize=undefined"
fi

AC_ARG_ENABLE(werror,
	AS_HELP_STRING(
		[--enable-werror],
		[Turn all compiler warnings into errors, with exceptions:
		 a) deprecation (allow upstream to mark deprecation without breaking builds);
		 b) "#warning" pragmas (allow to remind ourselves of errors without breaking builds)
		]
	)],
	[werror=$enableval], [werror="no"])
if test x"$werror" = x"yes"
then
	WERROR_FLAGS="-Werror"
	WERROR_FLAGS+=" -Wno-error=deprecated -Wno-error=deprecated-declarations"
	WERROR_FLAGS+=" -Wno-error=cpp" # "#warning"
	CFLAGS="$CFLAGS $WERROR_FLAGS"
	CPPFLAGS="$CPPFLAGS $WERROR_FLAGS"
fi

# Generate manuals
AC_ARG_ENABLE(manuals,
	[AS_HELP_STRING(
		[--enable-manuals],
		[Generate manual PDFs [default=no]],
	)],
	[osmo_ac_build_manuals=$enableval], [osmo_ac_build_manuals="no"])
AM_CONDITIONAL([BUILD_MANUALS], [test x"$osmo_ac_build_manuals" = x"yes"])
AC_ARG_VAR(OSMO_GSM_MANUALS_DIR, [path to common osmo-gsm-manuals files, overriding pkg-config and "../osmo-gsm-manuals"
	fallback])
if test x"$osmo_ac_build_manuals" = x"yes"
then
	# Find OSMO_GSM_MANUALS_DIR (env, pkg-conf, fallback)
	if test -n "$OSMO_GSM_MANUALS_DIR"; then
		echo "checking for OSMO_GSM_MANUALS_DIR... $OSMO_GSM_MANUALS_DIR (from env)"
	else
		OSMO_GSM_MANUALS_DIR="$($PKG_CONFIG osmo-gsm-manuals --variable=osmogsmmanualsdir 2>/dev/null)"
		if test -n "$OSMO_GSM_MANUALS_DIR"; then
			echo "checking for OSMO_GSM_MANUALS_DIR... $OSMO_GSM_MANUALS_DIR (from pkg-conf)"
		else
			OSMO_GSM_MANUALS_DIR="../osmo-gsm-manuals"
			echo "checking for OSMO_GSM_MANUALS_DIR... $OSMO_GSM_MANUALS_DIR (fallback)"
		fi
	fi
	if ! test -d "$OSMO_GSM_MANUALS_DIR"; then
		AC_MSG_ERROR("OSMO_GSM_MANUALS_DIR does not exist! Install osmo-gsm-manuals or set OSMO_GSM_MANUALS_DIR.")
	fi

	# Find and run check-depends
	CHECK_DEPENDS="$OSMO_GSM_MANUALS_DIR/check-depends.sh"
	if ! test -x "$CHECK_DEPENDS"; then
		CHECK_DEPENDS="osmo-gsm-manuals-check-depends"
	fi
	if ! $CHECK_DEPENDS; then
		AC_MSG_ERROR("missing dependencies for --enable-manuals")
	fi

	# Put in Makefile with absolute path
	OSMO_GSM_MANUALS_DIR="$(realpath "$OSMO_GSM_MANUALS_DIR")"
	AC_SUBST([OSMO_GSM_MANUALS_DIR])
fi

# https://www.freedesktop.org/software/systemd/man/daemon.html
AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],,
     [with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
     def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)

     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
   [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
    [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
    with_systemdsystemunitdir=no],
   [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

CFLAGS="$CFLAGS -Wall"
CPPFLAGS="$CPPFLAGS -Wall"

AC_MSG_RESULT([CFLAGS="$CFLAGS"])
AC_MSG_RESULT([CPPFLAGS="$CPPFLAGS"])

AC_OUTPUT(
	Makefile
	libosmo-rspro.pc
	contrib/Makefile
	contrib/etc_default/Makefile
	contrib/systemd/Makefile
	doc/Makefile
	doc/manuals/Makefile
	src/Makefile
	src/rspro/Makefile
	src/bankd/Makefile
	src/client/Makefile
	src/client/osmo-remsim-client-reader_conf
	src/server/Makefile
	include/Makefile
	include/osmocom/Makefile
	include/osmocom/rspro/Makefile
	)
