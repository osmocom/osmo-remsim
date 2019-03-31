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

AC_CHECK_LIB(csv, csv_init, LIBS="$LIBS -lcsv", [AC_MSG_ERROR([*** libcsv library not found!])])
AC_CHECK_HEADERS([csv.h])

PKG_CHECK_MODULES(OSMOCORE, libosmocore >= 0.11.0)
PKG_CHECK_MODULES(OSMOGSM, libosmogsm >= 0.11.0)
PKG_CHECK_MODULES(OSMOABIS, libosmoabis)
PKG_CHECK_MODULES(OSMOSIM, libosmosim)
PKG_CHECK_MODULES(PCSC, libpcsclite)
PKG_CHECK_MODULES(USB, libusb-1.0)
PKG_CHECK_MODULES(ULFIUS, libulfius)
PKG_CHECK_MODULES(JANSSON, jansson)

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

CFLAGS="$CFLAGS -Wall"
CPPFLAGS="$CPPFLAGS -Wall"

AC_MSG_RESULT([CFLAGS="$CFLAGS"])
AC_MSG_RESULT([CPPFLAGS="$CPPFLAGS"])

AC_OUTPUT(
	Makefile
	doc/Makefile
	doc/manuals/Makefile
	src/Makefile
	src/rspro/Makefile
	src/server/Makefile
	include/Makefile
	include/osmocom/Makefile
	include/osmocom/rspro/Makefile
	)
