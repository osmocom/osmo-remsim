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

CFLAGS="$CFLAGS -Wall"
CPPFLAGS="$CPPFLAGS -Wall"

AC_MSG_RESULT([CFLAGS="$CFLAGS"])
AC_MSG_RESULT([CPPFLAGS="$CPPFLAGS"])

AC_OUTPUT(
	Makefile
	src/Makefile
	src/rspro/Makefile
	src/server/Makefile
	include/Makefile
	include/osmocom/Makefile
	include/osmocom/rspro/Makefile
	)
