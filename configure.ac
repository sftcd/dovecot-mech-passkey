AC_PREREQ([2.69])

m4_define([mech_passkey_plugin_VERSION],
    m4_esyscmd_s([build-aux/git-version-gen]))

AC_INIT([dovecot-mech-passkey-plugin], [m4_defn([mech_passkey_plugin_VERSION])], [dovecot@dovecot.org])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AC_CONFIG_HEADERS([dummy-config.h])

AM_INIT_AUTOMAKE([no-define foreign tar-ustar])
AM_SILENT_RULES([yes])

AM_MAINTAINER_MODE

AC_PROG_CC
AC_PROG_CPP
LT_INIT

DC_DOVECOT
DC_DOVECOT_MODULEDIR

PKG_CHECK_MODULES([FIDO2], [libfido2], , AC_MSG_ERROR([Cannot find libfido2]))
PKG_CHECK_MODULES([CBOR], [libcbor], , AC_MSG_ERROR([Cannot find libcbor]))

LIBDOVECOT_INCLUDE="$LIBDOVECOT_INCLUDE $LIBDOVECOT_STORAGE_INCLUDE"
CFLAGS="$CFLAGS $EXTRA_CFLAGS"
LIBS="$DOVECOT_LIBS"

AC_SUBST(LIBDOVECOT_INCLUDE)
AC_SUBST(DOVECOT_BINARY_CFLAGS)
AC_SUBST(DOVECOT_BINARY_LDFLAGS)

AS_IF([test "$AR_FLAGS" = "cru"], [AR_FLAGS="cr"], [])
AC_SUBST([AR_FLAGS])

AC_CONFIG_FILES([
Makefile
src/Makefile
build-aux/run-test.sh
])

AC_OUTPUT
