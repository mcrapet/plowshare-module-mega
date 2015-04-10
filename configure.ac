AC_INIT(plowshare-module-mega, 1.0.1)

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects
        tar-pax no-dist-gzip dist-bzip2])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LN_S

AC_ARG_ENABLE(
    [local],
    [AS_HELP_STRING(
        [--enable-local],
        [don't install, and use current directory. Use this is you plan to use plowmod])],
    [enable_local=yes],
    [enable_local=""])
dnl AC_SUBST([LOCAL_MODE], [$enable_local])
AM_CONDITIONAL(LOCAL_MODE, test "$enable_local" = yes)

AC_ARG_WITH(
    [plowdir],
    [AC_HELP_STRING(
        [--with-plowdir=DIR],
        [change default Plowshare installation directory @<:@DATAROOTDIR/plowshare@:>@])],
    [
        if ! test -f "$withval/core.sh" ; then
          AC_MSG_WARN([*** plowdir doesn't not appear to be a Plowshare installation path! Can't find core.sh. Continue anyway.])
        fi
        plowdir=$withval
    ],
    [plowdir=$datarootdir/plowshare])
AC_SUBST(plowdir)

dnl Dependencies
PKG_CHECK_MODULES([OPENSSL], [libcrypto])

dnl Output the makefile
AC_CONFIG_FILES([Makefile src/Makefile module/Makefile])
AC_OUTPUT
