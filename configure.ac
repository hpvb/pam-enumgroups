AC_PREREQ([2.69])
AC_INIT([pam-enumgroups], [1.0.0], [https://github.com/hpvb/pam-enumgroups/issues])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([pam_enumgroups.c])

AC_PROG_CC

AM_INIT_AUTOMAKE(1.9.6)
AM_PROG_LIBTOOL
AM_DISABLE_STATIC

AC_CHECK_HEADERS([stdlib.h syslog.h security/pam_modules.h])
AC_CHECK_FUNCS([endgrent strerror])

AC_ARG_WITH([libsecuritydir],
    [AS_HELP_STRING([--with-libsecuritydir],
        [Directory to install PAM modules [LIBDIR/security]])],
    [], [with_libsecuritydir='$(libdir)/security'])
AC_SUBST([libsecuritydir], [$with_libsecuritydir])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
