AC_INIT(lsucpd, 0.90, dgilbert@interlog.com)

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_MAINTAINER_MODE
# AM_CONFIG_HEADER(config.h)
AC_CONFIG_HEADERS([config.h])

AC_LANG(C++)
AC_PROG_CXX
AC_PROG_INSTALL

AC_CANONICAL_HOST

AC_CHECK_HEADERS([format], [FMT_LDADD=''], [FMT_LDADD='-lfmt'], [])
AC_SUBST(FMT_LDADD)

AC_CHECK_HEADERS([source_location], [], [], [])

# AM_PROG_AR is supported and needed since automake v1.12+
ifdef([AM_PROG_AR], [AM_PROG_AR], [])

AC_ARG_ENABLE([debug],
              [  --enable-debug          Turn on debugging],
              [case "${enableval}" in
                  yes) debug=true ;;
                  no)  debug=false ;;
                  *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
               esac],[debug=false])

AC_ARG_ENABLE([static],
    [AS_HELP_STRING([--enable-static],
        [build static libraries @<:@default=yes@:>@])],
    [enable_static=$enableval],
    [enable_static=yes])

AC_ARG_ENABLE([shared],
    [AS_HELP_STRING([--disable-shared],
        [do not build shared libraries @<:@default=yes@:>@])],
    [enable_shared=$enableval],
    [enable_shared=yes])

AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])
AM_CONDITIONAL([BUILD_STATIC], [test "x$enable_static" = "xyes"])
AM_CONDITIONAL([BUILD_SHARED], [test "x$enable_shared" = "xyes"])

AC_CONFIG_FILES([
	Makefile
        src/Makefile
        doc/Makefile
])
AC_OUTPUT
