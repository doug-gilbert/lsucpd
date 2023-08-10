AC_INIT(lsucpd, 0.90, dgilbert@interlog.com)

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_MAINTAINER_MODE
# AM_CONFIG_HEADER(config.h)
AC_CONFIG_HEADERS([config.h])

AC_LANG(C++)
AC_PROG_CXX
AC_PROG_INSTALL

AC_CANONICAL_HOST

# AM_PROG_AR is supported and needed since automake v1.12+
ifdef([AM_PROG_AR], [AM_PROG_AR], [])

## AC_CHECK_HEADERS([linux/nvme_ioctl.h], [AC_DEFINE_UNQUOTED(HAVE_NVME, 1, [Found NVMe])], [], [])
## AC_CHECK_HEADERS([byteswap.h], [], [], [])

### AC_PROG_LIBTOOL

## AC_ARG_ENABLE([nvme-supp],
##   AC_HELP_STRING([--disable-nvme-supp], [remove all or most NVMe code]),
##   [AC_DEFINE_UNQUOTED(IGNORE_NVME, 1, [compile out NVMe support], )], [])

AC_ARG_ENABLE([debug],
              [  --enable-debug          Turn on debugging],
              [case "${enableval}" in
                  yes) debug=true ;;
                  no)  debug=false ;;
                  *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
               esac],[debug=false])
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])

AC_OUTPUT(Makefile src/Makefile doc/Makefile)
