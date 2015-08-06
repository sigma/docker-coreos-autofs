dnl
dnl --------------------------------------------------------------------------
dnl AF_PATH_INCLUDE:
dnl
dnl Like AC_PATH_PROGS, but add to the .h file as well
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_PATH_INCLUDE,
[AC_PATH_PROGS($1,$2,$3,$4)
if test -n "$$1"; then
  AC_DEFINE(HAVE_$1,1,[define if you have $1])
  AC_DEFINE_UNQUOTED(PATH_$1, "$$1", [define if you have $1])
  HAVE_$1=1
else
  HAVE_$1=0
fi
AC_SUBST(HAVE_$1)])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_PROG:
dnl
dnl Like AC_CHECK_PROG, but fail configure if not found
dnl and only define PATH_<name> variable
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_CHECK_PROG,
[AC_PATH_PROGS($1,$2,$3,$4)
if test -n "$$1"; then
  AC_DEFINE_UNQUOTED(PATH_$1, "$$1", [define if you have $1])
  PATH_$1="$$1"
else
  AC_MSG_ERROR([required program $1 not found])
fi
AC_SUBST(PATH_$1)])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_SSS_LIB:
dnl
dnl Check if a sss autofs library exists.
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_CHECK_SSS_LIB,
[if test -z "$sssldir"; then
  AC_MSG_CHECKING(for sssd autofs library)
  for libd in /usr/lib64 /usr/lib; do
    if test -z "$sssldir"; then
      if test -e "$libd/sssd/modules/$2"; then
        sssldir=$libd/sssd/modules
      fi
    fi
  done
  if test -n "$sssldir"; then
    HAVE_$1=1
    AC_MSG_RESULT(yes)
  else
    HAVE_$1=0
    AC_MSG_RESULT(no)
  fi
fi])

dnl --------------------------------------------------------------------------
dnl AF_SLOPPY_MOUNT
dnl
dnl Check to see if mount(8) supports the sloppy (-s) option, and define
dnl the cpp variable HAVE_SLOPPY_MOUNT if so.  This requires that MOUNT is
dnl already defined by a call to AF_PATH_INCLUDE or AC_PATH_PROGS.
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_SLOPPY_MOUNT,
[if test -n "$MOUNT" ; then
  AC_MSG_CHECKING([if mount accepts the -s option])
  if "$MOUNT" -s > /dev/null 2>&1 ; then
    enable_sloppy_mount=yes
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
  fi
fi])


dnl --------------------------------------------------------------------------
dnl AF_LINUX_PROCFS
dnl
dnl Check for the Linux /proc filesystem
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_LINUX_PROCFS,
[AC_MSG_CHECKING(for Linux proc filesystem)
if test "x`cat /proc/sys/kernel/ostype 2>&-`" = "xLinux"
then
	linux_procfs=yes
else
	linux_procfs=no
fi
AC_MSG_RESULT($linux_procfs)
if test $linux_procfs = yes
then
	AC_DEFINE(HAVE_LINUX_PROCFS, 1,
		[Define if you have the Linux /proc filesystem.])
fi])

dnl --------------------------------------------------------------------------
dnl AF_INIT_D
dnl
dnl Check the location of the init.d directory
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_INIT_D,
[if test -z "$initdir"; then
  AC_MSG_CHECKING([location of the init.d directory])
  for init_d in /etc/init.d /etc/rc.d/init.d; do
    if test -z "$initdir"; then
      if test -d "$init_d"; then
	initdir="$init_d"
	AC_MSG_RESULT($initdir)
      fi
    fi
  done
fi])

dnl --------------------------------------------------------------------------
dnl AF_CONF_D
dnl
dnl Check the location of the configuration defaults directory
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_CONF_D,
[if test -z "$confdir"; then
  for conf_d in /etc/sysconfig /etc/defaults /etc/conf.d /etc/default; do
    if test -z "$confdir"; then
      if test -d "$conf_d"; then
	confdir="$conf_d"
      fi
    fi
  done
fi])

dnl --------------------------------------------------------------------------
dnl AF_MAP_D
dnl
dnl Check the location of the autofs maps directory
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_MAP_D,
[if test -z "$mapdir"; then
  for map_d in /etc/autofs /etc; do
    if test -z "$mapdir"; then
      if test -d "$map_d"; then
	mapdir="$map_d"
      fi
    fi
  done
fi])

dnl --------------------------------------------------------------------------
dnl AF_PID_D
dnl
dnl Check the location of the pid file directory.
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_PID_D,
[if test -z "$piddir"; then
  for pid_d in /run /var/run /tmp; do
    if test -z "$piddir"; then
      if test -d "$pid_d"; then
        piddir="$pid_d"
      fi
    fi
  done
fi])

dnl --------------------------------------------------------------------------
dnl AF_FIFO_D
dnl
dnl Check the location of the autofs fifos directory
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_FIFO_D,
[if test -z "$fifodir"; then
  for fifo_d in /run /var/run /tmp; do
    if test -z "$fifodir"; then
      if test -d "$fifo_d"; then
        fifodir="$fifo_d"
      fi
    fi
  done
fi])

dnl --------------------------------------------------------------------------
dnl AF_FLAG_D
dnl
dnl Check the location of the autofs flag file directory
dnl --------------------------------------------------------------------------
AC_DEFUN(AF_FLAG_D,
[if test -z "$flagdir"; then
  for flag_d in /run /var/run /tmp; do
    if test -z "$flagdir"; then
      if test -d "$flag_d"; then
        flagdir="$flag_d"
      fi
    fi
  done
fi])

dnl ----------------------------------- ##                   -*- Autoconf -*-
dnl Check if --with-dmalloc was given.  ##
dnl From Franc,ois Pinard               ##
dnl ----------------------------------- ##
dnl
dnl Copyright (C) 1996, 1998, 1999, 2000, 2001, 2002, 2003, 2005
dnl Free Software Foundation, Inc.
dnl
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl serial 3

AC_DEFUN([AM_WITH_DMALLOC],
[AC_MSG_CHECKING([if malloc debugging is wanted])
AC_ARG_WITH(dmalloc,
[  --with-dmalloc          use dmalloc, as in
			  http://www.dmalloc.com/dmalloc.tar.gz],
[if test "$withval" = yes; then
  AC_MSG_RESULT(yes)
  AC_DEFINE(WITH_DMALLOC,1,
	    [Define if using the dmalloc debugging malloc package])
  DMALLOCLIB="-ldmallocth"
  LDFLAGS="$LDFLAGS -g"
else
  AC_MSG_RESULT(no)
fi], [AC_MSG_RESULT(no)])
])

dnl --------------------------------------------------------------------------
dnl AF_WITH_SYSTEMD
dnl
dnl Check the location of the systemd unit files directory
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_WITH_SYSTEMD],
[AC_ARG_WITH(systemd,
[  --with-systemd@<:@=systemddir@:>@  install systemd unit file.  If 'yes'
			  probe the system for unit directory.
			  If a path is specified, assume that
			  is a valid install path.],
[if test "$withval" = yes; then
  if test -z "$systemddir"; then
    AC_MSG_CHECKING([location of the systemd unit files directory])
    for systemd_d in /usr/lib/systemd/system /usr/lib64/systemd/system /lib/systemd/system /lib64/systemd/system; do
      if test -z "$systemddir"; then
        if test -d "$systemd_d"; then
          systemddir="$systemd_d"
        fi
      fi
    done
  fi
  if test -n "$systemddir"; then
    AC_MSG_RESULT($systemddir)
  else
    AC_MSG_RESULT(not found)
  fi
else
 if test "$withval" != no; then
  systemddir=$withval
 fi
fi])
])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_LIBXML
dnl
dnl Check for lib xml
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_LIBXML],
[AC_PATH_PROGS(XML_CONFIG, xml2-config, no)
AC_MSG_CHECKING(for libxml2)
if test "$XML_CONFIG" = "no"
then
  AC_MSG_RESULT(no)
  HAVE_LIBXML=0
else
  AC_MSG_RESULT(yes)
  HAVE_LIBXML=1
  XML_LIBS=`$XML_CONFIG --libs`
  XML_FLAGS=`$XML_CONFIG --cflags`
  XML_VER=`$XML_CONFIG --version`
  XML_MAJOR=`echo $XML_VER|cut -d\. -f1`
  if test $XML_MAJOR -le 99
  then
    XML_MINOR=`echo $XML_VER|cut -d\. -f2`
    if test $XML_MINOR -le 99
    then
      XML_REV=`echo $XML_VER|cut -d\. -f3`
      if test $XML_REV -le 99; then
        AC_DEFINE(LIBXML2_WORKAROUND,1, [Use libxml2 tsd usage workaround])
      fi
    fi
  fi
fi])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_KRB5
dnl
dnl Check for Kerberos 5
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_KRB5],
[AC_PATH_PROGS(KRB5_CONFIG, krb5-config, no)
AC_MSG_CHECKING(for Kerberos library)
if test "$KRB5_CONFIG" = "no"
then
  AC_MSG_RESULT(no)
  HAVE_KRB5=0
else
  AC_MSG_RESULT(yes)
  HAVE_KRB5=1
  KRB5_LIBS=`$KRB5_CONFIG --libs`
  KRB5_FLAGS=`$KRB5_CONFIG --cflags`

  SAVE_CFLAGS=$CFLAGS
  SAVE_LIBS=$LIBS
  CFLAGS="$CFLAGS $KRB5_FLAGS"
  LIBS="$LIBS $KRB5_LIBS"

  AC_CHECK_FUNCS([krb5_principal_get_realm])
fi])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_LIBHESIOD
dnl
dnl Check for lib hesiod
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_LIBHESIOD],
[AC_MSG_CHECKING(for libhesiod)

# save current libs
af_check_hesiod_save_libs="$LIBS"
LIBS="$LIBS -lhesiod -lresolv"

AC_TRY_LINK(
  [ #include <hesiod.h> ],
  [ void *c; hesiod_init(&c); ],
  [ HAVE_HESIOD=1
    LIBHESIOD="$LIBHESIOD -lhesiod -lresolv"
    AC_MSG_RESULT(yes) ],
  [ AC_MSG_RESULT(no) ])

# restore libs
LIBS="$af_check_hesiod_save_libs"
])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_FUNC_LDAP_CREATE_PAGE_CONTROL
dnl
dnl Check for function ldap_create_page_control
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_FUNC_LDAP_CREATE_PAGE_CONTROL],
[AC_MSG_CHECKING(for ldap_create_page_control in -lldap)

# save current libs
af_check_ldap_create_page_control_save_libs="$LIBS"
LIBS="$LIBS -lldap"

AC_TRY_LINK(
  [ #include <ldap.h> ],
  [ LDAP *ld;
    ber_int_t ps;
    struct berval *c;
    int ic, ret;
    LDAPControl **clp;
    ret = ldap_create_page_control(ld,ps,c,ic,clp); ],
  [ af_have_ldap_create_page_control=yes
    AC_MSG_RESULT(yes) ],
  [ AC_MSG_RESULT(no) ])

if test "$af_have_ldap_create_page_control" = "yes"; then
  AC_DEFINE(HAVE_LDAP_CREATE_PAGE_CONTROL, 1,
        [Define to 1 if you have the `ldap_create_page_control' function.])
fi

# restore libs
LIBS="$af_check_ldap_create_page_control_save_libs"
])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_FUNC_LDAP_PARSE_PAGE_CONTROL
dnl
dnl Check for function ldap_parse_page_control
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_FUNC_LDAP_PARSE_PAGE_CONTROL],
[AC_MSG_CHECKING(for ldap_parse_page_control in -lldap)

# save current libs
af_check_ldap_parse_page_control_save_libs="$LIBS"
LIBS="$LIBS -lldap"

AC_TRY_LINK(
  [ #include <ldap.h> ],
  [ LDAP *ld;
    ber_int_t ct;
    struct berval *c;
    int ret;
    LDAPControl **clp;
    ret = ldap_parse_page_control(ld,clp,ct,c); ],
  [ af_have_ldap_parse_page_control=yes
    AC_MSG_RESULT(yes) ],
  [ AC_MSG_RESULT(no) ])

if test "$af_have_ldap_create_page_control" = "yes"; then
  AC_DEFINE(HAVE_LDAP_PARSE_PAGE_CONTROL, 1,
        [Define to 1 if you have the `ldap_parse_page_control' function.])
fi

# restore libs
LIBS="$af_check_ldap_parse_page_control_save_libs"
])

dnl --------------------------------------------------------------------------
dnl AF_CHECK_LIBTIRPC
dnl
dnl Use libtirpc for rpc transport
dnl --------------------------------------------------------------------------
AC_DEFUN([AF_CHECK_LIBTIRPC],
[
# save current flags
af_check_libtirpc_save_cflags="$CFLAGS"
af_check_libtirpc_save_ldflags="$LDFLAGS"
CFLAGS="$CFLAGS -I/usr/include/tirpc"
LDFLAGS="$LDFLAGS -ltirpc"

AC_TRY_LINK(
    [ #include <rpc/rpc.h> ],
    [ CLIENT *cl;
      struct sockaddr_in addr;
      int fd;
      unsigned long ul; struct timeval t; unsigned int ui;
      cl = clntudp_bufcreate(&addr,ul,ul,t,&fd,ui,ui); ],
    [ af_have_libtirpc=yes
      AC_MSG_RESULT(yes) ],
    [ AC_MSG_RESULT(no) ])

if test "$af_have_libtirpc" = "yes"; then
    AC_DEFINE(WITH_LIBTIRPC,1, [Define to 1 if you have the libtirpc library installed])
    AC_DEFINE(TIRPC_WORKAROUND,1, [Define to 1 to use the libtirpc tsd usage workaround])
    TIRPCLIB="-ltirpc"
fi

AC_CHECK_FUNCS([getrpcbyname getservbyname])

# restore flags
CFLAGS="$af_check_libtirpc_save_cflags"
LDFLAGS="$af_check_libtirpc_save_ldflags"
])

AC_DEFUN([AF_WITH_LIBTIRPC],
[AC_MSG_CHECKING([if libtirpc is requested and available])
AC_ARG_WITH(libtirpc,
[  --with-libtirpc         use libtirpc if available],
[if test "$withval" = yes; then
  AF_CHECK_LIBTIRPC()
else
  AC_MSG_RESULT(no)
fi], [AC_MSG_RESULT(no)])
])

