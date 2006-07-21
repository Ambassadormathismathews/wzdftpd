# CFLAGS and library paths for wzdftpd
# Roman Bogorodskiy <bogorodskiy@inbox.ru>
# $Header$

dnl Usage:
dnl AM_PATH_WZD([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl
dnl Example:
dnl AM_PATH_WZD(0.4.0, , AC_MSG_ERROR([*** wzdftpd >= 0.4.0 not installed - please install first ***]))
dnl
dnl Defines WZD_CFLAGS, WZD_LIBS  WZD_VERSION
dnl

dnl WZD_TEST_VERSION(AVAILABLE-VERSION, NEEDED-VERSION [, ACTION-IF-OKAY [, ACTION-IF-NOT-OKAY]])
AC_DEFUN([WZD_TEST_VERSION], [

# Determine which version number is greater. Prints 2 to stdout if	
# the second number is greater, 1 if the first number is greater,	
# 0 if the numbers are equal.						
									
# Written 15 December 1999 by Ben Gertzfield <che@debian.org>		
# Revised 15 December 1999 by Jim Monty <monty@primenet.com>		
									
    AC_PROG_AWK
    wzd_got_version=[` $AWK '						\
BEGIN {									\
    print vercmp(ARGV[1], ARGV[2]);					\
}									\
									\
function vercmp(ver1, ver2,    ver1arr, ver2arr,			\
                               ver1len, ver2len,			\
                               ver1int, ver2int, len, i, p) {		\
									\
    ver1len = split(ver1, ver1arr, /\./);				\
    ver2len = split(ver2, ver2arr, /\./);				\
									\
    len = ver1len > ver2len ? ver1len : ver2len;			\
									\
    for (i = 1; i <= len; i++) {					\
        p = 1000 ^ (len - i);						\
        ver1int += ver1arr[i] * p;					\
        ver2int += ver2arr[i] * p;					\
    }									\
									\
    if (ver1int < ver2int)						\
        return 2;							\
    else if (ver1int > ver2int)						\
        return 1;							\
    else								\
        return 0;							\
}' $1 $2`]								

    if test $wzd_got_version -eq 2; then 	# failure
	ifelse([$4], , :, $4)			
    else  					# success!
	ifelse([$3], , :, $3)
    fi
])

AC_DEFUN([AM_PATH_WZD],
[
AC_ARG_WITH(wzd-prefix,[  --with-wzd-prefix=PFX  Prefix where wzdftpd is installed (optional)],
	wzd_config_prefix="$withval", wzd_config_prefix="")
AC_ARG_WITH(wzd-exec-prefix,[  --with-wzd-exec-prefix=PFX Exec prefix where wzdftpd is installed (optional)],
	wzd_config_exec_prefix="$withval", wzd_config_exec_prefix="")

if test x$wzd_config_exec_prefix != x; then
    wzd_config_args="$wzd_config_args --exec-prefix=$wzd_config_exec_prefix"
    if test x${WZD_CONFIG+set} != xset; then
	WZD_CONFIG=$wzd_config_exec_prefix/bin/wzd-config
    fi
fi

if test x$wzd_config_prefix != x; then
    wzd_config_args="$wzd_config_args --prefix=$wzd_config_prefix"
    if test x${WZD_CONFIG+set} != xset; then
  	WZD_CONFIG=$wzd_config_prefix/bin/wzd-config
    fi
fi

AC_PATH_PROG(WZD_CONFIG, wzd-config, no)
min_wzd_version=ifelse([$1], ,0.4.0, $1)

if test "$WZD_CONFIG" = "no"; then
    no_wzd=yes
else
    WZD_CFLAGS=`$WZD_CONFIG $wzd_config_args --cflags`
    WZD_LIBS=`$WZD_CONFIG $wzd_config_args --libs`
    WZD_VERSION=`$WZD_CONFIG $wzd_config_args --version`

    WZD_TEST_VERSION($WZD_VERSION, $min_wzd_version, ,no_wzd=version)
fi

AC_MSG_CHECKING(for wzdftpd version >= $min_wzd_version)

if test "x$no_wzd" = x; then
    AC_MSG_RESULT(yes)
    ifelse([$2], , :, [$2])
else
    AC_MSG_RESULT(no)

    if test "$WZD_CONFIG" = "no" ; then
	echo "*** The wzd-config script installed by wzdftpd could not be found."
      	echo "*** If wzdftpd was installed in PREFIX, make sure PREFIX/bin is in"
	echo "*** your path, or set the WZD_CONFIG environment variable to the"
	echo "*** full path to wzd-config."
    else
	if test "$no_wzd" = "version"; then
	    echo "*** An old version of wzdftpd, $WZD_VERSION, was found."
	    echo "*** You need a version of wzdftpd newer than $min_wzd_version."
	    echo "*** The latest version of wzdftpd is always available from"
	    echo "*** http://wzdftpd.net"
	    echo "***"
	fi
    fi
    WZD_CFLAGS=""
    WZD_LIBS=""
    ifelse([$3], , :, [$3])
fi
AC_SUBST(WZD_CFLAGS)
AC_SUBST(WZD_LIBS)
AC_SUBST(WZD_VERSION)
])
