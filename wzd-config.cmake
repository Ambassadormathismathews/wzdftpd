#!/bin/sh
#
# $Header$

# order is important
prefix="@CMAKE_INSTALL_PREFIX@"
exec_prefix="${prefix}"
exec_prefix_set="no"
datarootdir="${prefix}/share"
data_dir="@datadir@/@PACKAGE@"

version="@WZD_VERSION@"
include_dir="${prefix}/include"
wzd_include_dir="${prefix}/include/@PACKAGE@"
lib_dir="${prefix}/lib"

#ssl_flags="@WZD_SSL_LIBS@"
#ssl_cflags="@WZD_SSL_INCLUDES@"
#pth_libs="@PTHREAD_CFLAGS@ @PTHREAD_LIBS@"

# default for applications
library=libwzd

usage()
{
    cat <<EOF
Usage: $0 [OPTIONS] [LIBRARIES]
Options:
    [--prefix[=DIR]]
    [--exec-prefix[=DIR]]
    [--version]
    [--libs]
    [--cflags]
    [--data-dir]
Libraries:
    libwzd	wzdftpd application
    libwzd-core	wzdftpd internal module

EOF
    exit $1
}

if test $# -eq 0; then
    usage 1 1>&2
fi


while test $# -gt 0; do
    case "$1" in
	-*=*) optarg=`echo "$1" | sed 's/[-_a-zA-Z0-9]*=//'` ;;
	*) optarg= ;;
    esac

    case $1 in
	--prefix=*)
	    prefix=$optarg
	    if test $exec_prefix_set = no ; then
		exec_prefix=$optarg
	    fi
	    ;;

	--prefix)
	    echo_prefix=yes
	    ;;

	--exec-prefix=*)
	    exec_prefix=$optarg
	    exec_prefix_set=yes
	    ;;

	--exec-prefix)
	    echo_exec_prefix=yes
	    ;;

	--version)
	    echo $version
	    ;;

	--cflags)
	    echo_cflags=yes
	    ;;

	--libs)
	    echo_libs=yes
	    ;;

	--data-dir)
	    echo_data_dir=yes
	    ;;
	libwzd)
	    library=libwzd
	    ;;
	libwzd-core)
	    library=libwzd-core
	    ;;
	*)
	    usage 1 1>&2
	    ;;
    esac
  shift
done

if test "$echo_prefix" = "yes"; then
    echo $prefix
fi

if test "$echo_exec_prefix" = "yes"; then
    echo $exec_prefix
fi

if test "$include_dir" != "/usr/include"; then
    cflags="-I$include_dir -I$wzd_include_dir $ssl_cflags"
else
    cflags="-I$wzd_include_dir $ssl_cflags"
fi

if test "$library" = 'libwzd'; then
    lib_flags="-lwzd"
fi

if test "$library" = 'libwzd-core'; then
    lib_flags="-lwzd_core $pth_libs"
fi

if test "$lib_dir" != "/usr/lib"; then
    libs="-L$lib_dir $lib_flags $ssl_flags"
else
    libs="$lib_flags $ssl_flags"
fi

if test "$echo_cflags" = "yes"; then
    echo $cflags
fi

if test "$echo_libs" = "yes"; then
    echo $libs
fi

if test "$echo_data_dir" = "yes"; then
    echo $data_dir
fi
