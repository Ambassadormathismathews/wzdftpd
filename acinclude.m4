AC_DEFUN([AC_PATH_PROG_REQUIRE],
[
  AC_PATH_PROG($1, $2, no)
  if test "x$$1" == "xno"; then
    AC_MSG_ERROR($2 not found)
  fi
  AC_SUBST($1)
])

dnl Available from the GNU Autoconf Macro Archive at:
dnl http://www.gnu.org/software/ac-archive/htmldoc/acx_pthread.html
dnl
AC_DEFUN([ACX_PTHREAD], [
AC_REQUIRE([AC_CANONICAL_HOST])
AC_LANG_SAVE
AC_LANG_C
acx_pthread_ok=no

# We used to check for pthread.h first, but this fails if pthread.h
# requires special compiler flags (e.g. on True64 or Sequent).
# It gets checked for in the link test anyway.

# First of all, check if the user has set any of the PTHREAD_LIBS,
# etcetera environment variables, and if threads linking works using
# them:
if test x"$PTHREAD_LIBS$PTHREAD_CFLAGS" != x; then
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        AC_MSG_CHECKING([for pthread_join in LIBS=$PTHREAD_LIBS with CFLAGS=$PTHREAD_CFLAGS])
        AC_TRY_LINK_FUNC(pthread_join, acx_pthread_ok=yes)
        AC_MSG_RESULT($acx_pthread_ok)
        if test x"$acx_pthread_ok" = xno; then
                PTHREAD_LIBS=""
                PTHREAD_CFLAGS=""
        fi
        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"
fi

# We must check for the threads library under a number of different
# names; the ordering is very important because some systems
# (e.g. DEC) have both -lpthread and -lpthreads, where one of the
# libraries is broken (non-POSIX).

# Create a list of thread flags to try.  Items starting with a "-" are
# C compiler flags, and other items are library names, except for "none"
# which indicates that we try without any flags at all.

acx_pthread_flags="pthreads none -Kthread -kthread lthread -pthread -pthreads -mthreads pthread -lpthread --thread-safe -mt"

# The ordering *is* (sometimes) important.  Some notes on the
# individual items follow:

# pthreads: AIX (must check this before -lpthread)
# none: in case threads are in libc; should be tried before -Kthread and
#       other compiler flags to prevent continual compiler warnings
# -Kthread: Sequent (threads in libc, but -Kthread needed for pthread.h)
# -kthread: FreeBSD kernel threads (preferred to -pthread since SMP-able)
# lthread: LinuxThreads port on FreeBSD (also preferred to -pthread)
# -pthread: Linux/gcc (kernel threads), BSD/gcc (userland threads)
# -pthreads: Solaris/gcc
# -mthreads: Mingw32/gcc, Lynx/gcc
# -mt: Sun Workshop C (may only link SunOS threads [-lthread], but it
#      doesn't hurt to check since this sometimes defines pthreads too;
#      also defines -D_REENTRANT)
# pthread: Linux, etcetera
# --thread-safe: KAI C++

case "${host_cpu}-${host_os}" in
        *solaris*)

        # On Solaris (at least, for some versions), libc contains stubbed
        # (non-functional) versions of the pthreads routines, so link-based
        # tests will erroneously succeed.  (We need to link with -pthread or
        # -lpthread.)  (The stubs are missing pthread_cleanup_push, or rather
        # a function called by this macro, so we could check for that, but
        # who knows whether they'll stub that too in a future libc.)  So,
        # we'll just look for -pthreads and -lpthread first:

        acx_pthread_flags="-pthread -pthreads pthread -mt $acx_pthread_flags"
        ;;
esac

if test x"$acx_pthread_ok" = xno; then
for flag in $acx_pthread_flags; do

        case $flag in
                none)
                AC_MSG_CHECKING([whether pthreads work without any flags])
                ;;

                -*)
                AC_MSG_CHECKING([whether pthreads work with $flag])
                PTHREAD_CFLAGS="$flag"
                ;;

                *)
                AC_MSG_CHECKING([for the pthreads library -l$flag])
                PTHREAD_LIBS="-l$flag"
                ;;
        esac

        save_LIBS="$LIBS"
        save_CFLAGS="$CFLAGS"
        LIBS="$PTHREAD_LIBS $LIBS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Check for various functions.  We must include pthread.h,
        # since some functions may be macros.  (On the Sequent, we
        # need a special flag -Kthread to make this header compile.)
        # We check for pthread_join because it is in -lpthread on IRIX
        # while pthread_create is in libc.  We check for pthread_attr_init
        # due to DEC craziness with -lpthreads.  We check for
        # pthread_cleanup_push because it is one of the few pthread
        # functions on Solaris that doesn't have a non-functional libc stub.
        # We try pthread_create on general principles.
        AC_TRY_LINK([#include <pthread.h>],
                    [pthread_t th; pthread_join(th, 0);
                     pthread_attr_init(0); pthread_cleanup_push(0, 0);
                     pthread_create(0,0,0,0); pthread_cleanup_pop(0); ],
                    [acx_pthread_ok=yes])

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        AC_MSG_RESULT($acx_pthread_ok)
        if test "x$acx_pthread_ok" = xyes; then
                break;
        fi

        PTHREAD_LIBS=""
        PTHREAD_CFLAGS=""
done
fi

# Various other checks:
if test "x$acx_pthread_ok" = xyes; then
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Detect AIX lossage: threads are created detached by default
        # and the JOINABLE attribute has a nonstandard name (UNDETACHED).
        AC_MSG_CHECKING([for joinable pthread attribute])
        AC_TRY_LINK([#include <pthread.h>],
                    [int attr=PTHREAD_CREATE_JOINABLE;],
                    ok=PTHREAD_CREATE_JOINABLE, ok=unknown)
        if test x"$ok" = xunknown; then
                AC_TRY_LINK([#include <pthread.h>],
                            [int attr=PTHREAD_CREATE_UNDETACHED;],
                            ok=PTHREAD_CREATE_UNDETACHED, ok=unknown)
        fi
        if test x"$ok" != xPTHREAD_CREATE_JOINABLE; then
                AC_DEFINE(PTHREAD_CREATE_JOINABLE, $ok,
                          [Define to the necessary symbol if this constant
                           uses a non-standard name on your system.])
        fi
        AC_MSG_RESULT(${ok})
        if test x"$ok" = xunknown; then
                AC_MSG_WARN([we do not know how to create joinable pthreads])
        fi

        AC_MSG_CHECKING([if more special flags are required for pthreads])
        flag=no
        case "${host_cpu}-${host_os}" in
                *-aix* | *-freebsd*)     flag="-D_THREAD_SAFE";;
                *solaris* | *-osf* | *-hpux*) flag="-D_REENTRANT";;
        esac
        AC_MSG_RESULT(${flag})
        if test "x$flag" != xno; then
                PTHREAD_CFLAGS="$flag $PTHREAD_CFLAGS"
        fi

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        # More AIX lossage: must compile with cc_r
        AC_CHECK_PROG(PTHREAD_CC, cc_r, cc_r, ${CC})
else
        PTHREAD_CC="$CC"
fi

AC_SUBST(PTHREAD_LIBS)
AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(PTHREAD_CC)

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test x"$acx_pthread_ok" = xyes; then
        ifelse([$1],,AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.]),[$1])
        :
else
        acx_pthread_ok=no
        $2
fi
AC_LANG_RESTORE
])dnl ACX_PTHREAD


dnl mpatrol
dnl A library for controlling and tracing dynamic memory allocations.
dnl Copyright (C) 1997-2002 Graeme S. Roy <graeme.roy@analog.com>
dnl
dnl This library is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU Library General Public
dnl License as published by the Free Software Foundation; either
dnl version 2 of the License, or (at your option) any later version.
dnl
dnl This library is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl Library General Public License for more details.
dnl
dnl You should have received a copy of the GNU Library General Public
dnl License along with this library; if not, write to the Free
dnl Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
dnl MA 02111-1307, USA.


dnl Automake macro to build with the mpatrol library


dnl $Id$


# serial 1


# AM_WITH_MPATROL(DEFAULT)
# Check whether to build with the mpatrol library and also attempt to
# determine the support libraries that also need to be linked in when
# libmpatrol is used.  If `DEFAULT' is not specified then it is `no'.
# If `DEFAULT' is `threads' then the threadsafe version of the mpatrol
# library will be used.

AC_DEFUN([AM_WITH_MPATROL], [
  # Firstly, determine if the mpatrol library should be used.

  AC_MSG_CHECKING(if mpatrol should be used)
  AC_ARG_WITH(mpatrol,
   [  --with-mpatrol          build with the mpatrol library],
   [case "$withval" in
     threads)
      am_with_mpatrol=1
      am_with_mpatrol_threads=1;;
     yes)
      am_with_mpatrol=1
      am_with_mpatrol_threads=0;;
     no)
      am_with_mpatrol=0
      am_with_mpatrol_threads=0;;
     *)
      AC_MSG_RESULT(no)
      AC_MSG_ERROR(invalid value $withval for --with-mpatrol);;
    esac
   ],
   [if test "x[$1]" = x
    then
     am_with_mpatrol=0
     am_with_mpatrol_threads=0
    elif test "[$1]" = no
    then
     am_with_mpatrol=0
     am_with_mpatrol_threads=0
    elif test "[$1]" = yes
    then
     am_with_mpatrol=1
     am_with_mpatrol_threads=0
    elif test "[$1]" = threads
    then
     am_with_mpatrol=1
     am_with_mpatrol_threads=1
    else
     AC_MSG_RESULT(no)
     AC_MSG_ERROR(invalid argument [$1])
    fi
   ]
  )

  if test "$am_with_mpatrol" = 1
  then
   AC_MSG_RESULT(yes)

   # Next, determine which support libraries are available on this
   # system.  If we don't do this here then we can't link later with
   # the mpatrol library to perform any further tests.

   am_with_mpatrol_libs=""
   AC_CHECK_LIB(ld, ldopen,
                am_with_mpatrol_libs="$am_with_mpatrol_libs -lld")
   AC_CHECK_LIB(elf, elf_begin,
                am_with_mpatrol_libs="$am_with_mpatrol_libs -lelf")
   AC_CHECK_LIB(bfd, bfd_init,
                am_with_mpatrol_libs="$am_with_mpatrol_libs -lbfd -liberty", ,
                -liberty)
   AC_CHECK_LIB(imagehlp, SymInitialize,
                am_with_mpatrol_libs="$am_with_mpatrol_libs -limagehlp")
   AC_CHECK_LIB(cl, U_get_previous_frame,
                am_with_mpatrol_libs="$am_with_mpatrol_libs -lcl")
   AC_CHECK_LIB(exc, unwind,
                am_with_mpatrol_libs="$am_with_mpatrol_libs -lexc")

   # Now determine which libraries really need to be linked in with
   # the version of libmpatrol that is on this system.  For example,
   # if the system has libelf and libbfd, we need to determine which
   # of these, if any, libmpatrol was built with support for.

   am_with_mpatrol_libs2=""
   AC_CHECK_LIB(mpatrol, __mp_libld,
                am_with_mpatrol_libs2="$am_with_mpatrol_libs2 -lld", ,
                $am_with_mpatrol_libs)
   AC_CHECK_LIB(mpatrol, __mp_libelf,
                am_with_mpatrol_libs2="$am_with_mpatrol_libs2 -lelf", ,
                $am_with_mpatrol_libs)
   AC_CHECK_LIB(mpatrol, __mp_libbfd,
                am_with_mpatrol_libs2="$am_with_mpatrol_libs2 -lbfd -liberty", ,
                $am_with_mpatrol_libs)
   AC_CHECK_LIB(mpatrol, __mp_libimagehlp,
                am_with_mpatrol_libs2="$am_with_mpatrol_libs2 -limagehlp", ,
                $am_with_mpatrol_libs)
   AC_CHECK_LIB(mpatrol, __mp_libcl,
                am_with_mpatrol_libs2="$am_with_mpatrol_libs2 -lcl", ,
                $am_with_mpatrol_libs)
   AC_CHECK_LIB(mpatrol, __mp_libexc,
                am_with_mpatrol_libs2="$am_with_mpatrol_libs2 -lexc", ,
                $am_with_mpatrol_libs)

   # If we are using the threadsafe mpatrol library then we may also need
   # to link in the threads library.  We check blindly for pthreads here
   # even if we don't need them (in which case it doesn't matter) since
   # the threads libraries are linked in by default on AmigaOS, Windows
   # and Netware and it is only UNIX systems that we need to worry about.

   if test "$am_with_mpatrol_threads" = 1
   then
    AC_CHECK_LIB(pthread, pthread_mutex_init,
                 am_with_mpatrol_libs2="$am_with_mpatrol_libs2 -lpthread", [
      AC_CHECK_LIB(pthreads, pthread_mutex_init,
                   am_with_mpatrol_libs2="$am_with_mpatrol_libs2 -lpthreads", [
        AC_CHECK_LIB(thread, pthread_mutex_init,
                     am_with_mpatrol_libs2="$am_with_mpatrol_libs2 -lthread")
       ]
      )
     ]
    )
   fi

   # We now know what libraries to use in order to link with libmpatrol.

   AC_DEFINE(HAVE_MPATROL, 1, [Define if using mpatrol])
   if test "$am_with_mpatrol_threads" = 1
   then
    LIBS="-lmpatrolmt $am_with_mpatrol_libs2 $LIBS"
   else
    LIBS="-lmpatrol $am_with_mpatrol_libs2 $LIBS"
   fi

   # Finally, verify that mpatrol is correctly installed and that we can
   # link a simple program with it.

   AC_CACHE_CHECK(for working mpatrol, am_cv_with_mpatrol, [
     AC_TRY_LINK([#include <mpatrol.h>], [
int main(void)
{
    malloc(4);
    return EXIT_SUCCESS;
}
],
      [am_cv_with_mpatrol=yes],
      [am_cv_with_mpatrol=no]
     )
    ]
   )

   if test "$am_cv_with_mpatrol" = no
   then
    AC_MSG_ERROR(mpatrol not installed correctly)
   fi
  else
   AC_MSG_RESULT(no)
  fi
 ]
)

