dnl   WZD_LIB_PERL()
dnl  
dnl   Search for a useable version of the PERL libs in a
dnl   number of common places.
dnl
dnl   If we find a useable version, set WZD_PERL_INCLUDES and WZD_PERL_LIBS as
dnl   appropriate, and set the shell variable 'wzd_have_perl' to
dnl   'yes'. Otherwise, set 'wzd_have_perl' to 'no'.
dnl   
dnl   The macro will execute optional argument 1 if given, if PERL
dnl   libs are found.
dnl   

AC_DEFUN([WZD_LIB_PERL],
[
dnl   TODO check version !
dnl
dnl   AC_PROG_PERL_VERSION(5.6.1)
dnl   is not working with perl 5.8.4
dnl
  AC_CHECK_PROG(PERL,perl,perl)
  if test "x$PERL" != "x"; then
    WZD_PERL_INCLUDES="`perl -MExtUtils::Embed -e ccopts`"
    WZD_PERL_LIBS="`perl -MExtUtils::Embed -e ldopts`"
  fi

  AC_MSG_CHECKING([perl usability])

  WZD_LIB_PERL_TRY

  if test "x$wzd_have_perl" = "xyes"; then
    AC_MSG_RESULT(ok)
    AC_DEFINE(HAVE_PERL, 1, [Define if using perl])
    m4_ifval([$2])
  else
    AC_MSG_RESULT(could not compile the C test program)
  fi

  AC_SUBST(WZD_PERL_INCLUDES)
  AC_SUBST(WZD_PERL_LIBS)
])


dnl    AC_PROG_PERL_VERSION
dnl
dnl    make sure we have perl installed
dnl
AC_DEFUN([AC_PROG_PERL_VERSION],
  [
    if test -z "$PERL"; then
      AC_CHECK_PROG(PERL,perl,perl)
    fi

    # check if version of Perl is sufficient
    ac_perl_version="$1"

    if test "x$PERL" != "x"; then
      AC_MSG_CHECKING(for perl version greater or equal to $ac_perl_version)
      $PERL -e "user $ac_perl_version; " > /dev/null 2>&1
      if test $? -ne 0; then
        AC_MSG_RESULT(no);
	m4_ifval([$3])
      else
        AC_MSG_RESULT(yes);
	m4_ifval([$2])
      fi
    else
      AC_MSG_WARN(could not find perl)
    fi
  ]
)

dnl    WZD_LIB_PERL_TRY()
dnl
dnl    A subroutine of WZD_LIB_PERL.
dnl
dnl    Check that a new-enough version of PERL is installed.
dnl
dnl    Set the shell variable 'wzd_have_perl' to 'yes' if we found
dnl    an appropriate version installed, or 'no' otherwise.

AC_DEFUN([WZD_LIB_PERL_TRY],
  [
    wzd_lib_perl_try_save_libs="$LIBS"
    wzd_lib_perl_try_save_cflags="$CFLAGS"

    CFLAGS="$CFLAGS $WZD_PERL_INCLUDES"
    LIBS="$LIBS $WZD_PERL_LIBS"

    dnl not trying to run, there's no point
    AC_TRY_LINK([#include <EXTERN.h>
    #include <perl.h>],[PerlInterpreter * interp; interp=perl_alloc();],[wzd_have_perl=yes],[wzd_have_perl=no])

    LIBS="$wzd_lib_perl_try_save_libs"
    CFLAGS="$wzd_lib_perl_try_save_cflags"
  ]
)
