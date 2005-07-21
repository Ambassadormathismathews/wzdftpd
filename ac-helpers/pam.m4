dnl   WZD_LIB_PAM()
dnl  
dnl   Search for a useable version of the PAM client libs in a
dnl   number of common places.
dnl
dnl   If we find a useable version, set WZD_PAM_INCLUDES and WZD_PAM_LIBS as
dnl   appropriate, and set the shell variable 'wzd_have_pam' to
dnl   'yes'. Otherwise, set 'wzd_have_pam' to 'no'.

AC_DEFUN([WZD_LIB_PAM],
[
  AC_CHECK_HEADERS(pam/pam_appl.h security/pam_appl.h)

# Check for PAM libs
  wzd_have_pam=no
  AC_ARG_WITH(pam,
    [  --with-pam              Enable PAM support ],
    [
      if test "x$withval" != "x" -o "x$withval" != "xno" ; then
        if test "x$ac_cv_header_security_pam_appl_h" != "xyes" && \
          test "x$ac_cv_header_pam_pam_appl_h" != "xyes" ; then
            AC_MSG_ERROR([PAM headers not found])
        fi

        AC_CHECK_LIB(pam, pam_set_item, WZD_PAM_LIBS="-lpam" , AC_MSG_ERROR([*** libpam missing]))
        dnl AC_CHECK_FUNCS(pam_getenvlist)
        dnl AC_CHECK_FUNCS(pam_putenv)

        wzd_have_pam=yes
        AC_DEFINE(HAVE_PAM, 1, [Define if using pam])

        if test $ac_cv_lib_dl_dlopen = yes; then
          WZD_PAM_LIBS="$WZD_PAM_LIBS -ldl"
        fi
        AC_SUBST(WZD_PAM_LIBS)
      fi
    ]
  )
]
)

