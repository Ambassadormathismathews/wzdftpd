dnl =======================================
dnl ZEROCONF RELATED TESTS
dnl =======================================

AC_DEFUN([WZD_LIB_ZEROCONF],
[
        #
        # Zeroconf
        #
        AC_MSG_CHECKING([whether to build with Zeroconf support])
        PGAC_ARG_BOOL(with, zeroconf, no,
                                                                [  --with-zeroconf           build with Zeroconf support],
                                                                [AC_DEFINE([HAVE_ZEROCONF], 1, [Define to 1 to build with Zeroconf support. (--with-zeroconf)])])
        AC_MSG_RESULT([$with_zeroconf])
        AC_SUBST(with_zeroconf)

        dnl First of all check whether the user specified a
        dnl particular Zeroconf implementation but did forget
        dnl to set the --with-zeroconf flag
        if test "x$with_zeroconf" = "xno" ; then
                if test "x$enable_bonjour" = "xyes" -o \
                        "x$enable_avahi" = "xyes" -o \
                        "x$enable_howl" = "xyes" ; then
                        AC_MSG_WARN(You did specify to use a concrete Zeroconf implementation)
                        AC_MSG_WARN(but you did forget to enable general Zeroconf support.)
                        AC_MSG_WARN(Hence I am going to enforce Zerconf support.)
                        $with_zeroconf = "yes"
                fi
        fi

        #
        # Avahi
        #
        AC_MSG_CHECKING([whether to build with Avahi support])
        PGAC_ARG_BOOL(enable, avahi, no, [  --enable-avahi           enable Avahi support],
                                                                [AC_DEFINE([USE_AVAHI], 1,
                                                                                                        [Define to 1 if you want Avahi support. (--enable-avahi)])])
        AC_MSG_RESULT([$enable_avahi])
        AC_SUBST(enable_avahi)

        #
        # Bonjour
        #
        AC_MSG_CHECKING([whether to build with Bonjour support])
        PGAC_ARG_BOOL(enable, bonjour, no, [  --enable-bonjour           enable Bonjour support],
                                                                [AC_DEFINE([USE_BONJOUR], 1,
                                                                                                        [Define to 1 if you want Bonjour support. (--enable-bonjour)])])
        AC_MSG_RESULT([$enable_bonjour])
        AC_SUBST(enable_bonjour)

        #
        # Howl
        #
        AC_MSG_CHECKING([whether to build with Howl support])
        PGAC_ARG_BOOL(enable, howl, no, [  --enable-howl           enable Howl support],
                                                                [AC_DEFINE([USE_HOWL], 1,
                                                                                                        [Define to 1 if you want Howl support. (--enable-howl)])])
        AC_MSG_RESULT([$enable_howl])
        AC_SUBST(enable_howl)

        if test "$with_zeroconf" = yes ; then
                dnl Find pkg-config
                AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
                if test "x$PKG_CONFIG" = "xno"; then
                                        AC_MSG_ERROR([You need to install pkg-config])
                fi

                if test "$enable_bonjour" = yes ; then
                        AC_MSG_CHECKING(checking whether to use Bonjour)
                        if test "x$enable_avahi" = "xyes" -o \
                                "x$enable_howl" = "xyes" ; then
                                        AC_MSG_ERROR(It does not make sense to use more then one Zeroconf implementation.)
                        else
                                        AC_MSG_RESULT(yes)
                                        AC_CHECK_HEADER(DNSServiceDiscovery/DNSServiceDiscovery.h, [], [AC_MSG_ERROR([header file <DNSServiceDiscovery/DNSServiceDiscovery.h> is required for Bonjour])])
                        fi
                fi

                dnl Some notes about the ORG_... variables:
                dnl I am doing this, because at the time I do not know how to use
                dnl the CFLAGS/LIBS returned by pkg-config together with CHECK_HEADER
                dnl and CHECK_LIB. Thus I am appending them to LDFLAGS/CPPFLAGS after
                dnl having backed up the original values of those variables. After
                dnl those checks I am restoring the original value of LDFLAGS/CPPFLAGS.
                dnl This methodology ensures that one does not need to manually set
                dnl LDFLAGS/CPPFLAGS. Instead she could rely on the value return by pkg-config.

                if test "$enable_avahi" = yes ; then
                        AC_MSG_CHECKING(checking whether to use Avahi)
                        if test "x$enable_bonjour" = "xyes" -o \
                                "x$enable_howl" = "xyes" ; then
                                        AC_MSG_ERROR(It does not make sense to use more then one Zeroconf implementation.)
                        else
                                        AC_MSG_RESULT(yes)

                                        if pkg-config --exists 'avahi-client >= 0.6.0'; then
                                                echo avahi-client installation OK
                                                AC_MSG_CHECKING(checking whether Avahi supports AvahiThreadedPoll)
                                                if pkg-config --exists 'avahi-client >= 0.6.4'; then
                                                        AC_MSG_RESULT(yes)
                                                        AC_DEFINE([HAVE_AVAHI_THREADED_POLL], 1, [Define to 1 to use AvahiThreadedPoll])
                                                else
                                                        AC_MSG_RESULT(no)
                                                fi
                                        else
                                                AC_MSG_ERROR("Did not find avahi-client >= 0.6.0");
                                        fi

                                        WZD_AVAHI_CFLAGS="`pkg-config --silence-errors --cflags 'avahi-client >= 0.6.0'`"
                                        WZD_AVAHI_LIBS="`pkg-config --silence-errors --libs 'avahi-client >= 0.6.0'`"

                                        AC_SUBST(WZD_AVAHI_CFLAGS)
                                        AC_SUBST(WZD_AVAHI_LIBS)

                                        ORG_CPPFLAGS="$CPPFLAGS"
                                        ORG_LDFLAGS="$LDFLAGS"
                                        ORG_LIBS="$LIBS"
                                        CPPFLAGS="$WZD_AVAHI_CFLAGS $CPPFLAGS"
                                        LDFLAGS="$WZD_AVAHI_LIBS $LDFLAGS"

                                        AC_CHECK_HEADER(avahi-client/client.h, [], [AC_MSG_ERROR([header file <avahi-client/client.h> is required for Avahi])])
                                        AC_CHECK_HEADER(avahi-client/publish.h, [], [AC_MSG_ERROR([header file <avahi-client/publish.h> is required for Avahi])])
                                        AC_CHECK_HEADER(avahi-common/alternative.h, [], [AC_MSG_ERROR([header file <avahi-common/alternative.h> is required for Avahi])])
                                        AC_CHECK_HEADER(avahi-common/simple-watch.h, [], [AC_MSG_ERROR([header file <avahi-common/simple-watch.h> is required for Avahi])])
                                        AC_CHECK_HEADER(avahi-common/malloc.h, [], [AC_MSG_ERROR([header file <avahi-common/malloc.h> is required for Avahi])])
                                        AC_CHECK_HEADER(avahi-common/error.h, [], [AC_MSG_ERROR([header file <avahi-common/error.h> is required for Avahi])])

                                        AC_CHECK_LIB(dbus-1, dbus_bus_register, [], [AC_MSG_ERROR([library 'dbus' is required for Zeroconf support])])
                                        AC_CHECK_LIB(avahi-common, avahi_simple_poll_loop, [], [AC_MSG_ERROR([library 'avahi-common' is required for Zeroconf support])])
                                        AC_CHECK_LIB(avahi-client, avahi_client_new, [], [AC_MSG_ERROR([library 'avahi-client' is required for Zeroconf support])])

                                        CPPFLAGS="$ORG_CPPFLAGS"
                                        LDFLAGS="$ORG_LDFLAGS"
                                        LIBS="$ORG_LIBS"
                        fi
                fi
                if test "$enable_howl" = yes ; then
                        AC_MSG_CHECKING(checking whether to use Howl)
                        if test "x$enable_avahi" = "xyes" -o \
                                "x$enable_bonjour" = "xyes" ; then
                                        AC_MSG_ERROR(It does not make sense to use more then one Zeroconf implementation.)
                        else
                                        AC_MSG_RESULT(yes)

                                        if pkg-config --exists 'howl >= 1.0.0'; then
                                                echo howl installation OK
                                        else
                                                AC_MSG_ERROR("Did not find howl >= 1.0.0");
                                        fi

                                        WZD_HOWL_CFLAGS="`pkg-config --silence-errors --cflags 'howl >= 1.0.0'`"
                                        WZD_HOWL_LIBS="`pkg-config --silence-errors --libs 'howl >= 1.0.0'`"

                                        AC_SUBST(WZD_HOWL_CFLAGS)
                                        AC_SUBST(WZD_HOWL_LIBS)

                                        ORG_CPPFLAGS="$CPPFLAGS"
                                        ORG_LDFLAGS="$LDFLAGS"
                                        ORG_LIBS="$LIBS"
                                        CPPFLAGS="$WZD_HOWL_CFLAGS $CPPFLAGS"
                                        LDFLAGS="$WZD_HOWL_LIBS $LDFLAGS"

                                        AC_CHECK_HEADER(howl.h, [], [AC_MSG_ERROR([header file <howl.h> is required for Howl])])

                                        AC_CHECK_LIB(howl, sw_discovery_publish, [], [AC_MSG_ERROR([library 'howl' is required for Zeroconf support])])

                                        CPPFLAGS="$ORG_CPPFLAGS"
                                        LDFLAGS="$ORG_LDFLAGS"
                                        LIBS="$ORG_LIBS"
                        fi
                fi
        fi
])
