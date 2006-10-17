INCLUDE_DIRECTORIES(${WZDFTPD_SOURCE_DIR}
	${WZDFTPD_SOURCE_DIR}/libwzd-core
	${WZDFTPD_BINARY_DIR}
	)

ADD_DEFINITIONS(-DHAVE_CONFIG_H)

IF(AVAHI_FOUND)
  ADD_DEFINITIONS(-DUSE_AVAHI)
  IF (AVAHI_SUPPORT_THREADEDPOLL)
    ADD_DEFINITIONS(-DHAVE_AVAHI_THREADED_POLL)
  ENDIF (AVAHI_SUPPORT_THREADEDPOLL)
ENDIF(AVAHI_FOUND)

IF(HOWL_FOUND)
  ADD_DEFINITIONS(-DUSE_HOWL)
  SET(CMAKE_C_FLAGS "${HOWL_C_FLAGS} ${CMAKE_C_FLAGS}")
ENDIF(HOWL_FOUND)

ADD_LIBRARY (libwzd_zeroconf SHARED
	libwzd_avahi.c libwzd_avahi.h
	libwzd_bonjour.c libwzd_bonjour.h
	libwzd_howl.c libwzd_howl.h
	libwzd_zeroconf.c libwzd_zeroconf.h
	zeroconf.def
	)

if (CYGWIN OR NOT WIN32)
  SET_TARGET_PROPERTIES(libwzd_zeroconf PROPERTIES PREFIX "")
endif (CYGWIN OR NOT WIN32)

SET(libwzd_zeroconf_LIBS libwzd_core)

IF(AVAHI_FOUND)
  MACRO_ADD_LINK_FLAGS(libwzd_zeroconf "${AVAHI_LIBS}")
ENDIF(AVAHI_FOUND)

IF(HOWL_FOUND)
  MACRO_ADD_LINK_FLAGS(libwzd_zeroconf "${HOWL_LIBS}")
ENDIF(HOWL_FOUND)

TARGET_LINK_LIBRARIES (libwzd_zeroconf ${zeroconf_LIBS})
