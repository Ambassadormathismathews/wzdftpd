project(libwzd C)

INCLUDE_DIRECTORIES(${WZDFTPD_SOURCE_DIR}
	${WZDFTPD_SOURCE_DIR}/libwzd-core
	${WZDFTPD_BINARY_DIR}
	)

ADD_DEFINITIONS(-DHAVE_CONFIG_H)

LINK_DIRECTORIES (${WZDFTPD_BINARY_DIR}/libwzd-auth
	)

if(OPENSSL_FOUND)
  INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
endif(OPENSSL_FOUND)

if(GNUTLS_FOUND)
  INCLUDE_DIRECTORIES(${GNUTLS_INCLUDE_DIR})
endif(GNUTLS_FOUND)

INCLUDE(${WZDFTPD_SOURCE_DIR}/libwzd-base/libwzd-base.cmake)

SET(wzd_pub_HEADERS
	libwzd.h
	libwzd_codes.h
	libwzd_err.h
	libwzd_socket.h
	libwzd_tls.h
	)

add_library (libwzd SHARED
	${base_SOURCES}
	libwzd.c
	libwzd_codes.c
	libwzd_err.c
	libwzd_pv.h
	libwzd_socket.c
	libwzd_tls.c
	${wzd_pub_HEADERS}
	libwzd.def
	)

if (CYGWIN OR NOT WIN32)
  SET_TARGET_PROPERTIES(libwzd PROPERTIES PREFIX "")
endif (CYGWIN OR NOT WIN32)

if (MINGW)
  SET_TARGET_PROPERTIES(libwzd PROPERTIES LINK_FLAGS ${WZDFTPD_SOURCE_DIR}/libwzd/libwzd.def)
endif (MINGW)

set(libwzd_LIBS ${EXTRA_LIBS})

set(libwzd_LIBS ${libwzd_LIBS} ${CMAKE_THREAD_LIBS_INIT})

if (WIN32)
  set(libwzd_LIBS ${libwzd_LIBS} ws2_32)
endif (WIN32)

if (OPENSSL_FOUND)
  set(libwzd_LIBS ${libwzd_LIBS} ${OPENSSL_LIBRARIES})
endif (OPENSSL_FOUND)

if (CRYPTO_FOUND)
  set(libwzd_LIBS ${libwzd_LIBS} ${CRYPTO_LIBRARIES})
endif (CRYPTO_FOUND)

if (GNUTLS_FOUND)
  set(libwzd_LIBS ${libwzd_LIBS} ${GNUTLS_LIBRARIES})
endif (GNUTLS_FOUND)

TARGET_LINK_LIBRARIES(libwzd ${libwzd_LIBS})


SET_TARGET_PROPERTIES(libwzd PROPERTIES VERSION "${WZD_VERSION}")
SET_TARGET_PROPERTIES(libwzd PROPERTIES SOVERSION "${WZD_MAJOR}")


CREATE_LIBTOOL_FILE(libwzd "/lib") # this path is relative to ${CMAKE_INSTALL_PREFIX}

INSTALL(TARGETS libwzd DESTINATION ${LIB_INSTALL_PATH})
INSTALL(FILES ${wzd_pub_HEADERS} DESTINATION ${HEADERS_INSTALL_PATH}/wzdftpd/libwzd)
