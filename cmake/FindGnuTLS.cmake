INCLUDE( cmake/FindPkgConfig.cmake )
PKGCONFIG("gnutls >= 1.3.0")
IF(PKGCONFIG_FOUND)
  IF(CMAKE_PKGCONFIG_C_FLAGS)
    #SET(CMAKE_C_FLAGS "${CMAKE_PKGCONFIG_C_FLAGS} ${CMAKE_C_FLAGS}")
    SET(GNUTLS_FOUND TRUE)
    SET(GNUTLS_C_FLAGS "${CMAKE_PKGCONFIG_C_FLAGS}")
    SET(GNUTLS_LIBRARIES "${PKGCONFIG_LIBRARIES}")
    #do something with ${PKGCONFIG_LIBRARIES}
  ENDIF(CMAKE_PKGCONFIG_C_FLAGS)
ELSE(PKGCONFIG_FOUND)
  MESSAGE("Cannot find GnuTLS version 1.3.0 or above")
ENDIF(PKGCONFIG_FOUND)

IF(GNUTLS_FOUND)
  SET(GNUTLS_FOUND TRUE)
ENDIF(GNUTLS_FOUND)
