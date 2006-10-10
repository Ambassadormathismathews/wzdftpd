INCLUDE_DIRECTORIES(${WZDFTPD_SOURCE_DIR}
	${WZDFTPD_SOURCE_DIR}/libwzd-core
	${WZDFTPD_BINARY_DIR}
	)

ADD_DEFINITIONS(-DHAVE_CONFIG_H)

ADD_LIBRARY (libwzd_sfv SHARED
	libwzd_sfv_indicators.c libwzd_sfv_indicators.h
	libwzd_sfv_main.c libwzd_sfv_main.h
	libwzd_sfv_sfv.c libwzd_sfv_sfv.h
	libwzd_sfv_site.c libwzd_sfv_site.h
	libwzd_sfv_zip.c libwzd_sfv_zip.h
	minizip/crypt.h
	minizip/ioapi.c
	minizip/ioapi.h
	minizip/unzip.c
	minizip/unzip.h
	sfv.def
	)

if (CYGWIN OR NOT WIN32)
  SET_TARGET_PROPERTIES(libwzd_sfv PROPERTIES PREFIX "")
endif (CYGWIN OR NOT WIN32)

SET(sfv_LIBS libwzd_core)

TARGET_LINK_LIBRARIES (libwzd_sfv ${sfv_LIBS})

INSTALL(TARGETS libwzd_sfv DESTINATION ${MODULES_INSTALL_PATH})
