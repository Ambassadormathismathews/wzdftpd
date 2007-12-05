# This CMakeLists.txt depends on SQLite3
# It also depends on you checking for it, so that SQLITE3_INCLUDE_DIR
# and SQLITE3_LIBRARIES are set properly. :-)

INCLUDE_DIRECTORIES(${WZDFTPD_SOURCE_DIR}
	${WZDFTPD_SOURCE_DIR}/libwzd-core
	${WZDFTPD_BINARY_DIR}
        ${SQLITE3_INCLUDE_DIR}
	)

ADD_DEFINITIONS(-DHAVE_CONFIG_H)

ADD_LIBRARY (libwzd_dupecheck SHARED
        libwzd_dupecheck_main.c
        libwzd_dupecheck_main.h
	dupecheck.def
	)

if (CYGWIN OR NOT WIN32)
  SET_TARGET_PROPERTIES(libwzd_dupecheck PROPERTIES PREFIX "")
endif (CYGWIN OR NOT WIN32)

SET(dupecheck_LIBS libwzd_core ${SQLITE3_LIBRARIES})

TARGET_LINK_LIBRARIES (libwzd_dupecheck ${dupecheck_LIBS})

INSTALL(TARGETS libwzd_dupecheck DESTINATION ${MODULES_INSTALL_PATH})
