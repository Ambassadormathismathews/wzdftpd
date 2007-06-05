INCLUDE_DIRECTORIES(${WZDFTPD_SOURCE_DIR}
	${WZDFTPD_SOURCE_DIR}/libwzd-core
	${WZDFTPD_BINARY_DIR}
	)

ADD_DEFINITIONS(-DHAVE_CONFIG_H)

add_library (libwzd_plaintext SHARED
	libplaintext_file.c libplaintext_file.h
	libplaintext_main.c libplaintext_main.h
	libplaintext.def
	)

if (CYGWIN OR NOT WIN32)
  SET_TARGET_PROPERTIES(libwzd_plaintext PROPERTIES PREFIX "")
endif (CYGWIN OR NOT WIN32)

target_link_libraries (libwzd_plaintext libwzd_core)

INSTALL(TARGETS libwzd_plaintext DESTINATION ${BACKENDS_INSTALL_PATH})

INSTALL(FILES ${WZDFTPD_BINARY_DIR}/users.sample DESTINATION ${CONF_INSTALL_PATH})