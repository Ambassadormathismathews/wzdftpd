INCLUDE_DIRECTORIES(${WZDFTPD_SOURCE_DIR}
	${WZDFTPD_SOURCE_DIR}/libwzd-core
	${WZDFTPD_BINARY_DIR}
	)

ADD_DEFINITIONS(-DHAVE_CONFIG_H)
if (WIN32)
  ADD_DEFINITIONS(-D_USRDLL)
endif (WIN32)


add_library (libwzd_debug SHARED
	debug_backends.c debug_backends.h
	debug_commands.c debug_commands.h
	debug_context.c debug_context.h
	debug_crontab.c debug_crontab.h
	debug_modules.c debug_modules.h
	libwzd_debug.c
	mod_debug.def
	)

if (CYGWIN OR NOT WIN32)
  SET_TARGET_PROPERTIES(libwzd_debug PROPERTIES PREFIX "")
endif (CYGWIN OR NOT WIN32)

target_link_libraries (libwzd_debug libwzd_core)

INSTALL(TARGETS libwzd_debug DESTINATION ${MODULES_INSTALL_PATH})
