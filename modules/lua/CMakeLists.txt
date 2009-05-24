INCLUDE_DIRECTORIES(${WZDFTPD_SOURCE_DIR}
	${WZDFTPD_SOURCE_DIR}/libwzd-core
	${WZDFTPD_BINARY_DIR}
	${LUA51_INCLUDE_DIR}
	)

ADD_DEFINITIONS(-DHAVE_CONFIG_H)

ADD_LIBRARY (libwzd_lua SHARED
  lua.def
  libwzd_lua_api.c
  libwzd_lua_api_wzd.c
  libwzd_lua_api_group.c
  libwzd_lua_api_shm.c
  libwzd_lua_api_user.c
  libwzd_lua_api_vfs.c
  libwzd_lua_main.c
  libwzd_lua_state.c
)

if (CYGWIN OR NOT WIN32)
  SET_TARGET_PROPERTIES(libwzd_lua PROPERTIES PREFIX "")
endif (CYGWIN OR NOT WIN32)

SET(lua_LIBS libwzd_core)

TARGET_LINK_LIBRARIES (libwzd_lua ${lua_LIBS} ${LUA51_LIBRARIES})

INSTALL(TARGETS libwzd_lua DESTINATION ${MODULES_INSTALL_PATH})
