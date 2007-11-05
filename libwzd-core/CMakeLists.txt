INCLUDE_DIRECTORIES(${WZDFTPD_SOURCE_DIR}
	${WZDFTPD_SOURCE_DIR}/libwzd-core
	${WZDFTPD_BINARY_DIR}
	)

ADD_DEFINITIONS(-DHAVE_CONFIG_H)
if (WIN32)
  ADD_DEFINITIONS(-DLIBWZD_EXPORTS -D_USRDLL)
endif (WIN32)

LINK_DIRECTORIES (${WZDFTPD_BINARY_DIR}/libwzd-auth
	${WZDFTPD_BINARY_DIR}/libwzd-base
	)

INCLUDE(${WZDFTPD_SOURCE_DIR}/gnu_regex/gnu_regex.cmake)
INCLUDE(${WZDFTPD_SOURCE_DIR}/libwzd-base/libwzd-base.cmake)
INCLUDE(${WZDFTPD_SOURCE_DIR}/libwzd-auth/libwzd-auth.cmake)

ADD_CUSTOM_COMMAND(OUTPUT ${WZDFTPD_BINARY_DIR}/libwzd-core/wzd_cookie_lex.c
	COMMAND flex -t ${CMAKE_CURRENT_SOURCE_DIR}/wzd_cookie_lex.l > ${CMAKE_CURRENT_BINARY_DIR}/wzd_cookie_lex.c

	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/wzd_cookie_lex.l
)

if(OPENSSL_FOUND)
  INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
endif(OPENSSL_FOUND)

if(GNUTLS_FOUND)
  INCLUDE_DIRECTORIES(${GNUTLS_INCLUDE_DIR})
endif(GNUTLS_FOUND)

if(KRB5_FOUND)
  INCLUDE_DIRECTORIES(${KRB5_INCLUDE_DIRS})
endif(KRB5_FOUND)

add_subdirectory (arch)

SET(libwzd_core_pub_HEADERS
	wzd_action.h
	wzd_all.h
	wzd_backend.h
	wzd_cache.h
	wzd_ClientThread.h
	wzd_commands.h
	wzd_configfile.h
	wzd_configloader.h
	wzd_crc32.h
	wzd_crontab.h
	wzd_data.h
	wzd_debug.h
	wzd_dir.h
	wzd_events.h
	wzd_file.h
	wzd_fs.h
	wzd_group.h
	wzd_hardlimits.h
	wzd_ip.h
	wzd_libmain.h
	wzd_list.h
	wzd_log.h
	wzd_login.h
	wzd_messages.h
	wzd_misc.h
	wzd_mod.h
	wzd_mutex.h
	wzd_perm.h
	wzd_protocol.h
	wzd_ratio.h
	wzd_section.h
	wzd_shm.h
	wzd_site.h
	wzd_site_group.h
	wzd_site_user.h
	wzd_socket.h
	wzd_string.h
	wzd_structs.h
	wzd_threads.h
	wzd_tls.h
	wzd_types.h
	wzd_user.h
	wzd_utf8.h
	wzd_vars.h
	wzd_vfs.h
	)

add_library (libwzd_core SHARED
	${gnu_regex_SOURCES}
	${base_SOURCES}
	${auth_SOURCES}
	inet_ntop.c
	inet_pton.c
	wzd_action.c
	wzd_all.c
	wzd_backend.c
	wzd_cache.c
	wzd_ClientThread.c
	wzd_commands.c
	wzd_configfile.c
	wzd_configloader.c
	wzd_cookie_lex.c
	wzd_crc32.c
	wzd_crontab.c
	wzd_data.c
	wzd_debug.c
	wzd_dir.c
	wzd_events.c
	wzd_file.c
	wzd_fs.c
	wzd_group.c
	wzd_ip.c
	wzd_libmain.c
	wzd_list.c
	wzd_log.c
	wzd_login.c
	wzd_messages.c
	wzd_misc.c
	wzd_mod.c
	wzd_mutex.c
	wzd_perm.c
	wzd_protocol.c
	wzd_ratio.c
	wzd_section.c
	wzd_shm.c
	wzd_site.c
	wzd_site_group.c
	wzd_site_user.c
	wzd_socket.c
	wzd_string.c
	wzd_strptime.c wzd_strptime.h
	wzd_strtoull.c wzd_strtoull.h
	wzd_threads.c
	wzd_tls.c
	wzd_user.c
	wzd_utf8.c
	wzd_vars.c
	wzd_vfs.c
	${libwzd_core_pub_HEADERS}
	libwzd_core.def
	)

if (CYGWIN OR NOT WIN32)
  SET_TARGET_PROPERTIES(libwzd_core PROPERTIES PREFIX "")
endif (CYGWIN OR NOT WIN32)

SET_SOURCE_FILES_PROPERTIES(wzd_cookie_lex.c PROPERTIES GENERATED true)
if (MINGW)
  SET_TARGET_PROPERTIES(libwzd_core PROPERTIES LINK_FLAGS ${WZDFTPD_SOURCE_DIR}/libwzd-core/libwzd_core.def)
endif (MINGW)

set(libwzd_core_LIBS ${EXTRA_LIBS})

set(libwzd_core_LIBS ${libwzd_core_LIBS} ${CMAKE_THREAD_LIBS_INIT})

if (WIN32)
  set(libwzd_core_LIBS ${libwzd_core_LIBS} ws2_32)
endif (WIN32)

if (OPENSSL_FOUND)
  set(libwzd_core_LIBS ${libwzd_core_LIBS} ${OPENSSL_LIBRARIES})
endif (OPENSSL_FOUND)

if (CRYPTO_FOUND)
  set(libwzd_core_LIBS ${libwzd_core_LIBS} ${CRYPTO_LIBRARIES})
endif (CRYPTO_FOUND)

if (GNUTLS_FOUND)
  set(libwzd_core_LIBS ${libwzd_core_LIBS} ${GNUTLS_LIBRARIES})
endif (GNUTLS_FOUND)

if (KRB5_FOUND)
  set(libwzd_core_LIBS ${libwzd_core_LIBS} ${KRB5_LIBRARIES})
endif (KRB5_FOUND)

if (PAM_FOUND)
  set(libwzd_core_LIBS ${libwzd_core_LIBS} ${PAM_LIBRARIES})
endif (PAM_FOUND)

TARGET_LINK_LIBRARIES(libwzd_core ${libwzd_core_LIBS})


SET_TARGET_PROPERTIES(libwzd_core PROPERTIES VERSION "${WZD_VERSION}")
SET_TARGET_PROPERTIES(libwzd_core PROPERTIES SOVERSION "${WZD_MAJOR}")


CREATE_LIBTOOL_FILE(libwzd_core "/lib") # this path is relative to ${CMAKE_INSTALL_PREFIX}

INSTALL(TARGETS libwzd_core DESTINATION ${LIB_INSTALL_PATH})
INSTALL(FILES ${libwzd_core_pub_HEADERS} DESTINATION ${HEADERS_INSTALL_PATH}/wzdftpd/libwzd-core)

