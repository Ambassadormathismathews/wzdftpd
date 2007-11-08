INCLUDE_DIRECTORIES(${WZDFTPD_SOURCE_DIR}
	${WZDFTPD_SOURCE_DIR}/libwzd
	${WZDFTPD_BINARY_DIR})

LINK_DIRECTORIES (${WZDFTPD_BINARY_DIR}/libwzd-core)


MACRO (ADD_WZD_TEST _test_name _test_source)
  ADD_EXECUTABLE (${_test_name} ${_test_source})
  IF (${ARGC} GREATER 2)
    ADD_TEST (${_test_name} ${_test_name} ${ARGN})
  ELSE (${ARGC} GREATER 2)
    ADD_TEST (${_test_name} ${_test_name})
  ENDIF (${ARGC} GREATER 2)
TARGET_LINK_LIBRARIES (${_test_name} libwzd_core testcommon)
ENDMACRO (ADD_WZD_TEST _test_name _test_source)

MACRO (ADD_LIBWZD_TEST _test_name _test_source)
  ADD_EXECUTABLE (${_test_name} ${_test_source})
  IF (${ARGC} GREATER 2)
    ADD_TEST (${_test_name} ${_test_name} ${ARGN})
  ELSE (${ARGC} GREATER 2)
    ADD_TEST (${_test_name} ${_test_name})
  ENDIF (${ARGC} GREATER 2)
TARGET_LINK_LIBRARIES (${_test_name} libwzd testcommon)
ENDMACRO (ADD_LIBWZD_TEST _test_name _test_source)


ADD_DEFINITIONS (-DHAVE_CONFIG_H)

SET(testcommon_SOURCES
	fake_backend.c
	fake_backend.h
	test_common.c
	test_common.h
	)

ADD_LIBRARY(testcommon ${testcommon_SOURCES})

ADD_WZD_TEST(test_list test_list.c)

ADD_LIBWZD_TEST(test_libwzd_codes test_libwzd_codes.c)

ADD_WZD_TEST(test_wzd_action test_wzd_action.c)
ADD_WZD_TEST(test_wzd_backend test_wzd_backend.c)
ADD_WZD_TEST(test_wzd_cache test_wzd_cache.c "${WZDFTPD_SOURCE_DIR}/tests")
ADD_WZD_TEST(test_wzd_configfile test_wzd_configfile.c)
ADD_WZD_TEST(test_wzd_cookies test_wzd_cookies.c)
ADD_WZD_TEST(test_wzd_crc32 test_wzd_crc32.c "${WZDFTPD_SOURCE_DIR}/tests")
ADD_WZD_TEST(test_wzd_crontab test_wzd_crontab.c)
ADD_WZD_TEST(test_wzd_data test_wzd_data.c)
ADD_WZD_TEST(test_wzd_dir test_wzd_dir.c)
ADD_WZD_TEST(test_wzd_events test_wzd_events.c)
ADD_WZD_TEST(test_wzd_fs test_wzd_fs.c)
ADD_WZD_TEST(test_wzd_group test_wzd_group.c)
ADD_WZD_TEST(test_wzd_ip test_wzd_ip.c)
ADD_WZD_TEST(test_wzd_log test_wzd_log.c)
ADD_WZD_TEST(test_wzd_messages test_wzd_messages.c)
ADD_WZD_TEST(test_wzd_ratio test_wzd_ratio.c)
ADD_WZD_TEST(test_wzd_section test_wzd_section.c)
ADD_WZD_TEST(test_wzd_string test_wzd_string.c)
ADD_WZD_TEST(test_wzd_structs test_wzd_structs.c)
ADD_WZD_TEST(test_wzd_threads test_wzd_threads.c)
ADD_WZD_TEST(test_wzd_user test_wzd_user.c)
ADD_WZD_TEST(test_wzd_vfs test_wzd_vfs.c)

