EXTRA_DIST = file_crc.txt test_common.h test_template.c

INCLUDES = -I$(top_srcdir)
LDADD = @DL_FLAGS@ ../libwzd-core/libwzd_core.la

test_programs = \
	test_list \
	test_wzd_action \
	test_wzd_cache \
	test_wzd_configfile \
	test_wzd_cookies \
	test_wzd_crc32 \
	test_wzd_crontab \
	test_wzd_dir \
	test_wzd_events \
	test_wzd_fs \
	test_wzd_ip \
	test_wzd_ratio \
	test_wzd_section \
	test_wzd_string \
	test_wzd_structs \
	test_wzd_threads \
	test_wzd_vfs

check_PROGRAMS = $(test_programs)

TESTS = $(test_programs)

test_wzd_cookies_SOURCES = test_wzd_cookies.c test_common.c
test_wzd_dir_SOURCES = test_wzd_dir.c test_common.c
test_wzd_events_SOURCES = test_wzd_events.c test_common.c
test_wzd_ratio_SOURCES = test_wzd_ratio.c test_common.c
test_wzd_string_SOURCES = test_wzd_string.c test_common.c
