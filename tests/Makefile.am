EXTRA_DIST = file_crc.txt test_common.h

INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src
LDADD = @DL_FLAGS@ ../src/libwzd_core.la

test_programs = \
	test_wzd_action \
	test_wzd_crc32 \
	test_wzd_ratio \
	test_wzd_section \
	test_wzd_string

check_PROGRAMS = $(test_programs)

TESTS = $(test_programs)

test_wzd_ratio_SOURCES = test_wzd_ratio.c test_common.c
test_wzd_string_SOURCES = test_wzd_string.c test_common.c
