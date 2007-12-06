#ifndef LIBWZD_DUPECHECK_DUPELOG_H
#define LIBWZD_DUPECHECK_DUPELOG_H

#include <libwzd-core/wzd_structs.h>

int dupelog_is_upload_allowed(const char *filename);
int dupelog_add_entry(const char *path, const char *filename);
int dupelog_delete_entry(const char *filename);
void dupelog_print_matching_dirs(const char *pattern, int limit, wzd_context_t *context);

#endif
