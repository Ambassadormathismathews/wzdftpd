#ifndef LIBWZD_DUPECHECK_DUPELOG_H
#define LIBWZD_DUPECHECK_DUPELOG_H

int dupelog_is_upload_allowed(const char *filename);
int dupelog_add_entry(const char *path, const char *filename);
int dupelog_delete_entry(const char *filename);

#endif
