#ifndef __WZD_VFS_H__
#define __WZD_VFS_H__

char *stripdir(char * dir, char *buf, int maxlen);
int checkpath(const char *wanted_path, char *path, wzd_context_t *context);

/* free vfs list */
int vfs_free(wzd_vfs_t **vfs_list);

/* register a new vfs entry */
int vfs_add(wzd_vfs_t ** vfs_list, const char *vpath, const char *path);

/* if needed, replace the vfs in the path */
int vfs_replace(wzd_vfs_t *vfs_list, char *buffer, unsigned int maxlen);

#endif /* __WZD_VFS_H__ */
