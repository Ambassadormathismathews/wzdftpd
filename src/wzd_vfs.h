#ifndef __WZD_VFS_H__
#define __WZD_VFS_H__

/* free vfs list */
int vfs_free(wzd_vfs_t **vfs_list);

/* register a new vfs entry */
int vfs_add(wzd_vfs_t ** vfs_list, const char *vpath, const char *path);

/* if needed, replace the vfs in the path */
int vfs_replace(wzd_vfs_t *vfs_list, char *buffer, unsigned int maxlen);

#endif /* __WZD_VFS_H__ */
