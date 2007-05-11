#ifndef __LIBSQLITE_MAIN__
#define __LIBSQLITE_MAIN__

/** 
 * \file libsqlite_main.h
 * \brief Sqlite backend main functions
 * \addtogroup backend_sqlite
 * @{
 */

sqlite3 *libsqlite_open();
void     libsqlite_close(sqlite3 **db);
void     libsqlite_add_to_query(char **query, char *format, ...);

void     libsqlite_update_ip(struct wzd_ip_list_t *db,
		             struct wzd_ip_list_t *update,
			     struct wzd_ip_list_t **delete,
			     struct wzd_ip_list_t **add);

/** @} */

#endif /* __LIBSQLITE_MAIN__ */

