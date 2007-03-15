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

/** @} */

#endif /* __LIBSQLITE_MAIN__ */

