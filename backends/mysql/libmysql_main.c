#include <stdio.h>
#include <mysql.h>

#include "wzd_backend.h"

MYSQL mysql;
wzd_user_t *user_pool;
int users_count;

const void wzd_mysql_error(const char *filename, const char  *func_name, int line);//, const char *error); 

const void wzd_mysql_error(const char *filename, const char  *func_name, int line)//, const char *error)
{
	fprintf(stderr, "%s(%s):%n %s", filename, func_name, line, mysql_error(&mysql));
}


int 
FCN_INIT(int *backend_storage, void *arg)
{
//	int ret;

	const char *hostname,
		   *user,
		   *passwd,
		   *db;
	
	*backend_storage = 0;

	mysql_init(&mysql);

	if (!mysql_real_connect(&mysql, hostname, user, passwd, db, 0, NULL, 0)) {
		wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
		return -1;
	} 
#ifdef _DEBUG_
	else
		fprintf(stderr, "Connected to database");
#endif

	return 0;
	
}

int 
FCN_VALIDATE_LOGIN(const char *login, wzd_user_t * user)
{
	int found = 0, i = 0;
	const char *query = "SELECT * FROM users";

	if (mysql_query(&mysql, query) != 0) 
		wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);


	if (mysql_field_count(&mysql) > 0) {
		MYSQL_RES   *res;
		MYSQL_ROW    row, end_row;
		int num_fields;
		
		if (!(res = mysql_store_result(&mysql)))
			wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
			
		num_fields = mysql_num_fields(res);
		while ((row = mysql_fetch_row(res))) {
			strcpy(user_pool[i].username, row[0]); // username
			strcpy(user_pool[i].username, row[2]); // rootpath
			i++;
		}

		users_count = i;

	} else
		return -1;
			
	for (i = 0; i<=users_count; i++) {
		if (strcmp(user_pool[i].username, login) == 0) {
			found = 1;
			break;
		}
	}

	if (found) 
		return i;
	else
		return 	1;
}

int 
WZD_FINI()
{

#ifdef _DEGUB_
	fprintf(stderr, "Closing connection");
#endif

	mysql_close(&mysql);

	return 0;
	
}


