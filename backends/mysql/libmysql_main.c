/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2003  Pierre Chifflier
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, Pierre Chifflier
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */
#include <stdio.h>
#include <mysql.h>

#include "wzd_backend.h"

static MYSQL mysql;
static wzd_user_t *user_pool;
static char *user, *passwd, *hostname, *db;

static void wzd_mysql_error(const char *filename, const char  *func_name, int line); /*, const char *error); */
/*static int wzd_parse_arg(const char *arg);*/ /* parse arg (login:password@hostname */
static int wzd_parse_arg(char *arg);

static void wzd_mysql_error(const char *filename, const char  *func_name, int line)/*, const char *error)*/
{
  fprintf(stderr, "%s(%s):%d %s\n", filename, func_name, line, mysql_error(&mysql));
}

static int wzd_parse_arg(char *arg)
{
  char /**user, *pass, *host, *port,*/ *ptr;

  ptr = arg;

  user = (char*)strtok_r(arg, ":", &ptr);
/*  printf("user: '%s'\n",user);*/
  if (!user) return -1;

  passwd = (char *)strtok_r(NULL,"@", &ptr);
/*  printf("pass: '%s'\n",pass);*/
  if (!passwd) return -1;

  hostname = (char *)strtok_r(NULL, ":\n", &ptr);
/*  printf("host: '%s'\n",host);*/
  if (!hostname) return -1;

  db = (char *)strtok_r(NULL, "\n", &ptr);
/*  (printf("port: '%s'\n",port);*/
  if (!db) return -1;

  return 0;
}


int FCN_INIT(int *backend_storage, wzd_user_t * user_list, unsigned int user_max, wzd_group_t * group_list, unsigned int group_max, void *arg)
{
/*  int ret;*/

/*  const char *hostname, *user, *passwd, *db;*/

  if ((wzd_parse_arg((char *)arg)) != 0) {
    return -1;
  }

#ifdef DEBUG
  fprintf(stderr, "User: %s\nHostname: %s\nDatabase name: %s\n", user, hostname, db);
#endif

  *backend_storage = 1;

  mysql_init(&mysql);

  if (!mysql_real_connect(&mysql, hostname, user, passwd, db, 0, NULL, 0)) {
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    mysql_close(&mysql);
    return -1;
  } 
#ifdef DEBUG
  else
    fprintf(stderr, "Connected to database");
#endif

  return 0;
}

int FCN_VALIDATE_LOGIN(const char *login, wzd_user_t * user)
{
  //const char *select = "SELECT * FROM users WHERE username=";
  char *query = (char *)malloc((45+HARD_USERNAME_LENGTH));

  snprintf(query, 256, "SELECT * FROM users WHERE username='%s'", login);

  if (mysql_query(&mysql, query) != 0) { 
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }


  if (mysql_field_count(&mysql) == 1) {
    MYSQL_RES   *res;
    MYSQL_ROW    row, end_row;
    int num_fields;

    if (!(res = mysql_store_result(&mysql))) {
      wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
      return -1;
    }

    num_fields = mysql_num_fields(res);
    row = mysql_fetch_row(res);

    strncpy(user->username, row[0], (HARD_USERNAME_LENGTH- 1)); // username
    strncpy(user->username, row[2], (MAX_PASS_LENGTH - 1)); // rootpath
    user->uid = atoi(row[3]);
  } else // user does not exist in table
    return -1; 

  return 0;
}

int FCN_VALIDATE_PASS(const char *login, const char *pass, wzd_user_t * user)
{
  char *query = (char *)malloc((45+HARD_USERNAME_LENGTH));
  char * cipher;

  snprintf(query, 256, "SELECT * FROM users WHERE username='%s'", login);

  if (mysql_query(&mysql, query) != 0) {
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  if (mysql_field_count(&mysql) == 1) {
    MYSQL_RES   *res;
    MYSQL_ROW    row, end_row;
    int num_fields;

    if (!(res = mysql_store_result(&mysql))) {
      wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
      return -1;
    }

    num_fields = mysql_num_fields(res);
    row = mysql_fetch_row(res);
    strncpy(user->username, row[0], (HARD_USERNAME_LENGTH- 1)); // username
    strncpy(user->userpass, row[1], (MAX_PASS_LENGTH -1)); // userpass
    strncpy(user->username, row[2], (MAX_PASS_LENGTH - 1)); // rootpath

    user->uid = atoi(row[3]);

    if (strlen(user->userpass) == 0) 
      return user->uid;	// passworldless login

    cipher = (char*)crypt(pass, user->userpass);

    if (!strcasecmp(cipher,user->userpass))
      return -1;

  } else // user does not exist in table
    return -1;


  return 0;
}

int FCN_FIND_USER(const char *name, wzd_user_t * user)
{
  char *query = (char *)malloc((45+HARD_USERNAME_LENGTH));

  snprintf(query, 256, "SELECT * FROM users WHERE username='%s'", name);

  if (mysql_query(&mysql, query) != 0) {
    wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
    return -1;
  }

  if (mysql_field_count(&mysql) == 1) { 
    MYSQL_RES   *res;
    MYSQL_ROW    row, end_row;
    int num_fields;

    if (!(res = mysql_store_result(&mysql))) {
      wzd_mysql_error(__FILE__, __FUNCTION__, __LINE__);
      return -1;
    }

    num_fields = mysql_num_fields(res);
    row = mysql_fetch_row(res);
    strncpy(user->username, row[0], (HARD_USERNAME_LENGTH- 1)); // username
    strncpy(user->userpass, row[1], (MAX_PASS_LENGTH -1)); // userpass
    strncpy(user->username, row[2], (MAX_PASS_LENGTH - 1)); // rootpath
    user->uid = atoi(row[3]);
  } else  // no such user
    return -1;

  return 0;
}

int FCN_FIND_GROUP(int num, wzd_group_t * group)
{
  // XXX: forgot about it while  wzd_group_t->gid is not implemented

  return 0;
}

int FCN_CHPASS(const char *username, const char *new_pass)
{
  return 1;
}

/* if user does not exist, add it */
int FCN_MOD_USER(const char *name, wzd_user_t * user, unsigned long mod_type)
{
  return 1;
}

int FCN_MOD_GROUP(const char *name, wzd_group_t * group, unsigned long mod_type)
{
  return 1;
}

int  FCN_COMMIT_CHANGES(void)
{
  return 0;
}

int FCN_FINI()
{
#ifdef DEBUG
  fprintf(stderr, "Closing connection");
#endif

  mysql_close(&mysql);

  return 0;
}

