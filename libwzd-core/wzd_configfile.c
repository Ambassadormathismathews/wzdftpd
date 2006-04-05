/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2004  Pierre Chifflier
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
/** \file wzd_configfile.c
 * \brief Simple config file parser (.ini like)
 *
 * \note Implementation was greatly inspired from gkeyfile.c, from the glib sources.
 */

#include "wzd_all.h"

#ifndef WZD_USE_PCH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include <fcntl.h> /* O_RDONLY */

#include <ctype.h> /* isspace */

#include "wzd_structs.h"
#include "wzd_log.h"

#include "wzd_string.h"
#include "wzd_utf8.h"
#include "wzd_configfile.h"

#include "wzd_debug.h"

#endif /* WZD_USE_PCH */


#include "libwzd-base/dlist.h"



#define VALUE_LIST_SEPARATOR    ","

typedef struct _wzd_configfile_group_t wzd_configfile_group_t;

typedef struct _wzd_configfile_keyvalue_t wzd_configfile_keyvalue_t;

struct _wzd_configfile_t {
  List * groups;
  wzd_string_t * parse_buffer;

  wzd_configfile_group_t * current_group;

  unsigned long flags;
};

struct _wzd_configfile_group_t {
  char * name;

  wzd_configfile_keyvalue_t * comment; /* comment at top */

  DList * values;
};

struct _wzd_configfile_keyvalue_t {
  char * key; /* NULL for comments */
  char * value;
};

static void _configfile_group_init(wzd_configfile_group_t * group);
static void _configfile_group_free(wzd_configfile_group_t * group);
static wzd_configfile_keyvalue_t * _configfile_keyvalue_calloc(void);
static void _configfile_keyvalue_free(wzd_configfile_keyvalue_t * kv);

static void config_init(wzd_configfile_t * config);
static void config_clear(wzd_configfile_t * config);

static int _config_cmp_keyvalue(const char *k1, const wzd_configfile_keyvalue_t *k2);
static int _config_cmp_groupname(const char *k1, const wzd_configfile_group_t *k2);

static int config_line_is_comment(const char * line);
static int config_line_is_group(const char * line);
static int config_line_is_keyvalue(const char * line);
static int config_parse_data(wzd_configfile_t * config, const char * data, size_t length);
static int config_parse_flush_buffer(wzd_configfile_t * config);
static int config_parse_line(wzd_configfile_t * config, const char * line, size_t length);
static int config_parse_comment(wzd_configfile_t * config, const char * line, size_t length);
static int config_parse_group(wzd_configfile_t * config, const char * line, size_t length);
static int config_parse_keyvalue(wzd_configfile_t * config, const char * line, size_t length);

static wzd_configfile_group_t * config_lookup_group(const wzd_configfile_t * config, const char *groupname);
static wzd_configfile_keyvalue_t * config_lookup_keyvalue(const wzd_configfile_t * config, wzd_configfile_group_t * group, const char * key);

static int config_add_key(wzd_configfile_t * config, wzd_configfile_group_t * group, const char * key, const char * value);
static int config_add_group(wzd_configfile_t * config, const char * groupname);

static int config_set_key_comment(wzd_configfile_t * config, const char * groupname, const char * key, const char * comment);
static int config_set_group_comment(wzd_configfile_t * config, const char * groupname, const char * comment);
static int config_set_top_comment(wzd_configfile_t * config, const char * comment);



/** \brief Creates a new empty wzd_configfile_t object.
 */
wzd_configfile_t * config_new(void)
{
  wzd_configfile_t * filenew;

  filenew = wzd_malloc(sizeof(wzd_configfile_t));
  config_init(filenew);

  return filenew;
}

/** \brief Frees a wzd_configfile_t
 */
void config_free(wzd_configfile_t * file)
{
  if (!file) return;

  config_clear(file);
  wzd_free(file);
}

/** \brief Returns the list of groups contained in \a file
 */
wzd_string_t ** config_get_groups(const wzd_configfile_t * file)
{
  wzd_string_t ** array;
  ListElmt * elmnt;
  wzd_configfile_group_t * group = NULL;
  int i = 0;

  if (!file) return NULL;

  array = wzd_malloc(sizeof(*array) * (list_size(file->groups)+1));

  for (elmnt = list_head(file->groups); elmnt; elmnt = list_next(elmnt)) {
    group = list_data(elmnt);
    array[i++] = STR(group->name);
  }

  array[i] = NULL;

  return array;
}

/** \brief Returns the list of keys contained in \a group
 */
wzd_string_t ** config_get_keys(const wzd_configfile_t * file, const char * groupname, int * errcode)
{
  wzd_string_t ** array;
  DListElmt * elmnt;
  wzd_configfile_group_t * group;
  wzd_configfile_keyvalue_t * kv;
  int i = 0;

  if (!file || !groupname) return 0;

  group = config_lookup_group(file,groupname);
  if (!group) {
    if (errcode) *errcode = CF_ERROR_GROUP_NOT_FOUND;
    return NULL;
  }

  array = wzd_malloc(sizeof(*array) * (dlist_size(group->values)+1));

  for (elmnt = dlist_head(group->values); elmnt; elmnt = dlist_next(elmnt)) {
    kv = list_data(elmnt);
    array[i++] = STR(kv->key);
  }

  array[i] = NULL;

  return array;
}

/** \brief Looks whether the config file has the group \a groupname.
 * \return 1 if \a groupname is part of \a file
 */
int config_has_group(wzd_configfile_t * file, const char * groupname)
{
  if (!file || !groupname) return 0;

  return config_lookup_group(file,groupname) != NULL;
}

/** \brief Looks whether the config file has the key \a key in the group \a groupname.
 * \return 1 if \a key is part of \a groupname
 */
int config_has_key(wzd_configfile_t * file, const char * groupname, const char * key)
{
  wzd_configfile_group_t * group;
  wzd_configfile_keyvalue_t * kv;

  if (!file || !groupname || !key) return 0;

  group = config_lookup_group(file,groupname);
  if (!group) return 0;

  kv = config_lookup_keyvalue(file,group,key);

  return kv != NULL;
}

/** \brief Returns the value associated with \a key under \a groupname.
 * \return the value, or NULL if the key is not found
 * The returned value is a pointer to the object, it must not be freed.
 */
char * config_get_value(const wzd_configfile_t * file, const char * groupname, const char * key)
{
  wzd_configfile_group_t * group;
  wzd_configfile_keyvalue_t * kv;

  if (!file || !groupname || !key) return NULL;

  group = config_lookup_group(file,groupname);
  if (!group) return NULL;

  kv = config_lookup_keyvalue(file,group,key);
  if (!kv) return NULL;

  return kv->value;
}

/** \brief Associates a new value with \a key under \a groupname.
 *
 * If \a key cannot be found then it is created. If \a groupname cannot be found then it is
 * created.
 */
int config_set_value(wzd_configfile_t * file, const char * groupname, const char * key, const char * value)
{
  wzd_configfile_group_t * group;
  wzd_configfile_keyvalue_t * kv;

  if (!file || !groupname || !key || !value) return CF_ERROR_INVALID_ARGS;

  group = config_lookup_group(file,groupname);
  if (!group) {
    if (config_add_group(file, groupname)) return CF_ERROR_GROUP_NOT_FOUND;
    group = config_lookup_group(file,groupname);
    if (!group) return CF_ERROR_GROUP_NOT_FOUND;
  }

  kv = config_lookup_keyvalue(file,group,key);
  if (!kv) {
    return config_add_key(file,group,key,value);
  } else {
    wzd_free(kv->value);
    kv->value = wzd_strdup(value);
  }

  return CF_OK;
}
 
/** \brief Returns the value associated with \a key under \a groupname as a string.
 * \return the value, else \a errcode is set to nonzero.
 */
wzd_string_t * config_get_string(const wzd_configfile_t * file, const char * groupname, const char * key, int * errcode)
{
  char * value;
  wzd_string_t * str_value = NULL;

  if (!file || !groupname || !key) return NULL;
  if (errcode) *errcode = CF_OK;

  value = config_get_value(file,groupname,key);
  if (!value) {
    if (errcode) *errcode = CF_ERROR_NOT_FOUND;
    return NULL;
  }

#ifdef HAVE_UTF8
  if (!utf8_valid(value,strlen(value))) {
    if (errcode) *errcode = CF_ERROR_INVALID_ENCODING;
    return NULL;
  }
#endif

  str_value = STR(value);

  return str_value;
}

/** \brief Associates a new string value with \a key under \a groupname.
 *
 * If \a key cannot be found then it is created.
 */
int config_set_string(wzd_configfile_t * file, const char * groupname, const char * key, wzd_string_t * value)
{
  if (!file || !groupname || !key) return CF_ERROR_INVALID_ARGS;

  return config_set_value(file, groupname, key, str_tochar(value));
}

/** \brief Returns the value associated with \a key under \a groupname as a string.
 * \return a NULL-terminated string array,, or NULL and set \a errcode to nonzero.
 * The array should be freed using str_deallocate_array()
 */
wzd_string_t ** config_get_string_list(wzd_configfile_t * file, const char * groupname, const char * key, int * errcode)
{
  char * value;
  wzd_string_t * str_value;
  wzd_string_t ** array = NULL;
  unsigned int i;

  if (!file || !groupname || !key) return NULL;
  if (errcode) *errcode = CF_OK;

  value = config_get_value(file,groupname,key);
  if (!value) {
    if (errcode) *errcode = CF_ERROR_NOT_FOUND;
    return NULL;
  }

#ifdef HAVE_UTF8
  if (!utf8_valid(value,strlen(value))) {
    if (errcode) *errcode = CF_ERROR_INVALID_ENCODING;
    return NULL;
  }
#endif

  str_value = STR(value);

  array = str_split(str_value,VALUE_LIST_SEPARATOR,0);

  str_deallocate(str_value);

  /* remove leading spaces */
  if (array) {
    for (i=0; array[i]; i++) {
      str_trim_left(array[i]);
    }
  }

  return array;
}

/** \brief Associates a list of string values with \a key under \a groupname.
 *
 * If \a key cannot be found then it is created.
 */
int config_set_string_list(wzd_configfile_t * file, const char * groupname, const char * key, wzd_string_t ** value, size_t length)
{
  wzd_string_t * str;
  size_t i;
  int ret;

  if (!file || !groupname || !key) return CF_ERROR_INVALID_ARGS;

  str = str_allocate();
  for (i=0; value[i] != NULL && i < length; i++) {
    str_append(str, str_tochar(value[i]));
    str_append(str, VALUE_LIST_SEPARATOR);
  }
  /* removes the last separator */
  str_erase(str, str_length(str)-strlen(VALUE_LIST_SEPARATOR), -1);

  ret = config_set_value(file, groupname, key, str_tochar(str));

  str_deallocate(str);

  return ret;
}

/** \brief Returns the value associated with \a key under \a groupname as a boolean.
 * \return the value, else \a errcode is set to nonzero.
 */
int config_get_boolean(wzd_configfile_t * file, const char * groupname, const char * key, int * errcode)
{
  char * value;

  if (errcode) *errcode = CF_OK;

  value = config_get_value(file,groupname,key);
  if (!value) {
    if (errcode) *errcode = CF_ERROR_NOT_FOUND;
    return -1;
  }

  if (strcmp(value,"true")==0  || strcmp(value,"1")==0 || strcmp(value,"yes")==0) return 1;
  if (strcmp(value,"false")==0 || strcmp(value,"0")==0 || strcmp(value,"no")==0 ) return 0;

  if (errcode) *errcode = CF_ERROR_PARSE;

  return -1;
}

/** \brief Associates a new boolean value with \a key under \a groupname.
 *
 * If \a key cannot be found then it is created.
 */
int config_set_boolean(wzd_configfile_t * file, const char * groupname, const char * key, int value)
{
  char * result;

  if (!file || !groupname || !key) return CF_ERROR_INVALID_ARGS;

  result = (value) ? "true" : "false";

  return config_set_value(file, groupname, key, result);
}

/** \brief Returns the value associated with \a key under \a groupname as an integer.
 * \return the value, else \a errcode is set to nonzero.
 */
int config_get_integer(wzd_configfile_t * file, const char * groupname, const char * key, int * errcode)
{
  char * value;
  char * end;
  long longv;
  int intv;

  if (errcode) *errcode = CF_OK;

  value = config_get_value(file,groupname,key);
  if (!value) {
    if (errcode) *errcode = CF_ERROR_NOT_FOUND;
    return -1;
  }

  longv = strtoul(value,&end,10);
  if (*value == '\0' || *end != '\0') {
    if (errcode) *errcode = CF_ERROR_PARSE;
    return -1;
  }
  
  intv = longv;
  if (intv != longv || errno == ERANGE) {
    if (errcode) *errcode = CF_ERROR_PARSE;
    return -1;
  }

  return intv;
}

/** \brief Associates a new integer value with \a key under \a groupname.
 *
 * If \a key cannot be found then it is created.
 */
int config_set_integer(wzd_configfile_t * file, const char * groupname, const char * key, int value)
{
  wzd_string_t * str;
  int ret;

  if (!file || !groupname || !key) return CF_ERROR_INVALID_ARGS;

  str = str_allocate();
  str_sprintf(str,"%d",value);

  ret = config_set_value(file, groupname, key, str_tochar(str));

  str_deallocate(str);

  return ret;
}

/** \brief Places a comment above \a key from \a groupname.
 *
 * If \a key is NULL then \a comment will be written above \a groupname.
 * If both \a key and \a groupname are NULL, then \a comment will be written
 * above the first group in the file.
 */
int config_set_comment(wzd_configfile_t * file, const char * groupname, const char * key, const char * comment)
{
  if (!file) return CF_ERROR_INVALID_ARGS;

  if (groupname && key)
    return config_set_key_comment(file, groupname, key, comment);
  else if (groupname)
    return config_set_group_comment(file, groupname, comment);
  else
    return config_set_top_comment(file, comment);
}

/** \brief Removes a comment above \a key from \a groupname
 *
 * If \a key is \a NULL then the comment above \a groupname is removed.
 * If both \a key and \a groupname are \a NULL, then the comment before the
 * first group is removed.
 */
int config_remove_comment(wzd_configfile_t * file, const char * groupname, const char * key)
{
  if (!file) return CF_ERROR_INVALID_ARGS;

  if (groupname && key)
    return config_set_key_comment(file, groupname, key, NULL);
  else if (groupname)
    return config_set_group_comment(file, groupname, NULL);
  else
    return config_set_top_comment(file, NULL);
}

/** \brief Removes a \a key in \a groupname from the key file.
 */
int config_remove_key(wzd_configfile_t * file, const char * groupname, const char * key)
{
  wzd_configfile_group_t * group;
  wzd_configfile_keyvalue_t * kv;
  DListElmt * element;

  if (!file || !groupname || !key) return CF_ERROR_INVALID_ARGS;

  group = config_lookup_group(file,groupname);
  if (!group) {
    return CF_ERROR_GROUP_NOT_FOUND;
  }

  /* find the key the comments are supposed to be associated with */
  element = dlist_lookup_node(group->values,(void*)key);
  if (!element) {
    return CF_ERROR_NOT_FOUND;
  } else {
    dlist_remove(group->values,element,(void**)&kv);
    _configfile_keyvalue_free(kv);
  }

  return CF_OK;
}

/** \brief Removes a \a groupname (and all associated keys and comments) from the key file.
 */
int config_remove_group(wzd_configfile_t * file, const char * groupname)
{
  ListElmt * element;
  wzd_configfile_group_t * group;

  if (!file || !groupname) return CF_ERROR_INVALID_ARGS;

  element = list_lookup_node(file->groups, (void*)groupname);
  if (!element) return CF_ERROR_GROUP_NOT_FOUND;

  if (list_data(element) == file->current_group) {
    if (list_head(file->groups) != element)
      file->current_group = list_data(list_head(file->groups));
    else
      file->current_group = NULL;
  }

  list_remove(file->groups, element, (void**)&group);

  if (group) {
    _configfile_group_free(group);
  }

  return CF_OK;
}

/** Loads a key file from disk into an empty wzd_configfile_t structure.
 *
 * If the object cannot be created then the return value is non-zero.
 */
int config_load_from_file (wzd_configfile_t * config, const char * file, unsigned long flags)
{
  int fd;
  int ret;

  if (!config || !file) return CF_ERROR_INVALID_ARGS;

  fd = open(file, O_RDONLY, 0);
  if (fd < 0)
    return CF_ERROR_FILE;

  ret = config_load_from_fd(config, fd, flags);

  close(fd);
  return ret;
}

/** Loads a key file from an opened file descriptor into an empty
 * wzd_configfile_t structure.
 *
 * If the object cannot be created then the return value is non-zero.
 */
int config_load_from_fd (wzd_configfile_t * config, int fd, unsigned long flags)
{
  char read_buf[4096];
  int bytes_read;
  int ret;
  struct stat stat_buf;

  if (!config || fd < 0) return CF_ERROR_INVALID_ARGS;

  if (fstat(fd, &stat_buf) < 0)
    return CF_ERROR_FILE;

  if (!S_ISREG(stat_buf.st_mode))
    return CF_ERROR_FILE;

  if (stat_buf.st_size == 0)
    return CF_ERROR_PARSE;

  config->flags = flags;

  do {
    bytes_read = read(fd, read_buf, sizeof(read_buf));

    if (bytes_read == 0) /* EOF */
      break;

    if (bytes_read < 0) {
      if (errno == EINTR || errno == EAGAIN)
        continue;

      return CF_ERROR_PARSE;
    }

    /** \bug FIXME what happens if the last line is truncated ! */
    ret = config_parse_data(config, read_buf, bytes_read);
  } while (ret == CF_OK);

  if (ret != CF_OK)
    return ret;

  config_parse_flush_buffer (config);

  return ret;
}

/** Loads a key file from memory into an empty wzd_configfile_t structure.
 *
 * If the object cannot be created then the return value is non-zero.
 */
int config_load_from_data (wzd_configfile_t * config, const char * data, size_t length, unsigned long flags)
{
  int ret;

  if (!config) return CF_ERROR_INVALID_ARGS;
  if (!data) return CF_ERROR_INVALID_ARGS;
  if (length == 0) return CF_ERROR_INVALID_ARGS;

  if (length == (size_t)-1)
    length = strlen (data);

#if 0
  if (config->approximate_size > 0)
    {
      config_clear (config);
      config_init (config);
    }
#endif
  config->flags = flags;

  ret = config_parse_data (config, data, length);

  if (ret) return ret;

  config_parse_flush_buffer (config);

  return ret;
}

/** outputs \a config as a wzd_string_t.
 */
wzd_string_t * config_to_data (wzd_configfile_t * config, size_t * length)
{
  wzd_string_t * data_string;
  ListElmt * elmnt;
  DListElmt * el;
  wzd_configfile_group_t * group;
  wzd_configfile_keyvalue_t * kv;

  if (!config) return NULL;

  data_string = str_allocate();

  for (elmnt = list_head(config->groups); elmnt; elmnt = list_next(elmnt)) {
    group = list_data(elmnt);

    if (group->comment != NULL)
      str_append_printf (data_string, "%s\n", group->comment->value);
    if (group->name != NULL)
      str_append_printf (data_string, "[%s]\n", group->name);

    if (!group->values) continue;

    for (el = dlist_head (group->values); el != NULL; el = dlist_next(el))
    {
      kv = dlist_data(el);

      if (kv->key != NULL)
        str_append_printf (data_string, "%s = %s\n", kv->key, kv->value);
      else
        str_append_printf (data_string, "%s\n", kv->value);
    }
  }

  if (length)
    *length = str_length(data_string);

  return data_string;
}

/***************** static functions *****************/

static void _configfile_group_init(wzd_configfile_group_t * group)
{
  WZD_ASSERT_VOID(group != NULL);
  group->name = NULL;
  group->comment = NULL;
  group->values = wzd_malloc(sizeof(List));
  dlist_init(group->values,(void (*)(void*))_configfile_keyvalue_free);
  group->values->test = (int (*)(const void*,const void*))_config_cmp_keyvalue;
}

static void _configfile_group_free(wzd_configfile_group_t * group)
{
  WZD_ASSERT_VOID(group != NULL);
  wzd_free(group->name);
  if (group->comment) _configfile_keyvalue_free(group->comment);
  dlist_destroy(group->values);
  wzd_free(group->values);
  wzd_free(group);
}

static wzd_configfile_keyvalue_t * _configfile_keyvalue_calloc(void)
{
  wzd_configfile_keyvalue_t * kv;

  kv = wzd_malloc(sizeof(*kv));
  WZD_ASSERT_RETURN(kv != NULL, NULL);
  kv->key = NULL;
  kv->value = NULL;

  return kv;
}

static void _configfile_keyvalue_free(wzd_configfile_keyvalue_t * kv)
{
  WZD_ASSERT_VOID(kv != NULL);
  wzd_free(kv->key);
  wzd_free(kv->value);
  wzd_free(kv);
}

static void config_init(wzd_configfile_t * config)
{
  wzd_configfile_group_t * group;

  if (!config) return;
  config->groups = wzd_malloc(sizeof(List));
  list_init(config->groups,(void (*)(void *))_configfile_group_free);
  group = wzd_malloc(sizeof(wzd_configfile_group_t));
  _configfile_group_init(group);
  list_ins_next(config->groups,NULL,group);
  config->groups->test = (int (*)(const void*,const void*))_config_cmp_groupname;
  config->parse_buffer = str_allocate();
  config->current_group = group;
  config->flags = CF_FILE_NONE;
}

static void config_clear(wzd_configfile_t * config)
{
  if (!config) return;
  list_destroy(config->groups);
  wzd_free(config->groups);
  str_deallocate(config->parse_buffer);
}

static int _config_cmp_keyvalue(const char *k1, const wzd_configfile_keyvalue_t *k2)
{
  WZD_ASSERT(k2 != NULL);
  if (k1 == NULL || k2->key == NULL) return (!(k1 == k2->key));

  return strcmp(k1,k2->key);
}

static int _config_cmp_groupname(const char *k1, const wzd_configfile_group_t *k2)
{
  WZD_ASSERT(k2 != NULL);
  if (k1 == NULL || k2->name == NULL) return (!(k1 == k2->name));

  return strcmp(k1,k2->name);
}

static int config_line_is_comment(const char * line)
{
  return (*line == '#' || *line == '\0' || *line == '\n');
}

static int config_line_is_group(const char * line)
{
  const char * p;

  p = line;
  if (*p != '[') return 0;

  while (*p && *p != ']')
    p++;

  if (!*p) return 0;

  return 1;
}

static int config_line_is_keyvalue(const char * line)
{
  const char * p;

  p = strchr(line,'=');
  if (!p) return 0;

  /* key must be non-empty */
  if (*p == line[0])
    return 0;

  return 1;
}

static int config_parse_data(wzd_configfile_t * config, const char * data, size_t length)
{
  size_t i;
  int ret;

  if (!config || !data) return CF_ERROR_INVALID_ARGS;

  for (i = 0; i < length; i++) {
    if (data[i] == '\n')
    {
      if (i > 0 && str_length(config->parse_buffer) > 0 &&
          str_tochar(config->parse_buffer)[str_length(config->parse_buffer) - 1] == '\r')
        str_erase (config->parse_buffer, str_length(config->parse_buffer) - 1, 1);
	    
      /* if the line is ended with a \ then delete the last char and continue with next line
       */
      if (i > 0 && str_length(config->parse_buffer) > 0 &&
          str_tochar(config->parse_buffer)[str_length(config->parse_buffer) - 1] == '\\') {
        str_erase (config->parse_buffer, str_length(config->parse_buffer) - 1, 1);
        continue;
      }

      /* When a newline is encountered flush the parse buffer so that the
       * line can be parsed.  Note that completely blank lines won't show
       * up in the parse buffer, so they get parsed directly.
       */
      if (str_length(config->parse_buffer) > 0)
        ret = config_parse_flush_buffer (config);
      else
        ret = config_parse_comment (config, "", 1);

      if (ret) return ret; /* propagate error */
    } else
      str_append_c (config->parse_buffer, data[i]);
  }

  return CF_OK;
}

static int config_parse_flush_buffer(wzd_configfile_t * config)
{
  int ret;

  if (!config) return CF_ERROR_INVALID_ARGS;

#if DEBUG
  if ((config->flags & CF_FILE_DEBUG)) {
    out_err(LEVEL_INFO,"flushing buffer : [ %s ]\n",str_tochar(config->parse_buffer));
  }
#endif

  if (str_length(config->parse_buffer) > 0) {
    ret = config_parse_line (config, str_tochar(config->parse_buffer), str_length(config->parse_buffer));
    str_erase (config->parse_buffer, 0, -1);

#if DEBUG
  if ((config->flags & CF_FILE_DEBUG)) {
    if (ret) {
      out_err(LEVEL_INFO,"ERROR: config_parse_line returned %d !\n",ret);
    }
  }
#endif

    if (ret) return ret;
  }

  return CF_OK;
}

static int config_parse_line(wzd_configfile_t * config, const char * line, size_t length)
{
  const char * line_start;
  int ret;

  if (!config || !line) return CF_ERROR_INVALID_ARGS;

  line_start = line;
  while (isspace(*line_start)) line_start++;

  if (config_line_is_comment(line_start))
    ret = config_parse_comment(config,line,length);
  else if (config_line_is_group(line_start))
    ret = config_parse_group(config,line,length - (line_start - line));
  else if (config_line_is_keyvalue(line_start))
    ret = config_parse_keyvalue(config,line,length - (line_start - line));
  else
    return CF_ERROR_PARSE;

  if (ret) return ret; /* propagate error */

  return 0;
}

static int config_parse_comment(wzd_configfile_t * config, const char * line, size_t length)
{
  wzd_configfile_keyvalue_t * kv;

  if (!config || !line) return CF_ERROR_INVALID_ARGS;
  if (!config->current_group) return CF_ERROR_NO_CURRENT_GROUP;

  kv = _configfile_keyvalue_calloc();
  kv->value = wzd_strndup(line,length);

  dlist_ins_next(config->current_group->values,dlist_tail(config->current_group->values),kv);

  return CF_OK;
}

static int config_parse_group(wzd_configfile_t * config, const char * line, size_t length)
{
  char * groupname;
  const char *group_name_start, *group_name_end;

  if (!config || !line) return CF_ERROR_INVALID_ARGS;

  /* advance past opening '[' */
  group_name_start = line + 1;
  group_name_end = line + length - 1;

  while (*group_name_end != ']')
    group_name_end--;

  groupname = wzd_strndup(group_name_start,group_name_end - group_name_start);
  config_add_group(config,groupname);
  wzd_free(groupname);

  return CF_OK;
}

static int config_parse_keyvalue(wzd_configfile_t * config, const char * line, size_t length)
{
  char *key, *value, *key_end, *value_start;
  size_t key_len, value_len;
  int ret;

  if (!config || !line) return CF_ERROR_INVALID_ARGS;
  if (!config->current_group || !config->current_group->name) return CF_ERROR_NO_CURRENT_GROUP;

  key_end = value_start = strchr (line, '=');
  if (key_end == NULL) return CF_ERROR_PARSE;

  key_end--;
  value_start++;

  /* Pull the key name from the line (chomping trailing whitespace) */
  while (isspace (*key_end))
    key_end--;

  key_len = key_end - line + 2;
  if (key_len > length) return CF_ERROR_PARSE;

  key = wzd_strndup (line, key_len - 1);

  /* Pull the value from the line (chugging leading whitespace)
   */
  while (isspace (*value_start))
    value_start++;

  value_len = line + length - value_start;
  while (value_len > 0 && isspace(value_start[value_len-1]))
    value_len--;

  value = wzd_strndup (value_start, value_len);

/*  if (config->start_group == NULL) return CF_ERROR_PARSE; */

  ret = config_add_key(config,config->current_group,key,value);

  wzd_free(key);
  wzd_free(value);

  return ret;
}

static wzd_configfile_group_t * config_lookup_group(const wzd_configfile_t * config, const char *groupname)
{
  ListElmt * elmnt;
  wzd_configfile_group_t * group = NULL;

  if (!config || !groupname) return NULL;

  for (elmnt = list_head(config->groups); elmnt; elmnt = list_next(elmnt)) {
    group = list_data(elmnt);
    if (group && group->name && strcmp(group->name,groupname)==0) break;
    group = NULL;
  }

  return group;
}

static wzd_configfile_keyvalue_t * config_lookup_keyvalue(const wzd_configfile_t * config, wzd_configfile_group_t * group, const char * key)
{
  DListElmt * elmnt;
  wzd_configfile_keyvalue_t * kv = NULL;

  if (!config || !group || !key) return NULL;

  /** \todo this should be replaced by a direct lookup in a hash table */
  for (elmnt = dlist_head(group->values); elmnt; elmnt = dlist_next(elmnt)) {
    kv = dlist_data(elmnt);
    if (kv && kv->key && strcmp(kv->key,key)==0) break;
    kv = NULL;
  }

  return kv;
}

static int config_add_key(wzd_configfile_t * config, wzd_configfile_group_t * group, const char * key, const char * value)
{
  wzd_configfile_keyvalue_t * kv;

  if (!config || !group) return CF_ERROR_INVALID_ARGS;

  if ( (kv = config_lookup_keyvalue(config, group, key)) != NULL)
  {
    if (config->flags & CF_FILE_MERGE_MULTIPLE) {
      wzd_string_t * str;

      str = STR(kv->value);
      str_append_printf(str, "%s %s", VALUE_LIST_SEPARATOR, value);
      wzd_free(kv->value);
      kv->value = wzd_strdup( str_tochar(str) );
      str_deallocate(str);

      return CF_OK;
    }
#if DEBUG
    out_err(LEVEL_HIGH,"*** key collision *** %s/%s: old [%s] / new [%s]\n",
        group->name, key, kv->value, value);
#endif
    return CF_ERROR_KEY_ALREADY_EXISTS;
  }

  kv = _configfile_keyvalue_calloc();
  kv->key = wzd_strdup(key);
  kv->value = wzd_strdup(value);

  dlist_ins_next(group->values,dlist_tail(group->values),kv);

  return CF_OK;
}

static int config_add_group(wzd_configfile_t * config, const char * groupname)
{
  wzd_configfile_group_t * group;

  if (!config) return CF_ERROR_INVALID_ARGS;

  group = wzd_malloc(sizeof(wzd_configfile_group_t));
  _configfile_group_init(group);
  group->name = wzd_strdup(groupname);
  list_ins_next(config->groups,list_tail(config->groups),group);

  config->current_group = group;

  return CF_OK;
}

static int config_set_key_comment(wzd_configfile_t * config, const char * groupname, const char * key, const char * comment)
{
  wzd_configfile_group_t * group;
  wzd_configfile_keyvalue_t * kv;
  DListElmt * element, * tmp, * current_node;

  if (!config || !groupname) return CF_ERROR_INVALID_ARGS;

  group = config_lookup_group(config,groupname);
  if (!group) return CF_ERROR_GROUP_NOT_FOUND;

  /* find the key the comments are supposed to be associated with */
  element = dlist_lookup_node(group->values,(void*)key);
  if (!element) return CF_ERROR_NOT_FOUND;

  /* free existing comments for that key */
  tmp = element->prev;
  while (tmp) {
    kv = dlist_data(tmp);
    
    if (kv->key) break;

    current_node = tmp;
    tmp = tmp->prev;
    dlist_remove(group->values,current_node,(void**)&kv);
    _configfile_keyvalue_free(kv);
  }

  if (comment == NULL) return CF_OK;

  /* add our comment */
  kv = _configfile_keyvalue_calloc();
  kv->value = wzd_strdup(comment);

  dlist_ins_prev(group->values,element,kv);


  return CF_ERROR_PARSE;
}

static int config_set_group_comment(wzd_configfile_t * config, const char * groupname, const char * comment)
{
  wzd_configfile_group_t * group;

  if (!config || !groupname) return CF_ERROR_INVALID_ARGS;

  group = config_lookup_group(config,groupname);
  if (!group) return CF_ERROR_GROUP_NOT_FOUND;

  /* remove any existing comment */
  if (group->comment) {
    _configfile_keyvalue_free(group->comment);
    group->comment = NULL;
  }

  if (!comment) return CF_OK;

  if (config_line_is_comment(comment)) {
    group->comment = wzd_malloc(sizeof(wzd_configfile_group_t));
    group->comment->key = NULL;
    group->comment->value = wzd_strdup(comment);

    return CF_OK;
  }

  return CF_ERROR_PARSE;
}

static int config_set_top_comment(wzd_configfile_t * config, const char * comment)
{
  ListElmt * elmnt;
  wzd_configfile_group_t * group;
  wzd_configfile_keyvalue_t * kv;

  if (!config->groups) return CF_ERROR_INVALID_ARGS;

  elmnt = list_head(config->groups);
  group = list_data(elmnt);
  /* the last group is for comments only */
  if (!group || group->name) return CF_ERROR_INVALID_ARGS;

  WZD_ASSERT(group->values != NULL);

  while (dlist_size(group->values)>0) {
    dlist_remove(group->values,dlist_tail(group->values),(void**)&kv);
    _configfile_keyvalue_free(kv);
  }

  if (!comment)
    return CF_OK;

  if (config_line_is_comment(comment)) {
    kv = _configfile_keyvalue_calloc();
    kv->value = wzd_strdup(comment);

    dlist_ins_next(group->values,NULL,kv);

    return CF_OK;
  }

  return CF_ERROR_PARSE;
}

