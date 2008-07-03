#include <stdlib.h>
#include <string.h>

#ifndef WIN32
# include <unistd.h>
#endif

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_configfile.h>

#include <libwzd-core/wzd_debug.h>

#define C1 0x12345678
#define C2 0x9abcdef0


int main()
{
  unsigned long c1 = C1;
  int ret;
  wzd_configfile_t * file;
  wzd_string_t * str;
  wzd_string_t ** str_array;
  unsigned int i;
  const char * ptr;
  unsigned long c2 = C2;
  const char * data = "[GLOBAL]\n"
    "# comment 1\n"
    "key1 = value1\n"
    "multikey = v1, \\\n"
    "  v2\n";
  const char * multikey_ref[] = { "v1", "v2" };

  file = config_new();

/*  config_test(file); */
  ret = config_load_from_data (file, data, strlen(data), 0 /* flags */);

  config_set_value(file, "GLOBAL", "key1", "new_value1");
  ptr = config_get_value(file, "GLOBAL", "key1");
  if (strcmp(ptr,"new_value1")!=0) {
    fprintf(stderr,"config_get_value failed\n");
    exit (-1);
  }

  config_set_value(file, "GLOBAL", "key2", "value2");

  str_array = config_get_string_list(file, "GLOBAL", "multikey", NULL);
  for (i=0; str_array[i]; i++) {
    if (strcmp(multikey_ref[i],str_tochar(str_array[i]))) {
      fprintf(stderr, "error in key 'multikey' at index %d: read [%s] instead of [%s]\n",
	  i,str_tochar(str_array[i]),multikey_ref[i]);
      return -1;
    }
  }
  str_deallocate_array(str_array);

  str = STR("value_str");
  config_set_string(file, "GLOBAL", "key_str", str);
  str_deallocate(str);
  str = config_get_string(file, "GLOBAL", "key_bool", NULL);
  str_deallocate(str);

  str_array = config_get_string_list(file, "GLOBAL", "key_str", NULL);
  str_deallocate_array(str_array);

  config_set_value(file, "GLOBAL", "key_str_list", "v1,v2,v3");
  str_array = config_get_string_list(file, "GLOBAL", "key_str_list", NULL);
  str_deallocate_array(str_array);

  str_array = wzd_malloc( 3 * sizeof(wzd_string_t*));
  str_array[0] = STR("t1");
  str_array[1] = STR("t2");
  str_array[2] = NULL;
  config_set_string_list(file, "GLOBAL", "key_str_list", str_array, 3);
  str_deallocate_array(str_array);

  str_array = config_get_string_list(file, "GLOBAL", "key_str_list", NULL);
  str_deallocate_array(str_array);

  config_set_boolean(file, "GLOBAL", "key_bool", 1);
  config_get_boolean(file, "GLOBAL", "key_bool", NULL);

  config_set_integer(file, "GLOBAL", "key_int", 666);
  config_get_integer(file, "GLOBAL", "key_int", NULL);

  config_set_comment(file, NULL, NULL, "# top comment");
  config_set_comment(file, NULL, NULL, "# top comment 2");

  config_set_comment(file, "GLOBAL", NULL, "# group comment");
  config_set_comment(file, "GLOBAL", NULL, "# group comment 2");

  config_set_comment(file, "GLOBAL", "key_int", "# key comment");
  config_set_comment(file, "GLOBAL", "key_int", "# key_int comment 2");

  config_set_value(file, "GLOBAL", "key_removed", "should not be here");
  config_remove_key(file, "GLOBAL", "key_removed");

#if 0
  config_remove_comment(file, NULL, NULL);
  config_remove_comment(file, "GLOBAL", NULL);
  config_remove_comment(file, "GLOBAL", "key1");
#endif

  config_set_value(file, "GROUP2", "keyr", "should not be here");
  config_remove_group(file, "GROUP2");

  str = config_to_data(file, NULL);

  if (str) printf("%s\n",str_tochar(str));

  config_free(file);
  str_deallocate(str);

  if (c1 != C1) {
    fprintf(stderr, "c1 nuked !\n");
    return -1;
  }
  if (c2 != C2) {
    fprintf(stderr, "c2 nuked !\n");
    return -1;
  }

  return 0;
}
