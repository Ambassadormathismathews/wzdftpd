#include <stdlib.h>
#include <string.h>

#ifndef WIN32
# include <unistd.h>
#endif

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_configfile.h>

#define C1 0x12345678
#define C2 0x9abcdef0


int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  int ret;
  wzd_configfile_t * file;
  wzd_string_t * str;
  unsigned long c2 = C2;
  const char * data = "[GLOBAL]\n"
    "key1 = value1";

  file = config_new();

/*  config_test(file); */
  ret = config_load_from_data (file, data, strlen(data), 0 /* flags */);

  config_set_value(file, "GLOBAL", "key1", "new_value1");

  config_set_value(file, "GLOBAL", "key2", "value2");

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
