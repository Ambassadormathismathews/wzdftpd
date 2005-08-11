#include <stdlib.h> /* malloc */
#include <string.h> /* memset */

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_utf8.h>

wzd_user_t * f_user = NULL;

void fake_mainConfig(void)
{
  wzd_config_t * config;
  config = malloc(sizeof(wzd_config_t));
  memset(config, 0, sizeof(wzd_config_t));

  mainConfig = config;
}

void fake_backend(void)
{
}

void fake_utf8(void)
{
  if (!mainConfig) fake_mainConfig();
  utf8_detect(mainConfig);
}

void fake_user(void)
{
  wzd_user_t * user;

  if (!mainConfig) fake_mainConfig();
  user = malloc(sizeof(wzd_user_t));
  memset(user, 0, sizeof(wzd_user_t));

  strcpy(user->username,"test_user");
  user->uid = 666;
  strcpy(user->flags,"5"); /* 5 = color */

  f_user = user;
}

void fake_exit(void)
{
  if (mainConfig) {
    free(mainConfig);
    mainConfig = NULL;
  }
}
