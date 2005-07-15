#include <stdlib.h> /* malloc */
#include <string.h> /* memset */

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_utf8.h>


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

void fake_exit(void)
{
  if (mainConfig) {
    free(mainConfig);
    mainConfig = NULL;
  }
}
