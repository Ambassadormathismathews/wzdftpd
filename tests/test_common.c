#include <stdlib.h> /* malloc */
#include <string.h> /* memset */
#include <pthread.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_group.h>
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_mod.h>
#include <libwzd-core/wzd_user.h>
#include <libwzd-core/wzd_utf8.h>

#include <libwzd-core/wzd_cache.h>

#include <libwzd-core/wzd_debug.h>

#include "test_common.h"

void fake_write_function(fd_t fd, const char * msg, size_t msg_len, unsigned int timeout, wzd_context_t * context);


wzd_user_t * f_user = NULL;
wzd_group_t * f_group = NULL;
wzd_context_t * f_context = NULL;

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
  if (!f_group) fake_group();
  user = malloc(sizeof(wzd_user_t));
  memset(user, 0, sizeof(wzd_user_t));

  strcpy(user->username,"test_user");
  user->uid = 666;
  strcpy(user->flags,"5"); /* 5 = color */
  strcpy(user->rootpath, "/tmp");

  user->groups[0] = f_group->gid;
  user->group_num = 1;

  f_user = user;
}

void fake_group(void)
{
  wzd_group_t * group;

  if (!mainConfig) fake_mainConfig();
  group = malloc(sizeof(wzd_group_t));
  memset(group, 0, sizeof(wzd_group_t));

  strcpy(group->groupname,"test_group");
  group->gid = 333;

  f_group = group;
}

void fake_context(void)
{
  wzd_context_t * context;

  if (!mainConfig) fake_mainConfig();
  if (!f_user) fake_user();
  if (!f_group) fake_group();

  wzd_debug_init();

  user_register(f_user,f_user->uid);
  group_register(f_group,f_group->gid);

  context = malloc(sizeof(wzd_context_t));
  memset(context, 0, sizeof(wzd_context_t));

  context->magic = CONTEXT_MAGIC;
  context->userid = f_user->uid;
  context->write_fct = (write_fct_t)fake_write_function;
  context->thread_id = pthread_self();

  strcpy(context->currentpath, "/");

  f_context = context;

  context_list = malloc(sizeof(List));
  list_init(context_list,NULL);

  list_ins_next(context_list, list_tail(context_list), f_context);
}

void fake_exit(void)
{
  if (f_context) {
    list_destroy(context_list);
    free(context_list);
    free(f_context);
    user_free_registry();
    group_free_registry();
    f_context = NULL;

    wzd_debug_fini();
  }
  free(f_user); f_user = NULL;
  free(f_group); f_group = NULL;
  user_free_registry();
  group_free_registry();
  if (mainConfig) {
    free(mainConfig);
    mainConfig = NULL;
  }
}

void fake_write_function(fd_t fd, const char * msg, size_t msg_len, unsigned int timeout, wzd_context_t * context)
{
/*  printf("client out: [%s]\n",msg);*/
}

static int proto_handler(const char *command, const char * args)
{
  printf("proto out: [%s] [%s]\n",command,args);
  return EVENT_NEXT;
}

void fake_proto(void)
{
  if (!mainConfig) fake_mainConfig();
  hook_add_protocol("perl:",5,proto_handler);
}
