#include <wzd.h>

/***** EVENT HOOKS *****/
int my_event_hook(unsigned long event_id, const char *p1, const char *p2);

/***********************/
/* WZD_MODULE_INIT     */

int WZD_MODULE_INIT(void)
{
  printf("WZD_MODULE_INIT\n");
  out_log(LEVEL_INFO,"max threads: %d\n",getlib_mainConfig()->max_threads);
  return 0;
}

int my_event_hook(unsigned long event_id, const char *p1, const char *p2)
{
  fprintf(stderr,"*** ID: %lx, %s %s\n",event_id,
      (p1)?p1:"(NULL)",(p2)?p2:"(NULL)");
  return 0;
}

void moduletest(void)
{
  fprintf(stderr,"mainConfig: %lx\n",(unsigned long)getlib_mainConfig()->logfile);
  libtest();
  out_log(LEVEL_INFO,"max threads: %d\n",getlib_mainConfig()->max_threads);
}
