#include <stdlib.h>
#include <string.h>

#ifndef WIN32
# include <unistd.h>
#endif

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_threads.h>

#define C1 0x12345678
#define C2 0x9abcdef0

unsigned int global_var = 0;

void * thread_func(void * param)
{
  global_var++;
  printf("global_var: %u\n",global_var);

  return NULL;
}

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  wzd_thread_t thread;
  wzd_thread_attr_t thread_attr;
  int ret;
  unsigned long c2 = C2;

  ret = wzd_thread_attr_init( & thread_attr );
  if (ret) {
    fprintf(stderr, "wzd_thread_attr_init failed [%d]\n",ret);
    return -2;
  }

  if (wzd_thread_attr_set_detached( & thread_attr )) {
    fprintf(stderr, "wzd_thread_create failed [%d]\n",ret);
    return -3;
  }

  ret = wzd_thread_create(&thread,&thread_attr,thread_func,NULL);
  if (ret) {
    fprintf(stderr, "wzd_thread_create failed [%d]\n",ret);
    return -4;
  }

  wzd_thread_attr_destroy(&thread_attr);

  usleep(300);

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
