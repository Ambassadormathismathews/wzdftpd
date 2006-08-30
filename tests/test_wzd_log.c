#include <stdio.h>
#include <string.h> /* memset */
#include <stdlib.h> /* mktemp */

#include <fcntl.h> /* O_RDONLY */

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>

#include <libwzd-core/wzd_debug.h>

#define C1 0x12345678
#define C2 0x9abcdef0

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  int ret;
  char template[] = "/tmp/wzd-XXXXXX";
  int fd;
  unsigned long c2 = C2;

  wzd_debug_init();

  ret = log_init();
  if (ret != 0) { fprintf(stderr,"log_init() failed\n"); return 2; }

  log_get(MAX_LOG_CHANNELS+1);
  log_get(0);

  /* only generate a temporary name, we will create the file */
  ret = mkstemp(template);
  if (ret == -1) {
    fprintf(stderr,"Could not obtain a temp file using mkstemp(), aborting test\n");
    return -1;
  }
  close(ret);
  unlink(template);

  fd = log_open(template,O_CREAT|O_EXCL|O_RDWR);
  if (fd < 0) { fprintf(stderr,"log_open(%s) failed\n",template); return 3; }

  if (log_set(RESERVED_LOG_CHANNELS+1,fd)!=0) {
    fprintf(stderr,"log_set(%d,%d) failed\n",RESERVED_LOG_CHANNELS+1,fd);
    log_close(fd);
    unlink(template);
    return 4;
  }

  ret = log_get(RESERVED_LOG_CHANNELS+1);
  if (ret != fd) {
    fprintf(stderr,"log_get(%d) == %d failed\n",RESERVED_LOG_CHANNELS+1,fd);
    log_close(fd);
    unlink(template);
    return 5;
  }

  out_log(RESERVED_LOG_CHANNELS+1,"test format %d %s\n",123,"hello");

  log_set(LEVEL_NORMAL,fd);
  log_message("DEBUG","test 2 format %d %s",123,"hello");





  log_close(fd);
  /*unlink(template);*/

  wzd_debug_fini();

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
