#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_string.h>

#include <libwzd-core/wzd_fs.h>

#define C1 0x12345678
#define C2 0x9abcdef0

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  fs_dir_t * dir;
  fs_fileinfo_t * fileinfo;
  int err;
  const char * test_dirname = "_T_fs_mkdir";
  unsigned long c2 = C2;

  struct stat s;
  int ret;

  if (stat(".",&s) < 0) {
    fprintf(stderr,"FATAL: could not stat() current directory\n");
    return 1;
  }

  /** fs_mkdir **/
  ret = fs_mkdir(test_dirname, 0755, &err);
  if (ret < 0) {
    fprintf(stderr,"WARNING: could not create test directory %s\n", test_dirname);
    fprintf(stderr,"  errno is %d %s\n", errno, strerror(errno));
  } else {
    ret = rmdir(test_dirname);
    if (ret < 0) {
      fprintf(stderr,"WARNING: could not remove test directory %s\n", test_dirname);
      fprintf(stderr,"  errno is %d %s\n", errno, strerror(errno));
    }
  }

  /** fs_dir_open current directory **/
  ret = fs_dir_open(".", &dir);
  if (ret < 0) {
    fprintf(stderr,"FATAL: could not fs_dir_open() current directory\n");
    return 1;
  }

  /** \todo XXX '.' does not appear in the list ?! */
  while ( fs_dir_read(dir, &fileinfo) >= 0 ) {
    printf(" +--> %s\n", fs_fileinfo_getname(fileinfo));
  }



  fs_dir_close(dir);

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
