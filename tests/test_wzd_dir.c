#include <stdio.h>
#include <string.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_dir.h>
#include <libwzd-core/wzd_file.h>

#include <libwzd-core/wzd_debug.h>

#include "test_common.h"

#define C1 0x12345678
#define C2 0x9abcdef0

struct test_path_t {
  char * indir;
  char * outdir;
};

struct test_name_t {
  char * indir;
  char * outdir;
  unsigned int n;
};

struct test_basename_t {
  char * indir;
  char * outdir;
  char * suffix;
};

int create_fake_dirinfo(const char * dir);
int remove_fake_dirinfo(const char * dir);

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  char buffer[2048];
  struct wzd_dir_t * dir;
  struct wzd_file_t * file;
  char * ptr;
  unsigned long c2 = C2;
  struct test_path_t test_path[] = {
    { "",  "/" },
    { "/",  "/" },
    { "/aaa",  "/aaa" },
    { "//",  "/" },
    { "/./a",  "/a" },
    { "/../a",  "/a" },
    { "/..",  "/" },
    { NULL, NULL } };
  struct test_name_t test_trailingname[] = {
    { "",  "", 1 },
    { "/",  "/", 1 },
    { "toto",  "toto", 1 },
    { "/toto",  "toto", 1 },
    { "/test/toto",  "toto", 1 },
    { "/1234/test/toto",  "test/toto", 2 },
    { NULL, NULL, 0 } };
  struct test_basename_t test_basename[] = {
    { "", "", NULL },
    { "/", "/", NULL },
    { "/toto", "toto", NULL },
    { "/test/toto", "toto", NULL },
    { "/test/toto.txt", "toto", ".txt" },
    { "/test/toto", "", "toto" },
    { "/test/toto", "toto", "totototo" },
    { "/test/toto", "toto", "1234" },
    { NULL, NULL, NULL } };
  struct test_path_t test_dirname[] = {
    { "/",  "/" },
    { "/toto",  "/" },
    { "/test/toto",  "/test" },
    { NULL, NULL } };
  unsigned int i;

  fake_context();

  /* create a file .dirindex with fake entries for vfs and symlinks */
  create_fake_dirinfo("./");

  /* dir_open */
  dir = dir_open("./",f_context);

  do {
    file = dir_read(dir, f_context);
    if (file) {
      const char * type;
      switch (file->kind) {
        case FILE_NOTSET:
          type = "unknown (not set)";
          break;
        case FILE_REG:
          type = "regular file";
          break;
        case FILE_DIR:
          type = "directory";
          break;
        case FILE_LNK:
          type = "symbolic link";
          break;
        case FILE_VFS:
          type = "virtual filesystem";
          break;
        default:
          type = "unknown";
          break;
      };
      fprintf(stdout,"  %s: [%s]\n", type, file->filename);
    }
  } while (file != NULL);

  dir_close(dir);

  remove_fake_dirinfo("./");


  /* path_getdirname */
  i=0;
  while (test_dirname[i].indir != NULL) {
    strncpy(buffer,test_dirname[i].indir,sizeof(buffer));
    ptr = path_getdirname(buffer);
    if (strcmp(ptr,test_dirname[i].outdir) != 0) {
      fprintf(stderr, "path_getdirname(%s) failed !\n",test_dirname[i].indir);
      fprintf(stderr, " => [%s] instead of [%s]\n",ptr,test_dirname[i].outdir);
      wzd_free(ptr);
      return -2;
    }
    wzd_free(ptr);
    i++;
  }

  /* path_getbasename */
  i=0;
  while (test_basename[i].indir != NULL) {
    strncpy(buffer,test_basename[i].indir,sizeof(buffer));
    ptr = path_getbasename(buffer,test_basename[i].suffix);
    if (strcmp(ptr,test_basename[i].outdir) != 0) {
      fprintf(stderr, "path_getbasename(%s,%s) failed !\n",
          test_basename[i].indir,
          test_basename[i].suffix);
      fprintf(stderr, " => [%s] instead of [%s]\n",ptr,test_basename[i].outdir);
      wzd_free(ptr);
      return -2;
    }
    wzd_free(ptr);
    i++;
  }

  /* path_gettrailingname */
  i=0;
  while (test_trailingname[i].indir != NULL) {
    strncpy(buffer,test_trailingname[i].indir,sizeof(buffer));
    ptr = path_gettrailingname(buffer,test_trailingname[i].n);
    if (strcmp(ptr,test_trailingname[i].outdir) != 0) {
      fprintf(stderr, "path_gettrailingname(%s,%d) failed !\n",
          test_trailingname[i].indir,
          test_trailingname[i].n);
      fprintf(stderr, " => [%s] instead of [%s]\n",ptr,test_trailingname[i].outdir);
      wzd_free(ptr);
      return -2;
    }
    wzd_free(ptr);
    i++;
  }

  /* path_simplify */
  i=0;
  while (test_path[i].indir != NULL) {
    strncpy(buffer,test_path[i].indir,sizeof(buffer));
    ptr = path_simplify(buffer);
    if (strcmp(ptr,test_path[i].outdir) != 0) {
      fprintf(stderr, "path_simplify(%s) failed !\n",test_path[i].indir);
      fprintf(stderr, " => [%s] instead of [%s]\n",ptr,test_path[i].outdir);
      return -2;
    }
    i++;
  }

  fake_exit();


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

/* create a file .dirinfo with fake entries for vfs and symlinks */
int create_fake_dirinfo(const char * dir)
{
  char buffer[4096];
  FILE * file;

  snprintf(buffer,sizeof(buffer),"%s/%s",dir,".dirinfo");
  file = fopen(buffer,"w+");
  if (!file) {
    fprintf(stderr,"WARNING: could not create file %s\n", buffer);
    return -1;
  }

  /* TODO create some fake permissions on file */

  /* create some fake symlinks */
  fprintf(file,"link\t%s\t%s\t%s\t%s\t%lo\n","link1","/tmp","test_user","test_group",(long)0775);

  fclose(file);
  
  return 0;
}

int remove_fake_dirinfo(const char * dir)
{
  char buffer[4096];

  snprintf(buffer,sizeof(buffer),"%s/%s",dir,".dirinfo");

  remove(buffer);

  return 0;
}
