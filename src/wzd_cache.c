#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>

struct wzd_cache_t  {
  int fd;
};

struct wzd_cache_t * wzd_cache_open(const char *file, int flags, unsigned int mode)
{
  struct wzd_cache_t * cache;
  int fd;

  fd = open(file,flags,mode);
  if (fd==-1) return NULL;

  cache = (struct wzd_cache_t*)malloc(sizeof(struct wzd_cache_t));
  cache->fd = fd;
  
  return cache;
}

int wzd_cache_read(struct wzd_cache_t * c, void *buf, unsigned int count)
{
  if (c) return read( c->fd, buf, count );
  return -1;
}

int wzd_cache_write(struct wzd_cache_t * c, void *buf, unsigned int count)
{
  if (c) return write( c->fd, buf, count );
  return -1;
}

char * wzd_cache_gets(struct wzd_cache_t * c, char *buf, unsigned int size)
{
  off_t position;
  int fd = c->fd;
  char buffer[4096], *ptr, *dst;
  char _c;
  int ret;
  unsigned int size_to_read;

  if (!c) return NULL;
  
  /* get start position */
  position = lseek(fd,0,SEEK_CUR);

  /* read buffer */
  ptr = buffer;
  dst = buf;
  size_to_read = (size<4096)?size:4096;
  ret = read(fd,buffer,size_to_read);
  if (ret <= 0) return NULL;
  while (--size>0 && (_c=(*ptr++)) != EOF)
  {
    if ( (*dst++ = _c)=='\n' )
      break;
    if ( --size_to_read == 0 ) {
      size_to_read = (size<4096)?size:4096;
      ret = read(fd,buffer,size_to_read);
      ptr = buffer;
      if (ret < 0) return NULL;
    }
  }
  *dst=0;
  if (_c==EOF && ptr==buf) return NULL;
  lseek(fd,position + (dst-buf), SEEK_SET );
  return buf;
}

void wzd_cache_close(struct wzd_cache_t * c)
{
  if (c) close( c->fd );
}

