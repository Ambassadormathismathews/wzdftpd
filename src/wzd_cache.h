#ifndef __WZD_CACHE__
#define __WZD_CACHE__

struct wzd_cache_t;
typedef struct wzd_cache_t wzd_cache_t;

wzd_cache_t* wzd_cache_open(const char *file, int flags, unsigned int mode);

int wzd_cache_read(wzd_cache_t * c, void *buf, unsigned int count);
int wzd_cache_write(wzd_cache_t * c, void *buf, unsigned int count);

char * wzd_cache_gets(wzd_cache_t * c, char *buf, unsigned int size);

void wzd_cache_close(wzd_cache_t * c);

#endif /* __WZD_CACHE__ */

