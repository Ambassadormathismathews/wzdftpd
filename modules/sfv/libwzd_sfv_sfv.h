#ifndef __LIBWZD_SFV_SFV_H__
#define __LIBWZD_SFV_SFV_H__

#define	SFV_OK		  0x0001
#define	SFV_MISSING	0x0002
#define	SFV_BAD     0x0004
#define	SFV_UNKNOWN	0x0008

typedef struct {
  char *        filename;
  unsigned long crc;
  unsigned int	state;
  u64_t	size;
} wzd_sfv_entry;

typedef struct {
  char **       comments;
  wzd_sfv_entry **sfv_list;
} wzd_sfv_file;

void sfv_init(wzd_sfv_file *sfv);
void sfv_free(wzd_sfv_file *sfv);
int sfv_find_sfv(const char * filename, wzd_sfv_file *sfv, wzd_sfv_entry ** entry);
int sfv_process_new(const char *sfv_file, wzd_context_t *context);
int sfv_process_default(const char *filename, wzd_context_t *context);
int sfv_read(const char *filename, wzd_sfv_file *sfv);


#endif /* __LIBWZD_SFV_H__ */
