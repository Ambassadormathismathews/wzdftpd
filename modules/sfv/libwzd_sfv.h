#ifndef __LIBWZD_SFV_H__
#define __LIBWZD_SFV_H__

/************************** SFV ***************************/

/* values randomly chosen :) */ 
#define	SFV_UNKNOWN	0x0324
#define	SFV_OK		0x7040
#define	SFV_MISSING	0x0220
#define	SFV_BAD		0x1111

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

#endif /* __LIBWZD_SFV_H__ */
