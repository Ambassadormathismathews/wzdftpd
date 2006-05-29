#ifndef __LIBWZD_SFV_MAIN_H__
#define __LIBWZD_SFV_MAIN_H__

typedef struct {
  char progressmeter[256];
  char del_progressmeter[256];
  char incomplete_indicator[256];
  char other_completebar[256];
  BOOL incomplete_symlink;
} wzd_sfv_config;

typedef struct {
  unsigned int files_total;
  unsigned int files_ok;
  double size_total;
} wzd_release_stats;

wzd_sfv_config SfvConfig; /*Our main SFV config */
char * create_filepath(const char *dir, const char * file);


#endif /* __LIBWZD_SFV_MAIN_H__ */
