#ifndef __LIBWZD_SFV_ZIP_H__
#define __LIBWZD_SFV_ZIP_H__

/*Default unzip buffer */
#define UNZIP_BUFFER_SIZE 8192
#define UNZ_MAXFILENAMEINZIP 256

int sfv_process_diz(const char *diz_file, wzd_context_t *context);
int sfv_process_zip(const char *zip_file, wzd_context_t *context);

#endif /* __LIBWZD_SFV_ZIP_H__ */
