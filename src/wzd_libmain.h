#ifndef __WZD_LIBMAIN__
#define __WZD_LIBMAIN__

wzd_config_t * getlib_mainConfig(void);
void setlib_mainConfig(wzd_config_t *);

wzd_context_t * getlib_contextList(void);
void setlib_contextList(wzd_context_t *);

void libtest(void);

#endif /* __WZD_LIBMAIN__ */
