#ifndef __WZD_TLS__
#define __WZD_TLS__

#if SSL_SUPPORT

int tls_init(void);
int tls_exit(void);
int tls_auth (const char *type, wzd_context_t * context);
int tls_auth_cont(wzd_context_t * context);
int tls_init_datamode(int sock, wzd_context_t * context);
int tls_close_data(wzd_context_t * context);

int tls_auth_data_cont(wzd_context_t * context);

int tls_read(int sock, char *msg, unsigned int length, int flags, int timeout, wzd_context_t * context);
int tls_write(int sock, const char *msg, unsigned int length, int flags, int timeout, wzd_context_t * context);

#endif

#endif /* __WZD_TLS__ */
