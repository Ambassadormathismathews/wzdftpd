#ifndef __WZD_CLIENT_THREAD__
#define __WZD_CLIENT_THREAD__

int clear_read(int sock, char *msg, unsigned int length, int flags, int timeout, void * vcontext);
int clear_write(int sock, const char *msg, unsigned int length, int flags, int timeout, void * vcontext);

void clientThreadProc(void *arg);

int send_message(int code, wzd_context_t * context);
int send_message_with_args(int code, wzd_context_t * context, ...);
int send_message_raw(const char *msg, wzd_context_t * context);

int checkpath(const char *wanted_path, char *path, wzd_context_t *context);

void client_die(wzd_context_t * context);

#endif /* __WZD_CLIENT_THREAD__ */
