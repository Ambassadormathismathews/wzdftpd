#ifndef __WZD_CLIENT_THREAD__
#define __WZD_CLIENT_THREAD__

int clear_read(int sock, char *msg, unsigned int length, int flags, int timeout, wzd_context_t * context);
int clear_write(int sock, const char *msg, unsigned int length, int flags, int timeout, wzd_context_t * context);

void clientThreadProc(void *arg);

int send_message(int code, wzd_context_t * context);
int send_message_with_args(int code, wzd_context_t * context, ...);

#endif /* __WZD_CLIENT_THREAD__ */
