#ifndef __WZD_CLIENT_THREAD__
#define __WZD_CLIENT_THREAD__

int clear_read(int sock, char *msg, unsigned int length, int flags, int timeout, void * vcontext);
int clear_write(int sock, const char *msg, unsigned int length, int flags, int timeout, void * vcontext);

void clientThreadProc(void *arg);

void client_die(wzd_context_t * context);

#endif /* __WZD_CLIENT_THREAD__ */
