#ifndef __WZD_SERVER_THREAD__
#define __WZD_SERVER_THREAD__

#ifndef __CYGWIN__
extern unsigned int wzd_server_uid;
#endif

extern wzd_sem_t limiter_sem;

int runMainThread(int argc, char **argv);

#endif /* __WZD_SERVER_THREAD__ */
