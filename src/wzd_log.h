#ifndef __WZD_LOG__
#define __WZD_LOG__

void out_log(int level,const char *fmt,...);
void out_err(int level, const char *fmt,...);
void out_xferlog(wzd_context_t * context);

#endif /* __WZD_LOG__ */
