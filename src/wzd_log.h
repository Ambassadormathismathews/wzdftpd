#ifndef __WZD_LOG__
#define __WZD_LOG__

#include <stdarg.h>

void out_log(int level,const char *fmt,...);

void interpret_wsa_error(void);

#endif /* __WZD_LOG__ */