#ifndef __WZD_LOG__
#define __WZD_LOG__

/* colors */

#define CLR_BOLD	"[1m"

#define	CLR_BLUE	"[34m"
#define	CLR_CYAN	"[36m"
#define	CLR_GREEN	"[32m"
#define	CLR_RED		"[31m"

#define	CLR_NOCOLOR	"[0m"


/* DEBUG & LOG */
#define LEVEL_LOWEST	0
#define	LEVEL_FLOOD	1
#define	LEVEL_INFO	3
#define	LEVEL_NORMAL	5
#define	LEVEL_HIGH	7
#define	LEVEL_CRITICAL	9


void out_log(int level,const char *fmt,...);
void out_err(int level, const char *fmt,...);
void out_xferlog(wzd_context_t * context, int is_complete);

void log_message(const char *event, const char *fmt, ...);

#endif /* __WZD_LOG__ */
