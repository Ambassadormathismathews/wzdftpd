#ifndef __WZD_CRONTAB__
#define __WZD_CRONTAB__

struct wzd_cronjob_t;
typedef struct wzd_cronjob_t wzd_cronjob_t;

int cronjob_add(wzd_cronjob_t ** crontab, int (*fn)(void), const char * command, unsigned int interval);

int cronjob_run(wzd_cronjob_t ** crontab);

#endif /* __WZD_CRONTAB__ */
