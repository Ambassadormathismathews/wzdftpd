#include <stdlib.h>
#include <string.h>

#include <time.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_crontab.h>

#define C1 0x12345678
#define C2 0x9abcdef0

typedef struct {
  const char * desc;
  const char * minutes;
  const char * hours;
  const char * day_of_month;
  const char * month;
  const char * day_of_week;
} wzd_test_struct_t;

static int test_callback(void)
{
  fprintf(stdout,"crontab: test callback\n");
  return 0;
}

time_t _find_next_exec(time_t now, wzd_test_struct_t test)
{
  time_t next;
  struct tm * ltm;
  int num_minutes, num_hours, num_day_of_month, num_month;

  ltm = localtime(&now);
  if (!ltm) {
    fprintf(stderr,"Could not call localtime(%lu)\n",now);
    return -1;
  }

  if (test.minutes[0]!='*')
    num_minutes=strtol(test.minutes,NULL,10);
  else
    num_minutes = -1;
  if (test.hours[0]!='*')
    num_hours=strtol(test.hours,NULL,10);
  else
    num_hours = -1;
  if (test.day_of_month[0]!='*')
    num_day_of_month=strtol(test.day_of_month,NULL,10);
  else
    num_day_of_month = -1;
  if (test.month[0]!='*') {
    num_month=strtol(test.month,NULL,10);
    num_month--; /* ltm->tm_mon is in [0,11] */
  }
  else
    num_month = -1;

  if (num_month != -1)
  {
    ltm->tm_sec=0;
    if (num_minutes>0) ltm->tm_min = num_minutes;
    else ltm->tm_min = 0;
    if (num_hours>0) ltm->tm_hour = num_hours;
    else ltm->tm_hour = 0;
    if (num_day_of_month>0) ltm->tm_mday = num_day_of_month;
    else ltm->tm_mday = 0;
    if (num_month <= ltm->tm_mon) ltm->tm_year++;
    ltm->tm_mon = num_month;
  } else
  if (num_day_of_month != -1)
  {
    ltm->tm_sec=0;
    if (num_minutes>0) ltm->tm_min = num_minutes;
    else ltm->tm_min = 0;
    if (num_hours>0) ltm->tm_hour = num_hours;
    else ltm->tm_hour = 0;
    if (num_day_of_month <= ltm->tm_mday) ltm->tm_mon++;
    ltm->tm_mday = num_day_of_month;
  } else
  if (num_hours != -1)
  {
    ltm->tm_sec=0;
    if (num_minutes>0) ltm->tm_min = num_minutes;
    else ltm->tm_min = 0;
    if (num_hours <= ltm->tm_hour) ltm->tm_mday++;
    ltm->tm_hour = num_hours;
  } else
  if (num_minutes != -1) {
    ltm->tm_sec = 0;
    if (num_minutes <= ltm->tm_min) ltm->tm_hour++;
    ltm->tm_min = num_minutes;
  } else
  {
    /* every minute */
    ltm->tm_min++;

  }

  next = mktime(ltm);

  fprintf(stdout,"Next exec for '%s' will be at: %s\n",test.desc,ctime(&next));

  return next;
}

int main(int argc, char *argv[])
{
  unsigned long c1 = C1;
  time_t now;
  wzd_cronjob_t * crontab = NULL;
  int ret;
  long diff;
  wzd_test_struct_t tests[] = {
    { "every minute", "*", "*", "*", "*", "*" },
    { "every hour",   "0", "*", "*", "*", "*" },
    { "every day of month",   "0", "15", "*", "*", "*" },
    { "every month",   "0", "15", "4", "*", "*" },
    { "every month (2)",   "12", "*", "4", "*", "*" },
    { "every month (3)",   "*", "*", "*", "6", "*" },
    { "every day of week",   "*", "*", "*", "*", "2" },
    { NULL, NULL, NULL, NULL, NULL, NULL }
  };
  int i;
  unsigned long c2 = C2;

  for (i=0; tests[i].desc != 0; i++) {
    cronjob_free(&crontab);

    ret = cronjob_add(&crontab, test_callback, "fn:test_callback",
        tests[i].minutes, tests[i].hours, tests[i].day_of_month,
        tests[i].month, tests[i].day_of_week);

    now = time(NULL);

    /* hack cron job to make it run now */
    crontab->next_run = now;

    ret = cronjob_run(&crontab);

#if 0
    fprintf(stdout,"now:  %lu\n",now);
    fprintf(stdout,"next: %lu\n",crontab->next_run);
    fprintf(stdout,"diff: %lu\n",crontab->next_run - now);
#endif

    now = _find_next_exec(now,tests[i]);


    diff =  abs((long)crontab->next_run - (long)now);

    /* allow 1s difference */
    if (diff > 1) {
      fprintf(stderr,"crontab: next run was badly calculated for job '%s'\n",tests[i].desc);
      fprintf(stderr,"  found offset is %ld\n",(long)diff);
      return 1;
    }
  } /* next test */

  cronjob_free(&crontab);

  if (c1 != C1) {
    fprintf(stderr, "c1 nuked !\n");
    return -1;
  }
  if (c2 != C2) {
    fprintf(stderr, "c2 nuked !\n");
    return -1;
  }

  return 0;
}
