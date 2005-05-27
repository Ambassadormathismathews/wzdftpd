/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2004  Pierre Chifflier
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, Pierre Chifflier
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

#include "wzd_all.h"

#ifndef WZD_USE_PCH
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <string.h>

#include "wzd_structs.h"
#include "wzd_log.h"
#include "wzd_mod.h"
#include "wzd_crontab.h"

#include "wzd_debug.h"
#endif /* WZD_USE_PCH */

static int _crontab_insert_sorted(wzd_cronjob_t * job, wzd_cronjob_t ** crontab)
{
  wzd_cronjob_t * current;

  WZD_ASSERT( job != NULL );
  WZD_ASSERT( crontab != NULL );

  current = *crontab;

  /* case: list empty, or head insertion */
  if (!current || job->next_run < current->next_run) {
    *crontab = job;
    job->next_cronjob = current;
#ifdef WZD_DBG_CRONTAB
  out_err(LEVEL_HIGH,"cronjob: head insertion for %s\n",job->hook->external_command);
#endif
    return 0;
  }

  while (current->next_cronjob && job->next_run > current->next_cronjob->next_run) {
    current = current->next_cronjob;
  }

#ifdef WZD_DBG_CRONTAB
  out_err(LEVEL_HIGH,"cronjob: inserting %s after %s\n",job->hook->external_command, current->hook->external_command);
#endif
  job->next_cronjob = current->next_cronjob;
  current->next_cronjob = job;

  return 0;
}

static time_t cronjob_find_next_exec_date(time_t start,
    char * minutes, char * hours, char * day_of_month,
    char * month, char * day_of_week)
{
  time_t t = start;
  struct tm * ltm;
  int num_minutes, num_hours, num_day_of_month, num_month;

  if (minutes[0]!='*')
    num_minutes=strtol(minutes,NULL,10);
  else
    num_minutes = -1;
  if (hours[0]!='*')
    num_hours=strtol(hours,NULL,10);
  else
    num_hours = -1;
  if (day_of_month[0]!='*')
    num_day_of_month=strtol(day_of_month,NULL,10);
  else
    num_day_of_month = -1;
  if (month[0]!='*') {
    num_month=strtol(month,NULL,10);
    num_month--; /* ltm->tm_mon is in [0,11] */
  } else
    num_month = -1;

  ltm = localtime(&t);

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
  }

  /* here month = '*' */

  else if (num_day_of_month != -1)
  {
    ltm->tm_sec=0;
    if (num_minutes>0) ltm->tm_min = num_minutes;
    else ltm->tm_min = 0;
    if (num_hours>0) ltm->tm_hour = num_hours;
    else ltm->tm_hour = 0;
    if (num_day_of_month <= ltm->tm_mday) ltm->tm_mon++;
    ltm->tm_mday = num_day_of_month;
  }

  /* here month = '*' and day = '*' */

  else if (num_hours != -1)
  {
    ltm->tm_sec=0;
    if (num_minutes>0) ltm->tm_min = num_minutes;
    else ltm->tm_min = 0;
    if (num_hours <= ltm->tm_hour) ltm->tm_mday++;
    ltm->tm_hour = num_hours;
  }

  /* here month = '*' and day = '*' and hour = '*' */

  else if (num_minutes != -1)
  {
    ltm->tm_sec=0;
    if (num_minutes <= ltm->tm_min) ltm->tm_hour++;
    ltm->tm_min = num_minutes;
  }
  else {
    /* all is '*' */
    ltm->tm_min++;
  }

#if 0
  if (ltm->tm_min > 59)
{
  ltm->tm_min=0;
    ltm->tm_hour++;
  }
  if (ltm->tm_hour > 23)
  {
    ltm->tm_hour = 0;
    ltm->tm_mday++;
  }
  if (ltm->tm_mday > 31)
  {
    ltm->tm_mday = 1;
    ltm->tm_mon++;
  }
  if (ltm->tm_mon > 11)
  {
    ltm->tm_mon = 0;
    ltm->tm_year++;
  }
#endif

  t = mktime(ltm);
  return t;
}

int cronjob_add(wzd_cronjob_t ** crontab, int (*fn)(void), const char * command,
    char * minutes, char * hours, char * day_of_month,
    char * month, char * day_of_week)
{
  wzd_cronjob_t *new;
  time_t now;

  if (!fn && !command) return 1;
/*  if (fn && command) return 1;*/ /* why ?! This forbis to provide a description of functions */

#ifdef WZD_DBG_CRONTAB
  out_err(LEVEL_HIGH,"adding job %s\n",command);
#endif

  new = malloc(sizeof(wzd_cronjob_t));
  new->hook = malloc(sizeof(struct _wzd_hook_t));
  new->hook->mask = EVENT_CRONTAB;
  new->hook->opt = NULL;
  new->hook->hook = fn;
  new->hook->external_command = command?strdup(command):NULL;
  new->hook->next_hook = NULL;
  strncpy(new->minutes,minutes,32);
  strncpy(new->hours,hours,32);
  strncpy(new->day_of_month,day_of_month,32);
  strncpy(new->month,month,32);
  strncpy(new->day_of_week,day_of_week,32);
  (void)time(&now);
  new->next_run = cronjob_find_next_exec_date(now,minutes,hours,day_of_month,
      month,day_of_week);
  new->next_cronjob = NULL;

#ifdef WZD_DBG_CRONTAB
  out_err(LEVEL_CRITICAL,"Now: %s",ctime(&now));
  out_err(LEVEL_CRITICAL,"Next run: %s",ctime(&new->next_run));
#endif

  return _crontab_insert_sorted(new,crontab);
}

int cronjob_run(wzd_cronjob_t ** crontab)
{
  wzd_cronjob_t * job = *crontab;
  time_t now;
  int ret;

  /** list is sorted, so we only need to check the first entries */
  (void)time(&now);
  while (job && now >= job->next_run )
  {
    /* run job */
    typedef int (*cronjob_hook)(unsigned long, const char *, const char*);
    if (job->hook->hook)
      ret = (*(cronjob_hook)job->hook->hook)(EVENT_CRONTAB,NULL,job->hook->opt);
    else {
      if (job->hook->external_command)
        ret = hook_call_external(job->hook,-1);
    }
    /* mark job as done, its position must be changed in list */
    job->next_run = 0;
#ifdef WZD_DBG_CRONTAB
    out_err(LEVEL_CRITICAL,"Exec'ed %s\n",job->hook->external_command);
    out_err(LEVEL_CRITICAL,"Now: %s",ctime(&now));
#endif
    job = job->next_cronjob;
  }

  while ( (*crontab)->next_run == 0 ) {
    job = *crontab;
    *crontab = job->next_cronjob;
    job->next_run = cronjob_find_next_exec_date(now,job->minutes,job->hours,
        job->day_of_month, job->month, job->day_of_week);
#ifdef WZD_BUILD_OPTS
    out_err(LEVEL_CRITICAL,"Next run (%s): %s",job->hook->external_command,ctime(&job->next_run));
#endif
    _crontab_insert_sorted(job,crontab);
  }

  return 0;
}

void cronjob_free(wzd_cronjob_t ** crontab)
{
  wzd_cronjob_t * current_job, * next_job;

  current_job = *crontab;

  while (current_job) {
    next_job = current_job->next_cronjob;

    if (current_job->hook->external_command)
      free(current_job->hook->external_command);
    if (current_job->hook)
      free(current_job->hook);
#ifdef DEBUG
    current_job->hook = NULL;
    current_job->next_cronjob = NULL;
#endif /* DEBUG */
    free(current_job);

    current_job = next_job;
  }
  *crontab = NULL;
}

