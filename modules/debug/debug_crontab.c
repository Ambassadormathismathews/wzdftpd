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

#ifndef WIN32
#include <unistd.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_messages.h>

#include <libwzd-core/wzd_crontab.h>

#include "debug_crontab.h"

static int _cron_find_and_execute(const char * jobname, wzd_cronjob_t * crontab);

int do_site_listcrontab(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int ret;
  char buffer[4096];
  wzd_cronjob_t * cronjob;
  time_t now;

  send_message_raw("200-\r\n",context);
  send_message_raw(" Name                              Min  Hour Day  Mon  DayOfWeek Next\r\n",context);

  WZD_MUTEX_LOCK(SET_MUTEX_CRONTAB);
  cronjob = getlib_mainConfig()->crontab;

  time(&now);

  while (cronjob != NULL) {

    snprintf(buffer,sizeof(buffer)," %-33s %-4s %-4s %-4s %-4s %-9s %-5ld\n",cronjob->hook->external_command,
        cronjob->minutes, cronjob->hours, cronjob->day_of_month, cronjob->month,
        cronjob->day_of_week, (long)(cronjob->next_run - now));
    ret = send_message_raw(buffer,context);

    cronjob = cronjob->next_cronjob;
  }

  ret = send_message_raw("200 command ok\r\n",context);

  WZD_MUTEX_UNLOCK(SET_MUTEX_CRONTAB);
  return 0;
}

int do_site_cronjob(wzd_string_t *name, wzd_string_t *param, wzd_context_t * context)
{
  int ret, status;
  char buffer[4096];
  wzd_string_t * commandname, * jobname = NULL;

  commandname = str_tok(param," \t\r\n");
  if (!commandname) {
    ret = send_message_with_args(501,context,"site cronjob exec jobname");
    return -1;
  }

  ret = -1;
  if (strcasecmp(str_tochar(commandname),"exec")==0) {
    jobname = str_read_token(param);

    if (jobname) {
      send_message_raw("200-\r\n",context);

      status = _cron_find_and_execute(str_tochar(jobname),getlib_mainConfig()->crontab);

      snprintf(buffer,sizeof(buffer)-1," cron job: %s\n",str_tochar(jobname));
      ret = send_message_raw(buffer,context);

      if (status == 0)
        ret = send_message_raw("200 command ok\r\n",context);
      else if (status == -1)
        ret = send_message_raw("200 command failed (no cron job with this name)\r\n",context);
      else
        ret = send_message_raw("200 command ok (with errors)\r\n",context);
      ret = 0;
    } else {
      ret = send_message_with_args(501,context,"site cronjob exec jobname");
      ret = -1;
    }
  } else {
    ret = send_message_with_args(501,context,"site cronjob exec jobname");
    ret = -1;
  }

  str_deallocate(jobname);
  str_deallocate(commandname);

  return ret;
}



static int _cron_find_and_execute(const char * jobname, wzd_cronjob_t * crontab)
{
  int status = -1;
  wzd_cronjob_t *job;
  time_t now;

  job = malloc(sizeof(wzd_cronjob_t));

  WZD_MUTEX_LOCK(SET_MUTEX_CRONTAB);
  while (crontab != NULL) {
    if (crontab->hook && crontab->hook->external_command &&
        strcmp(crontab->hook->external_command,jobname)==0) {
      memcpy(job, crontab, sizeof(wzd_cronjob_t));
      time(&now);
      job->next_run = now;
      job->next_cronjob = NULL;
      status = 0;
      break;
    }
    crontab = crontab->next_cronjob;
  }

  WZD_MUTEX_UNLOCK(SET_MUTEX_CRONTAB);

  if (status == 0) {
    cronjob_run(&job);
  }

  free(job);

  return status;
}

