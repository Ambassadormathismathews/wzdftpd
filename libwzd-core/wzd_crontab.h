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

#ifndef __WZD_CRONTAB__
#define __WZD_CRONTAB__

typedef struct wzd_cronjob_t wzd_cronjob_t;
struct wzd_cronjob_t {
  struct _wzd_hook_t * hook;
  char minutes[32];
  char hours[32];
  char day_of_month[32];
  char month[32];
  char day_of_week[32];
  time_t next_run;
  wzd_cronjob_t * next_cronjob;
};


int cronjob_add(wzd_cronjob_t ** crontab, int (*fn)(void), const char * command,
    const char * minutes, const char * hours, const char * day_of_month,
    const char * month, const char * day_of_week);

/** \brief Add job to be run once, at a specified time
 * This is similar to the at (1) command
 */
int cronjob_add_once(wzd_cronjob_t ** crontab, int (*fn)(void), const char * command, time_t date);

void cronjob_free(wzd_cronjob_t ** crontab);

int cronjob_run(wzd_cronjob_t ** crontab);

/** \brief Start crontab thread */
int crontab_start(wzd_cronjob_t ** crontab);

/** \brief Stop crontab thread */
int crontab_stop(void);

#endif /* __WZD_CRONTAB__ */
