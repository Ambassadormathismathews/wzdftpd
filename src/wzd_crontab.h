/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2003  Pierre Chifflier
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

struct wzd_cronjob_t;
typedef struct wzd_cronjob_t wzd_cronjob_t;

int cronjob_add(wzd_cronjob_t ** crontab, int (*fn)(void), const char * command,
    char * minutes, char * hours, char * day_of_month,
    char * month, char * day_of_week);

void cronjob_free(wzd_cronjob_t ** crontab);

int cronjob_run(wzd_cronjob_t ** crontab);

#endif /* __WZD_CRONTAB__ */
