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

#include <string.h>

#include "wzd_structs.h"

#include "wzd_misc.h"

#include "wzd_vars.h"
#include "wzd_log.h"

int vars_get(const char *varname, void *data, unsigned int datalength, wzd_config_t * config)
{
  if (!config) return 1;

  if (strcasecmp(varname,"bw")==0) {
    snprintf(data,datalength,"%lu",get_bandwidth());
    return 0;
  }
  if (strcmp(varname,"loglevel")==0) {
    snprintf(data,datalength,"%s",loglevel2str(config->loglevel));
    return 0;
  }
  if (strcasecmp(varname,"max_dl")==0) {
    snprintf(data,datalength,"%d",config->global_dl_limiter.maxspeed);
    return 0;
  }
  if (strcasecmp(varname,"max_threads")==0) {
    snprintf(data,datalength,"%d",config->max_threads);
    return 0;
  }
  if (strcasecmp(varname,"max_ul")==0) {
    snprintf(data,datalength,"%d",config->global_ul_limiter.maxspeed);
    return 0;
  }
  if (strcasecmp(varname,"pasv_low")==0) {
    snprintf(data,datalength,"%d",config->pasv_low_range);
    return 0;
  }
  if (strcasecmp(varname,"pasv_high")==0) {
    snprintf(data,datalength,"%d",config->pasv_high_range);
    return 0;
  }
  if (strcasecmp(varname,"port")==0) {
    snprintf(data,datalength,"%d",config->port);
    return 0;
  }
  if (strcmp(varname,"uptime")==0) {
    time_t t;

    time(&t);
    t = t - config->server_start;
    snprintf(data,datalength,"%ld",t);
    return 0;
  }

  return 1;
}

int vars_set(const char *varname, void *data, unsigned int datalength, wzd_config_t * config)
{
  int i;
  unsigned long ul;

  if (!data || !config) return 1;

  if (strcasecmp(varname,"deny_access_files_uploaded")==0) {
    i = strtoul(data,NULL,0);
    if (i==1) { CFG_SET_OPTION(config,CFG_OPT_DENY_ACCESS_FILES_UPLOADED); return 0; }
    if (i==0) { CFG_CLEAR_OPTION(config,CFG_OPT_DENY_ACCESS_FILES_UPLOADED); return 0; }
    return 1;
  }
  if (strcasecmp(varname,"hide_dotted_files")==0) {
    i = strtoul(data,NULL,0);
    if (i==1) { CFG_SET_OPTION(config,CFG_OPT_HIDE_DOTTED_FILES); return 0; }
    if (i==0) { CFG_CLEAR_OPTION(config,CFG_OPT_HIDE_DOTTED_FILES); return 0; }
    return 1;
  }
  if (strcasecmp(varname,"loglevel")==0) {
    i = str2loglevel(data);
    if (i==-1) {
      return 1;
    }
    config->loglevel = i;
    return 0;
  }
  return 1;
}
