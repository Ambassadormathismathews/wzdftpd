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

#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*#include <wzd.h>*/
#include <wzd_structs.h>
#include <wzd_log.h>
#include <wzd_misc.h>
#include <wzd_libmain.h>
#include <wzd_mod.h> /* essential to define WZD_MODULE_INIT */

/***** EVENT HOOKS *****/
static int my_event_hook(unsigned long event_id, wzd_context_t * context, const char *p1, const char *p2);

/***********************/
/* WZD_MODULE_INIT     */

int WZD_MODULE_INIT(void)
{
  printf("WZD_MODULE_INIT\n");
  out_log(LEVEL_INFO,"max threads: %d\n",getlib_mainConfig()->max_threads);
  return 0;
}

static int my_event_hook(unsigned long event_id, wzd_context_t * context, const char *token, const char *args)
{
  fprintf(stderr,"*** ID: %lx, [%s] [%s]\n",event_id,
      (token)?token:"(NULL)",(args)?args:"(NULL)");
  return 0;
}

void moduletest(void)
{
  fprintf(stderr,"mainConfig: %lx\n",(unsigned long)getlib_mainConfig()->logfile);
  libtest();
  out_log(LEVEL_INFO,"max threads: %d\n",getlib_mainConfig()->max_threads);
}
