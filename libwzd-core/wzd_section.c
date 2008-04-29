/* vi:ai:et:ts=8 sw=2
 */
/*
 * wzdftpd - a modular and cool ftp server
 * Copyright (C) 2002-2008  Pierre Chifflier
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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef WIN32
#include <winsock2.h>
#include "../gnu_regex/regex.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>	/* struct in_addr (wzd_misc.h) */

#include <regex.h>
#endif

#include <sys/stat.h>
#include <string.h>	/* strdup */

#include "wzd_structs.h"

#include "wzd_section.h"
#include "wzd_misc.h"
#include "wzd_log.h"

#else /* WZD_USE_PCH */
#ifdef _MSC_VER
#include "../gnu_regex/regex.h"
#else
#include <regex.h>
#endif
#endif /* WZD_USE_PCH */


char * section_getname(wzd_section_t * section)
{
  if (section) return section->sectionname;
  return NULL;
}

int section_add(wzd_section_t **section_list, const char *name, const char *mask, const char *filter)
{
  wzd_section_t * section_new, * section;
  int err;

  if (!section_list || !name || !mask) return -1;

  section_new = malloc(sizeof(wzd_section_t));
  if (filter)
  {
    section_new->pathfilter = malloc(sizeof(regex_t));
    err = regcomp(section_new->pathfilter,filter,REG_EXTENDED | REG_NOSUB);
    if (err) {
      char buf[512];
      (void)regerror(err,section_new->pathfilter,buf,512);
      out_err(LEVEL_HIGH,"Error compiling regexp: %s\n",buf);
      free(section_new->pathfilter);
      free(section_new);
      return -1;
    }
  }
  else
    section_new->pathfilter = NULL;
  section_new->sectionname = strdup(name);
  section_new->sectionmask = strdup(mask);
  section_new->sectionre = strdup(filter);
  section_new->next_section = NULL;

  section = *section_list;

  /* head insertion ? */
  if (!section) {
    *section_list = section_new;
    return 0;
  }

  do {
    /* do not insert if a section with same name exists */
    if (strcmp((const char *)name,section->sectionname)==0) return 1;
    /* FIXME if a section with same or bigger mask exist, warn user ? */
    if (!section->next_section) break;
    section = section->next_section;
  }
  while ( section );

  section->next_section = section_new;

  return 0;
}

int section_free(wzd_section_t **section_list)
{
  wzd_section_t * section, * section_next;

  if (!section_list) return 0;
  section = *section_list;

  while (section)
  {
    section_next = section->next_section;
    free(section->sectionname);
    free(section->sectionmask);
    if (section->pathfilter)
    { regfree(section->pathfilter); free(section->pathfilter); }
    if (section->sectionre)
    { free(section->sectionre); }
    free(section);
    section = section_next;
  }
  *section_list = NULL;

  return 0;
}

/** \return 1 if in section, else 0 */
int section_check(wzd_section_t * section, const char *path)
{
  /* TODO we can restrict sections to users/groups, etc */
  if (my_str_compare(path, section->sectionmask)) return 1;
  return 0;
}

/* \return 1 if in path matches filter or section has no filter, else 0 */
int section_check_filter(wzd_section_t * section, const char *path)
{
  if (!section->pathfilter || !regexec(section->pathfilter,path,0,NULL,0))
    return 1;
  return 0;
}

/** \return a pointer to the first matching section or NULL */
wzd_section_t * section_find(wzd_section_t *section_list, const char *path)
{
  wzd_section_t * section;

  if (!section_list) return NULL;
  section=section_list;

  while (section)
  {
    if (my_str_compare(path,section->sectionmask)) return section;
    section = section->next_section;
  }
  return NULL;
}
