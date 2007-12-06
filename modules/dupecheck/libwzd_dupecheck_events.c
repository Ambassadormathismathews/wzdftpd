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

#include <stdlib.h>
#include <string.h>

#include <libwzd-core/wzd_structs.h>
#include <libwzd-core/wzd_log.h>
#include <libwzd-core/wzd_misc.h>
#include <libwzd-core/wzd_events.h>
#include <libwzd-core/wzd_libmain.h>
#include <libwzd-core/wzd_mod.h> /* WZD_MODULE_INIT */
#include <libwzd-core/wzd_configfile.h>
#include <libwzd-core/wzd_file.h>

#include "dupelog.h"
#include "libwzd_dupecheck_events.h"

/***** EVENT HOOKS *****/
event_reply_t dupecheck_event_preupload(const char * args)
{
  int ret;

  char *filename, *path, *username;
  char *str = strdup(args), *ptr;

  username = strtok_r(str, " ", &ptr);
  // TODO: Make sure path is absolute!
  path = ptr;
  filename = strrchr(path, '/');

  if (filename == NULL)
  {
    // TODO: Make sure this is an absolute path,
    // so make path = getcwd() or something equally silly.
    filename = path;
    path = "./";
  }
  else
  {
    *filename = '\0';
    filename++;
  }

  ret = dupelog_is_upload_allowed(filename);
  if (ret != EVENT_DENY)
  {
    dupelog_add_entry(path, filename);
  }

  free(str);

  return ret;
}

event_reply_t dupecheck_event_postupload_denied(const char * args)
{
  const char *filename = strchr(args, ' ');
  if (filename == NULL)
    filename = args;
  else
    filename++;

  if (strrchr(filename, '/') != NULL)
    filename = strrchr(filename, '/') + 1;

  return dupelog_delete_entry(filename);
}

event_reply_t dupecheck_event_dele(const char * args)
{
  if (strrchr(args, '/') != NULL)
    args = strrchr(args, '/') + 1;

  return dupelog_delete_entry(args);
}

event_reply_t dupecheck_event_prerename(const char * args)
{
  /* This code is a bit complicated, because it compares the two filenames in args
   * without modifying or duplicating args. We have to compare the two arguments, 
   * because if they're identical (E.g. you're moving a file to another directory,
   * but keeping filename) you'll get a false positive from dupelog_is_upload_allowed
   */

  // FIXME: Paths with space in it :(
  char *pathFrom = strchr(args, ' '), *filenameFrom, *pathTo, *filenameTo;
  int filenameToLength;

  if (pathFrom == NULL)
  {
    out_err(LEVEL_HIGH, "Dupecheck: No space in args for dupecheck_event_prerename('%s')\n", args);
    return EVENT_OK;
  }
  pathFrom++;

  pathTo = strchr(pathFrom, ' ');
  if (pathTo == NULL)
  {
    out_err(LEVEL_HIGH, "Dupecheck: No second space in args for dupecheck_event_prerename('%s')\n", args);
    return EVENT_OK;
  }
  pathTo++;

  /* Here we set filenameFrom to the 
   * first character in the filename. It is _not_ nullterminated
   * where the filename ends, but rather where the args end. */
  for (filenameFrom = pathTo - 1; filenameFrom > pathFrom && *filenameFrom != '/'; filenameFrom--);
  filenameFrom++;

  /* Here we set filenameTo to the first character
   * in the filename, this _is_ nullterminated (it's the last part
   * of the args) */
  filenameTo = strrchr(pathTo, '/');
  if (filenameTo == NULL)
    filenameTo = pathTo;
  filenameTo++;

  filenameToLength = strlen(filenameTo);

  /* This checks if filenameFrom and filenameTo are
   * equally long. If they are, it're not the same filename,
   * and we check with the dupelog. */
  if (filenameFrom + filenameToLength + 1 != pathTo)
    return dupelog_is_upload_allowed(filenameTo);
  /* This checks the part of filenameFrom that contains the filename (that's
   * why we use strncmp - it stops after the right amount of characters).
   * This is only valid because we know the strings are of equal length.
   * If they're the same filename, then filenameFrom will be in the dupedb, and
   * we'll get a false positive from dupelog_is_upload_allowed(). */
  if (strncmp(filenameFrom, filenameTo, filenameToLength) == 0)
    return EVENT_OK;

  /* No more special-casing, we just check it. */
  return dupelog_is_upload_allowed(filenameTo);
}

event_reply_t dupecheck_event_postrename(const char * args)
{
  char *filenameFrom, *filenameTo, *pathTo;
  char *str = strdup(args), *ptr;

  // TODO: Make sure path is absolute!
  filenameFrom = strtok_r(strchr(str, ' '), " ", &ptr);
  pathTo = ptr;

  filenameTo = strrchr(pathTo, '/');

  if (strrchr(filenameFrom, '/') != NULL);
    filenameFrom = strrchr(filenameFrom, '/') + 1;

  if (filenameTo == NULL)
  {
    // FIXME: Path needs to found
    filenameTo = pathTo;
    pathTo = "./";
  }
  else
  {
    *filenameTo = '\0';
    filenameTo++;
  }

  dupelog_delete_entry(filenameFrom);
  dupelog_add_entry(pathTo, filenameTo);

  free(str);

  return EVENT_OK;
}
