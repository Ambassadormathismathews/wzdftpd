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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _MSC_VER
#include <winsock2.h>
#include <direct.h>
#include <io.h>

#include "../../visual/gnu_regex_dist/regex.h"
#else
#include <dirent.h>
#include <sys/types.h>
#include <regex.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

/*#include "wzd.h"*/
#include "wzd_structs.h"
#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_libmain.h"
#include "wzd_messages.h"
#include "wzd_mod.h" /* essential to define WZD_MODULE_INIT */
#include "wzd_cache.h"
#include "wzd_crc32.h"
#include "wzd_vfs.h" /* checkabspath */

#include "libwzd_sfv.h"
#include "libwzd_sfv_zip.h"

#define BUFFER_LEN      4096

static char progressmeter[256];
static char del_progressmeter[256];
static char incomplete_indicator[256];
static char other_completebar[256];
static short params_ok=0;

/* Converts cookies in incomplete indicators */
char *c_incomplete(char *instr, char *path);

/* updates complete bar (erasing preceding one if existing) */
void sfv_update_completebar(wzd_sfv_file sfv, const char *filename, wzd_context_t *context);

/* parse dir to calculate release completion % */
float _sfv_get_release_percent(const char *dir, wzd_sfv_file sfv);

/* get params from server */
static int get_all_params(void)
{
  if (params_ok) return 0;

  if (server_get_param("sfv_progressmeter",progressmeter,256,getlib_mainConfig()->param_list)) {
    out_log(LEVEL_HIGH,"Module SFV: missing parameter 'sfv_progressmeter'\n");
    return 1;
  }
  if (server_get_param("sfv_del_progressmeter",del_progressmeter,256,getlib_mainConfig()->param_list)) {
    out_log(LEVEL_HIGH,"Module SFV: missing parameter 'sfv_del_progressmeter'\n");
    return 1;
  }
  if (server_get_param("sfv_incomplete_indicator",incomplete_indicator,256,getlib_mainConfig()->param_list)) {
    out_log(LEVEL_HIGH,"Module SFV: missing parameter 'sfv_incomplete_indicator'\n");
    return 1;
  }
  if (server_get_param("sfv_other_completebar",other_completebar,256,getlib_mainConfig()->param_list)) {
    out_log(LEVEL_HIGH,"Module SFV: missing parameter 'sfv_other_completebar'\n");
    return 1;
  }

  params_ok = 1;
  return 0;
}

/* inits an sfv struct
 */
void sfv_init(wzd_sfv_file *sfv)
{
  sfv->comments = NULL;
  sfv->sfv_list = NULL;
}

/* create / remove ".missing" / ".bad" depending on the result of the test
 */
int sfv_check_create(const char *filename, wzd_sfv_entry * entry)
{
  char missing[1024], bad[1024];
  unsigned long real_crc;
  int ret, fd;
  struct stat s;

  if (strlen(filename) > 1000) return -1;
  strcpy(missing,filename);
  strcpy(bad,filename);
  strcat(missing,".missing");
  strcat(bad,".bad");

  if (stat(filename,&s) && errno==ENOENT) {
    /* missing */
    fd = open(missing,O_WRONLY|O_CREAT,0666);
    close(fd);
    if (!stat(bad,&s)) { unlink(bad); }
    entry->state = SFV_MISSING;
    return 0;
  }
  if (s.st_size == 0) {
    /* remove 0-sized file and treat it as missing */
    unlink(filename);
    fd = open(missing,O_WRONLY|O_CREAT,0666);
    close(fd);
    if (!stat(bad,&s)) { unlink(bad); }
    entry->state = SFV_MISSING;
    return 0;
  }
  entry->size = s.st_size;
  real_crc = 0;
  ret = calc_crc32(filename,&real_crc,0,-1);
  if (ret) return -1;

  if (real_crc == entry->crc) {
    if (!stat(bad,&s)) { unlink(bad); }
    if (!stat(missing,&s)) { unlink(missing); }
    entry->state = SFV_OK;
  } else { /* CRC differs */
    entry->state = SFV_BAD;
    fd = open(bad,O_WRONLY|O_CREAT,0666);
    close(fd);
    if (!stat(missing,&s)) { unlink(missing); }
  }
  return 0;
}

/* frees contents of a sfv structure
 * if sfv was allocated on heap you MUST free sfv struct after
 */
void sfv_free(wzd_sfv_file *sfv)
{
  int i;

  i=0;
  if (sfv->comments) {
    while (sfv->comments[i])
    {
      free(sfv->comments[i]);
      sfv->comments[i] = NULL;
      i++;
    }
  }
  i=0;
  if (sfv->sfv_list) {
    while (sfv->sfv_list[i])
    {
      free(sfv->sfv_list[i]->filename);
      sfv->sfv_list[i]->filename = NULL;
      free(sfv->sfv_list[i]);
      sfv->sfv_list[i] = NULL;
      i++;
    }
  }
}

/* reads sfv file
 */
int sfv_read(const char *filename, wzd_sfv_file *sfv)
{
  FILE *in;
  struct stat st;
  char buf[BUFSIZ];
  char * ptr;
  char *err_ptr;
/*  size_t i;*/
  int count_comments=0, count_entries=0;
  int length;

  if (stat(filename,&st) < 0) return -1;
  if (!S_ISREG(st.st_mode)) return -1;
  if ((in=fopen(filename,"r")) == NULL) return -1;

  sfv->comments = malloc(50*sizeof(char*));
  sfv->sfv_list = malloc(50*sizeof(wzd_sfv_entry*));

  while ( fgets(buf,BUFSIZ-1,in) != NULL) {
/*    if (i == -1) return -1;*/
    ptr = buf;
    length = strlen(buf); /* fgets put a '\0' at the end */
    /* trim trailing space, because fgets keep a \n */
    while ( *(ptr+length-1) == '\r' || *(ptr+length-1) == '\n') {
      *(ptr+length-1) = '\0';
      length--;
    }
    if (length <= 0) continue;
    /* XXX limitation */
    if (length > 512) continue;
    if (buf[0] == ';') { /* comment */
      /* count_comments + 2 : +1 for the new line to add, +1 to terminate
         array by NULL */
      if ((count_comments + 2 )% 50 == 0)
        sfv->comments = realloc(sfv->comments,(count_comments+50)*sizeof(char*));
      sfv->comments[count_comments] = malloc(length+1);
      strcpy(sfv->comments[count_comments],buf);
      count_comments++;
    } /* comment */
    else { /* entries */
      /* count_entries + 2 : +1 for the new line to add, +1 to terminate
         array by NULL */
      if ((count_entries + 2 )% 50 == 0)
        sfv->sfv_list = realloc(sfv->sfv_list,(count_entries+50)*sizeof(wzd_sfv_entry*));
      if (length < 10) continue;
      ptr = buf + length - 8;
      *(buf+length-9) = '\0';
      sfv->sfv_list[count_entries] = malloc(sizeof(wzd_sfv_entry));
      sfv->sfv_list[count_entries]->crc = strtoul(ptr,&err_ptr, 16);
      if (*err_ptr != '\0') {
        free(sfv->sfv_list[count_entries]);
        continue;
      }
      sfv->sfv_list[count_entries]->filename = malloc(strlen(buf)+1);
      strcpy(sfv->sfv_list[count_entries]->filename,buf);
      sfv->sfv_list[count_entries]->state = SFV_UNKNOWN;
      sfv->sfv_list[count_entries]->size = 0;
      count_entries++;
    }
  }
  sfv->comments[count_comments] = NULL;
  sfv->sfv_list[count_entries] = NULL;

  fclose(in);

  return 0;
}

/* creates sfv file
 * returns 0 if all ok
 * -1 for other errors
 * !! sfv_file path must be an ABSOLUTE path !!
 */
int sfv_create(const char * sfv_file)
{
  int ret=0, thisret;
  char * ptr;
  char directory[1024];
  char filename[2048];
  wzd_sfv_file sfv;
  int i;
  unsigned long crc;
  struct stat s;
#ifndef _MSC_VER
  DIR *dir;
  struct dirent *entr;
#else
  HANDLE dir;
  WIN32_FIND_DATA fileData;
  int finished;
  char dirfilter[MAX_PATH];
#endif
  char *dir_filename;
  int count_comments=0, count_entries=0;

  sfv_init(&sfv);

  sfv.comments = malloc(50*sizeof(char*));
  sfv.sfv_list = malloc(50*sizeof(wzd_sfv_entry*));

  if (strlen(sfv_file) >= 1024) return -1;
  strncpy(directory,sfv_file,1023);
  ptr = strrchr(directory,'/');
  if (!ptr) return -1;
  *(++ptr) = '\0';

  strcpy(filename,directory);
#ifndef _MSC_VER
  if ((dir=opendir(directory))==NULL) return -1;
#else
  _snprintf(dirfilter,2048,"%s/*",directory);
  if ((dir = FindFirstFile(dirfilter,&fileData))== INVALID_HANDLE_VALUE) return -1;
#endif

#ifndef _MSC_VER
  while ((entr=readdir(dir))!=NULL) {
    dir_filename = entr->d_name;
#else
  finished = 0;
  while (!finished) {
	dir_filename = fileData.cFileName;
#endif
    if (dir_filename[0]=='.') DIR_CONTINUE
    /* TODO check that file matches mask */

    if (strlen(dir_filename)>4) {
      char extension[5];
      strcpy(extension,dir_filename+strlen(dir_filename)-4);
      /* files that should not be in a sfv */
      if (strcasecmp(extension,".nfo")==0 ||
	  strcasecmp(extension,".diz")==0 ||
	  strcasecmp(extension,".sfv")==0 ||
	  strcasecmp(extension,".txt")==0)
	  DIR_CONTINUE
    }
    /* add to sfv file */
    strcpy(filename,directory);
    ptr = filename + strlen(directory);
/*    strcpy(ptr,sfv.sfv_list[i]->filename);*/
    strcpy(ptr,dir_filename);
    if (stat(filename,&s) || S_ISDIR(s.st_mode))
	  DIR_CONTINUE
    crc = 0;
    thisret = calc_crc32(filename,&crc,0,-1);
    /* count_entries + 2 : +1 for the new line to add, +1 to terminate
       array by NULL */
    if ((count_entries + 2 )% 50 == 0)
      sfv.sfv_list = realloc(sfv.sfv_list,(count_entries+50)*sizeof(wzd_sfv_entry*));
    sfv.sfv_list[count_entries] = malloc(sizeof(wzd_sfv_entry));
    sfv.sfv_list[count_entries]->crc = crc;
    sfv.sfv_list[count_entries]->filename = strdup(dir_filename);
    sfv.sfv_list[count_entries]->state = SFV_OK;
    sfv.sfv_list[count_entries]->state = s.st_size;
    count_entries++;
	DIR_CONTINUE
  } /* while ((entr=readdir(dir))!=NULL) */
  closedir(dir);
  sfv.comments[count_comments] = NULL;
  sfv.sfv_list[count_entries] = NULL;

  /* writes file */
  {
    char buffer[2048];
    int fd_sfv;
    fd_sfv = open(sfv_file,O_CREAT | O_WRONLY | O_TRUNC,0644);

    i=0;
    while (sfv.comments[i]) {
      write(fd_sfv,sfv.comments[i],strlen(sfv.comments[i]));
      write(fd_sfv,"\n",1);
      i++;
    }
    i=0;
    while (sfv.sfv_list[i]) {
      if (snprintf(buffer,2047,"%s %lx\n",sfv.sfv_list[i]->filename,
	    sfv.sfv_list[i]->crc) <= 0) return -1;
      ret = strlen(buffer);
      if ( write(fd_sfv,buffer,ret) != ret ) {
	out_err(LEVEL_CRITICAL,"Unable to write sfv_file (%s)\n",strerror(errno));
        closedir(dir);
       	return -1;
      }
      i++;
    }

    close(fd_sfv);
  }

  sfv_free(&sfv);
  return 0;
}

/* checks sfv file
 * returns 0 if all ok
 * number 0xaaabbb: a == missing files, b == errors
 * -1 for other errors
 * !! sfv_file path must be an ABSOLUTE path !!
 */
int sfv_check(const char * sfv_file)
{
  int ret=0, thisret;
  char * ptr;
  char dir[1024];
  char filename[2048];
  wzd_sfv_file sfv;
  int i;
  unsigned long crc;
  struct stat s;

  if (strlen(sfv_file) >= 1024) return -1;
  strncpy(dir,sfv_file,1023);
  ptr = strrchr(dir,'/');
  if (!ptr) return -1;
  *(++ptr) = '\0';

  sfv_init(&sfv);
  if (sfv_read(sfv_file,&sfv)) {
    sfv_free(&sfv);
    return -1;
  }

  i=0;
  strcpy(filename,dir);
  ptr = filename + strlen(dir);
  while (sfv.sfv_list[i]) {
    strcpy(ptr,sfv.sfv_list[i]->filename);
    if (stat(filename,&s) || S_ISDIR(s.st_mode)) {
      ret += 0x1000;
      sfv.sfv_list[i]->state = SFV_MISSING;
    } else {
      crc = 0;
      thisret = calc_crc32(filename,&crc,0,-1);
      if (thisret || crc != sfv.sfv_list[i]->crc) {
        ret ++;
	sfv.sfv_list[i]->state = SFV_BAD;
      }
      else {
	sfv.sfv_list[i]->state = SFV_OK;
      }
#ifdef DEBUG
out_err(LEVEL_CRITICAL,"file %s calculated: %08lX reference: %08lX\n",filename,crc,sfv.sfv_list[i]->crc);
#endif
    }
    *ptr = '\0';
    i++;
  }

  sfv_free(&sfv);
  return ret;
}

/* find sfv file in same dir than file
 * file must be an ABSOLUTE path to a file
 * retuns -1 if error
 * 0 if sfv found and file present in sfv, and put crc
 * 1 if no sfv found or sfv found but file not present
 */
int sfv_find_sfv(const char * file, wzd_sfv_file *sfv, wzd_sfv_entry ** entry)
{
#ifndef _MSC_VER
  DIR *dir;
  struct dirent *entr;
#else
  HANDLE dir;
  WIN32_FIND_DATA fileData;
  int finished;
  char dirfilter[MAX_PATH];
#endif
  char * dir_filename;
  char sfv_dir[1024];
  char stripped_filename[1024];
  char *ptr;
  unsigned int length;
  int ret;

  if (strlen(file) > 1023) return -1;

  strcpy(sfv_dir,file);
  ptr = strrchr(sfv_dir,'/');
  if (!ptr) return -1;
  *ptr = '\0';
  strncpy(stripped_filename,ptr+1,1023);
  if (strlen(stripped_filename)<=0) return -1;

#ifndef _MSC_VER
  if ( (dir=opendir(sfv_dir)) == NULL ) return -1;
#else
  _snprintf(dirfilter,2048,"%s/*",sfv_dir);
  if ((dir = FindFirstFile(dirfilter,&fileData))== INVALID_HANDLE_VALUE) return -1;
#endif

  sfv_init(sfv);

#ifndef _MSC_VER
  while ( (entr=readdir(dir)) != NULL ) {
    dir_filename = entr->d_name;
#else
  finished = 0;
  while (!finished) {
	dir_filename = fileData.cFileName;
#endif
    if (strcmp(dir_filename,".")==0 ||
	strcmp(dir_filename,"..")==0 ||
        strcmp(dir_filename,HARD_PERMFILE)==0)
	  DIR_CONTINUE;
    length = strlen(dir_filename);
    if (length<5) DIR_CONTINUE;
    if (strcasecmp(dir_filename+length-3,"sfv")==0)
    {
      char sfv_name[1024];
      int i;
      i = 0;
      ptr = sfv_dir;
      while (*ptr) {
	if (i >= 1022) DIR_CONTINUE
	sfv_name[i] = *ptr;
	i++;
	ptr++;
      }	
      sfv_name[i++] = '/';
      ptr = dir_filename;
      while (*ptr) {
	if (i >= 1023) DIR_CONTINUE
	sfv_name[i] = *ptr;
	i++;
	ptr++;
      }	
      *ptr = '\0';
      sfv_name[i]='\0';
      ret = sfv_read(sfv_name,sfv);
#ifdef DEBUG
      out_err(LEVEL_CRITICAL,"sfv file: %s\n",entr->d_name);
#endif
      if (ret == -1 || sfv->sfv_list == NULL) { closedir(dir); return -1; }
      /* sfv file found, check if file is in sfv */
      i = 0;
      while (sfv->sfv_list[i]) {
#ifdef __CYGWIN__
	if (strcasecmp(stripped_filename,sfv->sfv_list[i]->filename)==0) {
#else /* __CYGWIN__ */
	if (strcmp(stripped_filename,sfv->sfv_list[i]->filename)==0) {
#endif /* __CYGWIN__ */
	  *entry = sfv->sfv_list[i];
	  closedir(dir);
	  return 0;
	}
	i++;
      }
      sfv_free(sfv);
    }
	DIR_CONTINUE
  } /* while readdir */

  closedir(dir);

  return 1;
}

/* called after a sfv file is uploaded
 * sfv_file must be an ABSOLUTE path to a file
 * retuns -1 if error
 * 0 else
 */
int sfv_process_new(const char *sfv_file, wzd_context_t *context)
{
  wzd_sfv_file sfv;
  char dir[1024];
  char filename[2048];
  char *ptr;
  char * stripped_dirname = NULL;
  int i;
  int num_files;

  if (get_all_params()) return -1;

  if (strlen(sfv_file) >= 1024) return -1;
  strncpy(dir,sfv_file,1023);
  ptr = strrchr(dir,'/');
  if (!ptr) return -1;
  *(++ptr) = '\0';

  sfv_init(&sfv);
  if (sfv_read(sfv_file,&sfv)) {
    sfv_free(&sfv);
    return -1;
  }

  i=0;
  strcpy(filename,dir);
  ptr = filename + strlen(dir);
  while (sfv.sfv_list[i]) {
    strcpy(ptr,sfv.sfv_list[i]->filename);
    /* Check file ? - means sfv uploaded AFTER files */
    sfv_check_create(filename,sfv.sfv_list[i]);

    *ptr = '\0';
    i++;
  }
  num_files = i;

  /* create a dir/symlink to mark incomplete */
  if (strlen(dir)>2)
  {
    const char * incomplete;
    char dirname[256];
    if (dir[strlen(dir)-1]=='/') dir[strlen(dir)-1]='\0';
    ptr = strrchr(dir,'/');
    if (ptr) {
      stripped_dirname = ptr + 1; /* keep start of dir name for later use */
      strncpy(dirname,ptr+1,255);
      incomplete = c_incomplete(incomplete_indicator,dirname);
      /* create empty file|dir / symlink ? */
      if (dir[strlen(dir)-1]!='/') strcat(dir,"/");
      strcat(dir,incomplete); /* XXX FIXME bad ! */
      if (!checkabspath(dir,filename,context))
      {
#ifndef _MSC_VER
	/* symlink ? */
	if (symlink(dirname,filename) && errno != EEXIST)
	{
	  out_log(LEVEL_INFO,"Symlink creation failed (%s -> %s) %d (%s)\n",
	      dir, filename, errno, strerror(errno));
	}
#else
	/* empty file ? */
	close(creat(filename,0600));
#endif
      }
    }
  }

  /* warn user that we await xx files */
  if (stripped_dirname)
  {
    /* TODO XXX FIXME we only show last dir: /upload/TEST-SFV => TEST-SFV
     * This can be bad if dir name is like MOVIE-NAME/Cd1
     */
    ptr = strchr(stripped_dirname,'/');
    if (ptr)
    {
      *ptr = '\0';
      log_message("SFV","\"%s\" \"Got SFV for %s. Expecting %d file(s).\"",
          stripped_dirname,
          stripped_dirname,
          num_files
          );
    }
  }

  sfv_update_completebar(sfv,sfv_file,context);

  sfv_free(&sfv);
  return 0;
}

/* Converts cookies in incomplete indicators */
char i_buf[ 256 ];
char * c_incomplete(char *instr, char *path)
{
  char *buf_p;

  buf_p = i_buf;
  for ( ; *instr ; instr++ ) if ( *instr == '%' ) {
    instr++;
    switch ( *instr ) {
/*      case '0': buf_p += sprintf( buf_p, "%s", path[0] ); break;
      case '1': buf_p += sprintf( buf_p, "%s", path[1] ); break;*/
       case '0': buf_p += sprintf( buf_p, "%s", path ); break;
      case '%': *buf_p++ = '%' ; break;
    }
  } else {
    *buf_p++ = *instr;
  }
  *buf_p = 0;
  return i_buf;
}

char output[2048];
/* Converts cookies in complete indicators
 *
 * NOTE: sfv file MUST be filled !
 */
const char *_sfv_convert_cookies(char * instr, const char *dir, wzd_sfv_file sfv)
{
 int 	val1, val2;
/* int	n, from, to, reverse;*/
 char	*out_p;
 char	*m;
 char	ctrl[10];
 int	total_files = 0, i;
 double	total_size=0;
 struct stat s;
 char	buffer[1024];
 size_t	len;

 strncpy(buffer,dir,1023);
 len = strlen(dir);
 if (buffer[len-1] != '/') { buffer[len-1]='/'; len++; }
 i=0;
 while (sfv.sfv_list[i]) {
   strcpy(buffer+len,sfv.sfv_list[i]->filename);
   if (!stat(buffer,&s)) {
     total_size += (s.st_size / 1024.);
   }
   buffer[len]='\0';
   i++;
 }
 total_files = i;

 out_p = output;

 for ( ; *instr ; instr++ ) if ( *instr == '%' ) {
	instr++;
	m = instr;
	if (*instr == '-' && isdigit(*(instr + 1))) instr += 2;
	while (isdigit(*instr)) instr++;
	if ( m != instr ) {
		sprintf(ctrl, "%.*s", instr - m, m);
		val1 = atoi(ctrl);
		} else {
		val1 = 0;
		}

	if ( *instr == '.' ) {
		instr++;
		m = instr;
		if (*instr == '-' && isdigit(*(instr + 1))) instr += 2;
		while (isdigit(*instr)) instr++;
		if ( m != instr ) {
			sprintf(ctrl, "%.*s", instr - m, m);
			val2 = atoi(ctrl);
			} else {
			val2 = 0;
			}
		} else {
		val2 = -1;
		}

	 switch ( *instr ) {
#if 0
		case 'a': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)(raceI->total.size / raceI->total.speed)); break;
		case 'A': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)(raceI->total.size / ((raceI->transfer_stop.tv_sec - raceI->transfer_start.tv_sec) + (raceI->transfer_stop.tv_usec - raceI->transfer_start.tv_usec) / 1000000.) / 1024)); break;
		case 'b': out_p += sprintf(out_p, "%*i", val1, (int)raceI->total.size); break;
		case 'B': out_p += sprintf(out_p, "\\002"); break;
		case 'c':
			from = to = reverse = 0;
			instr++;
			m = instr;
			if ( *instr == '-' ) {  
				reverse = 1;
				instr++;
				}

			for ( ; isdigit(*instr) ; instr++ ) {
				from *= 10;
				from += *instr - 48;
				}

			if ( *instr == '-' ) {
				instr++;
				for ( ; isdigit(*instr) ; instr++ ) { 
					to *= 10;
					to += *instr - 48;
					}
				if ( to == 0 || to >= raceI->total.groups ) {
					to = raceI->total.groups - 1;
					}
				}

			if ( to < from ) {
				to = from;
				}

			if ( reverse == 1 ) {
				n = from;
				from = raceI->total.groups - 1 - to;
				to = raceI->total.groups - 1 - n;
				}

			if ( from >= raceI->total.groups ) {
				to = -1;
				}

			for ( n = from ; n <= to ; n++ ) {
				out_p += sprintf(out_p, "%*.*s", val1, val2, convert3(raceI, groupI[groupI[n]->pos], group_info, n));
				}
			instr--;
			break;
		case 'C':
			from = to = reverse = 0;
			instr++;
			m = instr;
			if ( *instr == '-' ) {  
				reverse = 1;
				instr++;
				}

			for ( ; isdigit(*instr) ; instr++ ) {
				from *= 10;
				from += *instr - 48;
				}

			if ( *instr == '-' ) {
				instr++;
				for ( ; isdigit(*instr) ; instr++ ) { 
					to *= 10;
					to += *instr - 48;
					}
				if ( to == 0 || to >= raceI->total.users ) {
					to = raceI->total.users - 1;
					}
				}

			if ( to < from ) {
				to = from;
				}

			if ( reverse == 1 ) {
				n = from;
				from = raceI->total.users - 1 - to;
				to = raceI->total.users - 1 - n;
				}

			if ( from >= raceI->total.users ) {
				to = -1;
				}

			for ( n = from ; n <= to ; n++ ) {
				out_p += sprintf(out_p, "%*.*s", val1, val2, convert2(raceI, userI[userI[n]->pos], groupI, user_info, n)); break;
				}
			instr--;
			break;
		case 'd': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)hms(raceI->transfer_stop.tv_sec - raceI->transfer_start.tv_sec)); break;
		case 'e': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)((raceI->file.size * raceI->total.files >> 10) / 1024.)); break;
#endif
		case 'f': out_p += sprintf(out_p, "%*i", val1, (int)total_files); break;
#if 0
		case 'F': out_p += sprintf(out_p, "%*i", val1, (int)raceI->total.files - raceI->total.files_missing); break;
		case 'g': out_p += sprintf(out_p, "%*i", val1, (int)raceI->total.groups); break;
		case 'G': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->user.group); break;
		case 'k': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)(raceI->total.size / 1024.)); break;
		case 'l': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)convert2(raceI, userI[raceI->misc.slowest_user[1]], groupI, slowestfile, 0)); break;
		case 'L': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)convert2(raceI, userI[raceI->misc.fastest_user[1]], groupI, fastestfile, 0)); break;
#endif
		case 'm': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)(total_size / 1024.)); break;
#if 0
		case 'M': out_p += sprintf(out_p, "%*i", val1, (int)raceI->total.files_missing); break;
		case 'n': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->file.name); break;
		case 'o': out_p += sprintf(out_p, "%*i", val1, val2, (int)raceI->total.files_bad); break;
		case 'O': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)((raceI->total.bad_size >> 10) / 1024.)); break;
		case 'p': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)((raceI->total.files - raceI->total.files_missing) * 100. / raceI->total.files)); break;
		case 'P': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)(raceI->total.bad_size / 1024.)); break;
		case 'S': out_p += sprintf(out_p, "%*.*f", val1, val2, (double)(raceI->file.speed / 1024.)); break;
		case 'r': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->misc.release_name); break;
		case 'R': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->misc.racer_list + 1); break;
		case 't': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->misc.top_messages[1] + 1); break;
		case 'T': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->misc.top_messages[0] + 1); break;
		case 'u': out_p += sprintf(out_p, "%*i", val1, (int)raceI->total.users); break;
		case 'U': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->user.name); break;
		case 'v': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->misc.error_msg); break;
		case 'V': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->misc.progress_bar); break;

		/* Audio */

		case 'w': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.id3_genre); break;
		case 'W': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.id3_album); break;
		case 'x': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.id3_artist); break;
		case 'y': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.id3_title); break;
		case 'Y': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.id3_year); break;
		case 'X': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.bitrate); break;
		case 'z': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.samplingrate); break;
		case 'h': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.codec); break;
		case 'q': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.layer); break;
		case 'Q': out_p += sprintf(out_p, "%*.*s", val1, val2, (char *)raceI->audio.channelmode); break;

		/* Video */

		case 'D': out_p += sprintf(out_p, "%*i", val1, raceI->video.width); break;
		case 'E': out_p += sprintf(out_p, "%*i", val1, raceI->video.height); break;
		case 'H': out_p += sprintf(out_p, "%*i", val1, raceI->video.fps); break;

		/* Other */

		case 'Z': *out_p++ = raceI->file.compression_method; break;
		case '%': *out_p++ = *instr;
#endif
		}
	} else *out_p++ = *instr;
 *out_p = 0;
 return output;
}

/* updates complete bar (erasing preceding one if existing) */
void sfv_update_completebar(wzd_sfv_file sfv, const char *filename, wzd_context_t * context)
{
  char dir[512];
  int ret;
  char *ptr;
  size_t len;
  regex_t preg;
  regmatch_t pmatch[1];

  if (get_all_params()) return;

  /* do NOT comment this, we get len here ! */
#ifndef _MSC_VER
  if (!filename || (len=strlen(filename))<2 || filename[0]!='/') return;
#else
  if (!filename || (len=strlen(filename))<2 || (filename[0]!='/' && filename[1]!=':')) return;
#endif
  ptr = strrchr(filename,'/');
  len = (ptr-filename)+1; /* +1 because we want the / */
  strncpy(dir,filename,len);
  dir[len]='\0';
  
  regcomp( &preg, del_progressmeter, REG_NEWLINE|REG_EXTENDED );
  {
    char buffer[512];
#ifndef _MSC_VER
    DIR *d;
    struct dirent *entr;
#else
    HANDLE d;
    WIN32_FIND_DATA fileData;
    int finished;
    char dirfilter[MAX_PATH];
#endif
    char *dir_filename;
    float percent;

    /* Removes previous progressmeter */
#ifndef _MSC_VER
    if ( (d=opendir(dir))==NULL ) return;
#else
    snprintf(dirfilter,2048,"%s/*",dir);
    if ((d = FindFirstFile(dirfilter,&fileData))== INVALID_HANDLE_VALUE) return;
#endif
#ifndef _MSC_VER
    while ((entr=readdir(d))!=NULL) {
      dir_filename = entr->d_name;
#else
    finished = 0;
    while (!finished) {
	  dir_filename = fileData.cFileName;
#endif
      if (dir_filename[0]=='.')
	  {
#ifdef _MSC_VER
        if (!FindNextFile(d,&fileData))
		{
	      if (GetLastError() == ERROR_NO_MORE_FILES)
		    finished = 1;
		}
#endif
	    continue;
	  }
      if ( regexec( &preg, dir_filename, 1, pmatch, 0) == 0 ) {
	/* found, remove it  */
	/* security check */
	if (len+strlen(dir_filename)>510)
	  {
#ifdef _MSC_VER
        if (!FindNextFile(d,&fileData))
		{
	      if (GetLastError() == ERROR_NO_MORE_FILES)
		    finished = 1;
		}
#endif
	    continue;
	  }
	strcpy(dir+len,dir_filename);
	remove (dir);
	dir[len]='\0';
      }
#ifdef _MSC_VER
    if (!FindNextFile(d,&fileData))
	{
      if (GetLastError() == ERROR_NO_MORE_FILES)
	    finished = 1;
	}
#endif
    }
    closedir(d);

    percent = _sfv_get_release_percent(dir, sfv);
    if (percent >= 100.f) { /* complete */
      const char *complete;
      const char *incomplete;
      char dirname[512];
      /* create complete tag */
      complete = _sfv_convert_cookies(other_completebar,dir,sfv);
      strcpy(dir+len,complete);
      mkdir(dir,0755);
      dir[len]='\0';
      /* remove incomplete symlink */
      if (dir[strlen(dir)-1]=='/') dir[strlen(dir)-1]='\0';
      ptr = strrchr(dir,'/');
      if (ptr) {
	strncpy(dirname,ptr+1,255);
	incomplete = c_incomplete(incomplete_indicator,dirname);
	/* remove empty file|dir / symlink */
	if (dir[strlen(dir)-1]!='/') strcat(dir,"/");
	strcat(dir,incomplete);
	if (!checkabspath(dir,buffer,context))
	{
	  remove(buffer);
	}
      }
      {
	wzd_context_t * context;
	wzd_user_t * user;
	char * groupname=NULL;
	char buffer[2048];
	char *ptr;

	context = GetMyContext();
	user = GetUserByID(context->userid);
	strncpy(buffer,context->currentpath,2048);
	len = strlen(buffer);
	if (buffer[len-1] != '/') {
	  buffer[len++]='/';
	  buffer[len]='\0';
	}
	strncpy(buffer+len,context->last_command+5,2048-len);
	ptr = strrchr(buffer,'/');
	if (!ptr) { closedir(d); return; }
	*ptr='\0';
	if (user->group_num>0) {
	  wzd_group_t * group;
	  group = GetGroupByID(user->groups[0]);
	  if (group) groupname = group->groupname;
	}
	log_message("COMPLETE","\"%s\" \"%s\" \"%s\" \"%s\"",
	    buffer, /* ftp-absolute path */
	    user->username,
	    (groupname)?groupname:"No Group",
	    user->tagline
	    );
      }
    } else { /* incomplete */
      snprintf(buffer,255,progressmeter,(int)percent);

      strcat(dir,buffer); /* XXX FIXME bad ! */
      /* create empty dir ? */
      mkdir (dir,0755);
    } /* complete ? */
  }
}

/* parse dir to calculate release completion % */
float _sfv_get_release_percent(const char *dir, wzd_sfv_file sfv)
{
  float percent=0.f;
  char buffer[512], missing[512], bad[512];
  size_t len, len_file;
  int i;
  unsigned int count=0, total_count=0;
  struct stat s;

  if (sfv.sfv_list == NULL) return 0;
  
  strncpy(buffer,dir,511);
  len = strlen(buffer);
  if (buffer[len-1] != '/') { buffer[len-1]='/'; len++; }
    /* note: we do not write '\0' because strncpy pads buffer with 0's */

  i=0;
  while (sfv.sfv_list[i])
  {
    total_count++;
    len_file = strlen(sfv.sfv_list[i]->filename);
    if (511-len <= len_file+8) continue;
      /* 8 is strlen("-missing") */
    strcpy(buffer+len,sfv.sfv_list[i]->filename);
    strcpy(missing,buffer);
    strcpy(missing+len+len_file,".missing");
    strcpy(bad,buffer);
    strcpy(bad+len+len_file,".bad");
    if ( stat(buffer,&s)==0 && stat(missing,&s) && stat(bad,&s) ) {
      count++;
    } else {
      if ( stat(buffer,&s) ) {
	if ( !stat(bad,&s) )
	  remove(bad);
	if ( stat(missing,&s) )
	  close(open(missing,O_WRONLY|O_CREAT,0666));
      }
    }
    i++;
  }
  if (count == total_count) return 100.f;

  percent = count * 100.f / total_count;
  return percent;
}

void do_site_help_sfv(wzd_context_t * context)
{
  char buffer[BUFFER_LEN];

  snprintf(buffer,BUFFER_LEN,"Syntax error in command SFV\n");
  strcat(buffer," SITE SFV CHECK sfv_filename\n");
  strcat(buffer," SITE SFV CREATE sfv_filename\n");
  strcat(buffer," ");
  send_message_with_args(501,context,buffer);
}

/********************* do_site_zip *************************/
/* called after a zip file is uploaded
 * zip_file must be an ABSOLUTE path to a file
 * retuns -1 if error
 * 0 else
 */
int _internal_sfv_check_zip(const char *zip_file, wzd_context_t *context)
{
#ifdef HAVE_ZLIB

#define UNZIP_BUFFER_SIZE       (8192)

  zipFile s;
  zip_global_info gi;
  zip_file_info file_info;
  int err;
  unsigned int size_buf = UNZIP_BUFFER_SIZE;
  unsigned char buf[UNZIP_BUFFER_SIZE];
  char filename_inzip[256];
  unsigned int i;

  s = unzipOpen(zip_file);

  err = unzipGetGlobalInfo(s,&gi);
  if (err != ZIP_OK)
  {
    unzipClose(s);
    return 1;
  }

  for (i=0; i<gi.number_entry; i++)
  {
    err = unzipGetCurrentFileInfo(s,&file_info,
        filename_inzip,sizeof(filename_inzip),
        NULL, 0, NULL, 0);
    if (err != ZIP_OK)
    {
      unzipClose(s);
      return 1;
/*      fprintf(stderr,"error %d with zipfile in unzipGetCurrentFileInfo\n",err);*/
/*      break;*/
    }

    if ( (err=unzipOpenCurrentFile(s)) != ZIP_OK) {
/*      fprintf(stderr,"Error opening zip file ! (%d)\n",err);*/
      unzipClose(s);
      return 1;
    } else {
      do {
        err = unzipReadCurrentFile(s,buf,size_buf);
        if (err < 0)
        {
          unzipCloseCurrentFile(s);
          unzipClose(s);
          return 1;
/*          fprintf(stderr,"Error %d with zipfile in unzipReadCurrentFile\n",err);*/
/*          break;*/
        }
      } while (err > 0);
      unzipCloseCurrentFile(s);
    }

    
    if ((i+1) < gi.number_entry)
    {
      err = unzipGoToNextFile(s);
      if (err != ZIP_OK)
      {
        unzipClose(s);
        return 1;
/*        fprintf(stderr,"error %d with zipfile in unzipGoToNextFile\n",err);*/
/*        break;*/
      }
    }
  }


  unzipClose(s);
#endif /* HAVE_ZLIB */
  return 0;
}

int sfv_process_zip(const char *zip_file, wzd_context_t *context)
{
  char * bad;
  int ret;
  int fd;
  unsigned int length;
  struct stat s;

  ret = _internal_sfv_check_zip(zip_file,context);

  length = strlen(zip_file);
  bad = malloc(length + 5);
  strncpy(bad,zip_file,length);
  memcpy(bad+length,".bad",4);
  bad[length+4] = '\0';

  if (ret)
  {
    fd = open(bad,O_WRONLY|O_CREAT,0666);
  } else { /* if .bad exists, remove it */
    if (!stat(bad,&s)) { unlink(bad); }
  }

  free(bad);

  return ret;
}

/********************* sfv_process_diz *********************/
/* called after a diz file is uploaded
 * diz_file must be an ABSOLUTE path to a file
 * retuns -1 if error
 * 0 else
 */
int sfv_process_diz(const char *diz_file, wzd_context_t *context)
{
#define MAX_LINE        1024
  char buffer[MAX_LINE];
  wzd_cache_t * fd;
  regex_t reg_format;
  regmatch_t regmatch[3];
  char * str_num_files;
  char * stripped_dirname = NULL;
  char * ptr;
  int num_files;
  int i;
  int ret;
  /* search for following pattern in .diz file (in order!):
   *  [xx/15] or [01/15]
   *  <xx/15>
   *
   *  NOTE 0 is sometime replaced with O
   */

  fd = wzd_cache_open(diz_file,O_RDONLY,0644);
  if (!fd) { return -1; } /* error opening .diz file */

  ret = regcomp(&reg_format, "[[<]([0-9xXo0]+)/([0-9o0]+)[]>]", REG_EXTENDED);
  if (ret) { return -1; } /* bad regex, could not be compiled */

  while ( wzd_cache_gets(fd,buffer,MAX_LINE-1) )
  {
    ret = regexec(&reg_format,buffer,3,regmatch,0);
    if (!ret)
    {
      str_num_files = buffer+regmatch[2].rm_so;
      buffer[regmatch[2].rm_eo] = '\0';
      /* replace oO with 0 */
      for (i=0;str_num_files[i] != '\0';i++)
      {
        if (str_num_files[i] == 'o' || str_num_files[i] == 'O')
          str_num_files[i] = '0';
      }
      num_files = atoi(str_num_files);
      break;
    }
  }

  regfree(&reg_format);
  wzd_cache_close(fd);

  /* warn user that we await xx files */
  /* we re-use buffer, we have enough space in it */
  strncpy(buffer,diz_file,MAX_LINE);
  ptr = strrchr(buffer,'/');
  *ptr = '\0';
  ptr = strrchr(buffer,'/');
  stripped_dirname = ptr;
  if (stripped_dirname)
  {
    /* TODO XXX FIXME we only show last dir: /upload/TEST-SFV => TEST-SFV
     * This can be bad if dir name is like MOVIE-NAME/Cd1
     */
    stripped_dirname++;
    log_message("DIZ","\"%s\" \"Got DIZ for %s. Expecting %d file(s).\"",
        stripped_dirname,
        stripped_dirname,
        num_files
        );
  }

  return 0;
}

/********************* do_site_sfv *************************/
/* sfv: add / check / create
 * check sfv_name
 * create new_sfv_name
 */
void do_site_sfv(char *command_line, wzd_context_t * context)
{
  char buffer[BUFFER_LEN];
  char * ptr;
  char * command, *name;
  int ret;
  wzd_sfv_file sfv;

  ptr = command_line;
  command = strtok_r(command_line," \t\r\n",&ptr);
  if (!command) {
    do_site_help_sfv(context);
    return;
  }
  name = strtok_r(NULL," \t\r\n",&ptr);

  if (!name) {
    do_site_help_sfv(context);
    return;
  }

  /* convert file to absolute path, remember sfv wants ABSOLUTE paths ! */
  if ( (ret = checkpath(name,buffer,context)) != 0 ) {
    do_site_help_sfv(context);
    return;
  }
/*  buffer[strlen(buffer)-1] = '\0';*/ /* remove '/', appended by checkpath */
  sfv_init(&sfv);

  if (strcasecmp(command,"add")==0) {
    ret = send_message_with_args(200,context,"Site SFV add successfull");
  }
  if (strcasecmp(command,"check")==0) {
    ret = sfv_check(buffer);
    if (ret == 0) {
      ret = send_message_with_args(200,context,"All files ok");
    } else if (ret < 0) {
       ret = send_message_with_args(501,context,"Critical error occured");
    }
    else {
      char buf2[128];
      snprintf(buf2,128,"SFV check: missing files %d;  crc errors %d", (ret >> 12),ret & 0xfff);
      ret = send_message_with_args(501,context,buf2);
    }
  }
  if (strcasecmp(command,"create")==0) {
    ret = sfv_create(buffer);
    if (ret == 0) {
      ret = send_message_with_args(200,context,"All files ok");
    } else {
       ret = send_message_with_args(501,context,"Critical error occured");
    }
  }
  
  sfv_free(&sfv);
}


/***** EVENT HOOKS *****/
int sfv_hook_preupload(unsigned long event_id, const char * username, const char *filename)
{
  wzd_sfv_file sfv;
  wzd_sfv_entry *entry=NULL;
  int ret;
  int length;

  /* check file type */
  length = strlen(filename);
  if (length >= 4) {
    if (strcasecmp(filename+length-4,".sfv")==0) /* do not check sfv files against themselves ... */
      return 0;
  }
  ret = sfv_find_sfv(filename,&sfv,&entry);
  switch (ret) {
  case 0:
#ifdef DEBUG
    out_err(LEVEL_FLOOD,"sfv_hook_preupload user %s file %s, ret %d crc %08lX\n",username,filename,ret,entry->crc);
#endif
    break;
  case 1:
#ifdef DEBUG
    out_err(LEVEL_FLOOD,"No sfv found or file not present in sfv\n");
#endif
    break;
  default:
    /* error */
    return -1;
  }
  sfv_free(&sfv);
  return 0;
}

int sfv_hook_postupload(unsigned long event_id, const char * username, const char *filename)
{
  wzd_sfv_file sfv;
  wzd_sfv_entry *entry=NULL;
  unsigned long crc, real_crc;
  int ret;
  int length;
  wzd_context_t * context;

  context = GetMyContext();

  /* check file type */
  length = strlen(filename);
  if (length >= 4) {
    if (strcasecmp(filename+length-4,".sfv")==0) /* Process a new sfv file */
      return sfv_process_new(filename,context);
    if (strcasecmp(filename+length-4,".zip")==0) /* Process a zip file */
      return sfv_process_zip(filename,context);
    if (strcasecmp(filename+length-4,".diz")==0) /* Process a diz file */
      return sfv_process_diz(filename,context);
  }
  crc = 0;
  ret = sfv_find_sfv(filename,&sfv,&entry);
  switch (ret) {
  case 0:
#ifdef DEBUG
    out_err(LEVEL_NORMAL,"sfv_hook_postupload user %s file %s, crc %08lX OK\n",username,filename,entry->crc);
#endif
    break;
  case 1:
#ifdef DEBUG
    out_err(LEVEL_NORMAL,"No sfv found or file not present in sfv\n");
#endif
    return 1;
  default:
    /* error */
    return -1;
  }
  real_crc = 0;
  ret = calc_crc32(filename,&real_crc,0,-1);
  if (ret) {
    sfv_free(&sfv);
    return -1;
  }
  sfv_check_create(filename,entry);

  sfv_update_completebar(sfv,filename,context);

  sfv_free(&sfv);
  return ret;
}

int sfv_hook_site(unsigned long event_id, wzd_context_t * context, const char *token, const char *args)
{
  if (strcasecmp(token,"SFV")==0) {
    char buffer[BUFFER_LEN];
    strncpy(buffer,args,BUFFER_LEN-1);
    do_site_sfv(buffer,context);
    return 0;
  }

  return 1;
}

/***********************/
/* WZD_MODULE_INIT     */

int WZD_MODULE_INIT(void)
{
/*  printf("WZD_MODULE_INIT\n");*/
/*  out_err(LEVEL_INFO,"max threads: %d\n",getlib_mainConfig()->max_threads);*/
  hook_add(&getlib_mainConfig()->hook,EVENT_PREUPLOAD,(void_fct)&sfv_hook_preupload);
  hook_add(&getlib_mainConfig()->hook,EVENT_POSTUPLOAD,(void_fct)&sfv_hook_postupload);
  hook_add(&getlib_mainConfig()->hook,EVENT_SITE,(void_fct)&sfv_hook_site);
#ifdef DEBUG
  out_err(LEVEL_INFO,"module sfv: hooks registered\n");
#endif
  return 0;
}

int WZD_MODULE_CLOSE(void)
{
  hook_remove(&getlib_mainConfig()->hook,EVENT_PREUPLOAD,(void_fct)&sfv_hook_preupload);
  hook_remove(&getlib_mainConfig()->hook,EVENT_POSTUPLOAD,(void_fct)&sfv_hook_postupload);
  hook_remove(&getlib_mainConfig()->hook,EVENT_SITE,(void_fct)&sfv_hook_site);
#ifdef DEBUG
  out_err(LEVEL_INFO,"module sfv: hooks unregistered\n");
#endif
  return 0;
}
