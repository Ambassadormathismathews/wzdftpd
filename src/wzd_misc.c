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
#include <string.h>
#include <ctype.h> /* isspace */
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _MSC_VER
#include <winsock2.h>
#include <direct.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/ioctl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <net/if.h>
#include <netdb.h>

#include <dirent.h>

#include <pthread.h>
#endif

#include <fcntl.h>
#include <time.h>
/* for intel compiler */
#ifdef __INTEL_COMPILER
# define __SWORD_TYPE   int
#endif /* __INTEL_COMPILER */

#ifndef _MSC_VER
#include <sys/param.h>

#ifdef BSD
/* statfs */
#include <sys/mount.h>
#else
#include <sys/vfs.h> /* statfs */
#endif
#endif /* _MSC_VER */


#include "wzd_structs.h"

#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_messages.h"
#include "wzd_mutex.h"
#include "wzd_ServerThread.h"

#endif /* WZD_USE_PCH */


#if defined(WIN32) || defined(BSD)
#define LONGBITS  0x20
#else
/* needed  for LONGBITS */
#include <values.h>
#endif


#include "wzd_debug.h"


/** Compute the hash value for the given string.  The algorithm
 * is taken from [Aho,Sethi,Ullman], modified to reduce the number of
 * collisions for short strings with very varied bit patterns.
 * See http://www.clisp.org/haible/hashfunc.html.
 */
unsigned long compute_hashval (const void *key, size_t keylen)
{
  size_t cnt;
  unsigned long int hval;

  cnt = 0;
  hval = keylen;
  while (cnt < keylen)
  {
    hval = (hval << 9) | (hval >> (LONGBITS - 9));
    hval += (unsigned long int) *(((char *) key) + cnt++);
  }
  return hval != 0 ? hval : ~((unsigned long) 0);
}

#define PRIME 211
int hash_pjw(const char *s)
{
  const char *p;
  unsigned h=0, g;

  for (p=s; *p!='\0'; p++)
  {
    h = (h << 4) + (*p);
    if ( (g= h & 0xF0000000) != 0) {
      h = h ^ (g >> 24);
      h = h ^ g;
    }
  }
  return h % PRIME;
}

char *time_to_str(time_t time)
{

  static char workstr[100];
  unsigned short int days=(time/86400),hours,mins,secs;
  hours=((time-(days*86400))/3600);
  mins=((time-(days*86400)-(hours*3600))/60);
  secs = time % 60;

  if (days) {
    snprintf(workstr,sizeof(workstr),"%dd %dh %dm %ds",days,hours,mins,secs);
  }
  else {
    if (hours) {
      snprintf(workstr,sizeof(workstr),"%dh %dm %ds",hours,mins,secs);
    }
    else {
      if (mins) {
        snprintf(workstr,sizeof(workstr),"%dm %ds",mins,secs);
      }
      else {
        if (secs) {
          snprintf(workstr,sizeof(workstr),"%ds",secs);
        }
        else {
          snprintf(workstr,sizeof(workstr),"0 seconds");
        }
      }
    }
  }


  return(workstr);
}

/** \todo replace this with: char units[]="bkMGT";
 * char * ptr = units; -> while (*value > 1024.f) { ... *unit = *ptr++; }
 */
int bytes_to_unit(float *value, char *unit)
{
  *unit='b';
  if (*value>1024.f) {
    *value /= 1024.f;
    *unit = 'k';
  }
  if (*value>1024.f) {
    *value /= 1024.f;
    *unit = 'M';
  }
  if (*value>1024.f) {
    *value /= 1024.f;
    *unit = 'G';
  }
  if (*value>1024.f) {
    *value /= 1024.f;
    *unit = 'T';
  }
  return 0;
}

void chop(char *s)
{
  char *r;

  if ((r=(char*) strchr(s,'\r')))
    *r = '\0';
  if ((r=(char*) strchr(s,'\n')))
    *r = '\0';
}

int split_filename(const char *filename, char *path, char *stripped_filename,
    int pathlen, unsigned int filelen)
{
  char *ptr;

  ptr = strrchr(filename,'/');
  if (!ptr) { /* no dir */
    if (path && pathlen>0) path[0] = '\0';
    if (stripped_filename && filelen>strlen(filename)) strncpy(stripped_filename,filename,filelen);
  } else {
    if (path && pathlen>(ptr-filename))
      { memcpy(path,filename,ptr-filename); path[ptr-filename]='\0'; }
    if (stripped_filename && filelen>(strlen(filename)-(ptr-filename)))
      { strncpy(stripped_filename,ptr+1,filelen); }
  }

  return 0;
}

/** returns system ip on specifed interface (e.g eth0) */
int get_system_ip(const char * itface, struct in_addr * ina)
{
#if defined(_MSC_VER)
  char buffer_name[256];
  struct hostent * host;

  if (gethostname(buffer_name,sizeof(buffer_name))) return -1;

  if ( !(host = gethostbyname(buffer_name)) ) return -1;

  memcpy(ina,host->h_addr,4);
  out_log(LEVEL_FLOOD,"IP: %s\n",inet_ntoa(*ina));

  return 0;
#endif
#if BSD || defined(_MSC_VER)
  return -1;
#else
/*  struct in_addr *ina = void_in;*/
  struct ifreq ifr;
  int s;

  if ( (s = socket(PF_INET,SOCK_STREAM,0))<0 ) {
    out_log(LEVEL_CRITICAL,"Can't create new socket (%s:%d)\n",__FILE__,__LINE__);
    ina->s_addr = 0;
    return -1;
  } 
  memset(&ifr,0,sizeof(ifr));
  strncpy(ifr.ifr_name,itface,sizeof(ifr.ifr_name));

  if (ioctl(s,SIOCGIFADDR,&ifr)<0) {
    out_log(LEVEL_CRITICAL,"Can't get my ip (ioctl %s:%d)\n",__FILE__,__LINE__);
    ina->s_addr = 0;
    return -1;
  }

  memcpy(ina,ifr.ifr_hwaddr.sa_data+2,4);
  out_log(LEVEL_FLOOD,"IP: %s\n",inet_ntoa(*ina));

  close(s);
  return 0;
#endif /* BSD */
}

/** returns info on device containing dir/file */
int get_device_info(const char *file, long * f_type, long * f_bsize, long * f_blocks, long *f_free)
{
#ifndef WIN32
  struct statfs fs;

  if (statfs(file,&fs)==0) {
    if (f_bsize) *f_bsize = fs.f_bsize;
#ifndef BSD
    if (f_type) *f_type = fs.f_type;
#endif /* BSD */
    if (f_blocks) *f_blocks = fs.f_blocks;
    if (f_free) *f_free = fs.f_bavail; /* f_bavail: free blocks avail to non-superuser */
    return 0;
  }
#else
  struct _diskfree_t df;
  unsigned int err;
  unsigned int drive;

  if (!file || strlen(file)<2) return -1;

  if (file[1] == ':') {
    if (file[0] >= 'A' && file[0] <= 'Z')
      drive = file[0] - 'A' + 1;
    else
      drive = file[0] - 'a' + 1;
  } else {
    drive = _getdrive();
  }
  if (drive > 26) return -1;
  err = _getdiskfree(drive, &df);
  if (!err) {
    if (f_free) *f_free = df.avail_clusters * df.sectors_per_cluster;
    if (f_bsize) *f_bsize = df.bytes_per_sector;
    if (f_blocks) *f_blocks = df.total_clusters * df.sectors_per_cluster;
  }
#endif
  return -1;
}

/** internal fct, rename files by copying data */
static int _int_rename(const char * src, const char *dst)
{
  struct stat s;
  int ret;

  if (lstat(src,&s)) return -1;

  if (S_ISDIR(s.st_mode)) {
    char buf_src[2048];
    char buf_dst[2048];
    unsigned int length_src=2048;
    unsigned int length_dst=2048;
    char * ptr_src, * ptr_dst;
#ifndef _MSC_VER
    DIR *dir;
    struct dirent *entr;
#else
    HANDLE dir;
    WIN32_FIND_DATA fileData;
    int finished;
    char dirfilter[2048];
#endif
    const char *filename;

    ret = mkdir(dst,s.st_mode & 0xffff);
    ret = chmod(dst,s.st_mode & 0xffff);
    memset(buf_src,0,2048);
    memset(buf_dst,0,2048);
    strncpy(buf_src,src,length_src-1); /* FIXME check ret */
    strncpy(buf_dst,dst,length_dst-1); /* FIXME check ret */
    length_src -= strlen(buf_src);
    length_dst -= strlen(buf_dst);
    ptr_src = buf_src + strlen(buf_src);
    ptr_dst = buf_dst + strlen(buf_dst);
    *ptr_src++ = '/'; /* no need to add '\0', the memset had already filled buffer with 0 */
    *ptr_dst++ = '/';
    /* TODO read dir and recurse function for all entries */
#ifndef _MSC_VER
    if ((dir=opendir(src))==NULL) return -1;
    while ((entr=readdir(dir))!=NULL) {
      filename = entr->d_name;
      if (entr->d_name[0]=='.') {
        if (strcmp(entr->d_name,".")==0 ||
            strcmp(entr->d_name,"..")==0)
          continue;
      }
#else
    snprintf(dirfilter,2048,"%s/*",src);
    if ((dir = FindFirstFile(dirfilter,&fileData))== INVALID_HANDLE_VALUE) return 0;

    finished = 0;
    while (!finished)
    {
      filename = fileData.cFileName;
      if (filename[0]=='.') {
        if (strcmp(filename,".")==0 ||
            strcmp(filename,"..")==0)
        {
          if (!FindNextFile(dirfilter,&fileData))
          {
            if (GetLastError() == ERROR_NO_MORE_FILES)
              finished = 1;
          }
          continue;
        }
      }
#endif
      strncpy(ptr_src,filename,length_src-1); /* FIXME check ret */
      strncpy(ptr_dst,filename,length_dst-1); /* FIXME check ret */
      ret = _int_rename(buf_src,buf_dst); /* FIXME check ret */
      *ptr_src = '\0';
      *ptr_dst = '\0';
#ifdef _MSC_VER
      if (!FindNextFile(dirfilter,&fileData))
      {
        if (GetLastError() == ERROR_NO_MORE_FILES)
          finished = 1;
      }
#endif
    }
    rmdir(src);
  } else
  if (S_ISLNK(s.st_mode)) {
    char buf[WZD_MAX_PATH+1];
    memset(buf,0,sizeof(buf));
    ret = readlink(src,buf,WZD_MAX_PATH);
    /* FIXME this will work iff the symlink is _relative_ to src
     * otherwise we need to re-build a path from buf
     */
    ret = symlink(buf,dst);
    ret = chmod(dst,s.st_mode & 0xffff);
    unlink(src);
  } else
  if (S_ISREG(s.st_mode)) {
    char buffer[32768];
    int fd_from, fd_to;

    /* FIXME XXX would it be wise to test functions return values ? :-P */
    fd_from = open(src,O_RDONLY);
    fd_to = open(dst,O_CREAT | O_WRONLY); /* XXX will overwite existing files */
    while ( (ret=read(fd_from,buffer,sizeof(buffer))) > 0)
    {
      ret = write(fd_to,buffer,ret);
    }
    close(fd_from);
    close(fd_to);
    unlink(src);
  }

  return 0;
}

/** renames file/dir, if on different fs then moves recursively */
int safe_rename(const char *src, const char *dst)
{
  int ret;

  ret = rename(src,dst);
  if (ret == -1 && errno == EXDEV)
  {
    fprintf(stderr,"Cross device move\n");
    ret = _int_rename(src,dst);
  }
  
  return ret;
}

/** returns 1 if file is hidden: perm,hidden,race_info file, etc */
int is_hidden_file(const char *filename)
{
  const char *ptr;

  ptr = strrchr(filename,'/');
  if (ptr) {
    if (strcasecmp(ptr+1,HARD_PERMFILE)==0) return 1;
    if (*(ptr+1)=='.' && CFG_GET_OPTION(mainConfig,CFG_OPT_HIDE_DOTTED_FILES)) return 1;
    if (mainConfig->dir_message[0]!='\0' && strcasecmp(ptr+1,mainConfig->dir_message)==0) return 1;
  } else {
    if (strcasecmp(filename,HARD_PERMFILE)==0) return 1;
    if (filename[0]=='.' && CFG_GET_OPTION(mainConfig,CFG_OPT_HIDE_DOTTED_FILES)) return 1;
    if (mainConfig->dir_message[0]!='\0' && strcasecmp(filename,mainConfig->dir_message)==0) return 1;
  }
  return 0;
}

/** \return 1 if file is perm file
 * \deprecated Use \ref is_hidden_file
 */
int is_perm_file(const char *filename)
{
  const char *endfile;

  if (filename) {
    endfile = filename + (strlen(filename) - strlen(HARD_PERMFILE));
    if (strlen(filename)>strlen(HARD_PERMFILE)) {
      if (strcasecmp(HARD_PERMFILE,endfile)==0)
        return 1;
    }
  }
  return 0;
}

/** get file last change time */
time_t get_file_ctime(const char *file)
{
  struct stat s;
  if ( stat(file,&s) < 0 ) return (time_t)-1;
  return s.st_ctime;
}

time_t lget_file_ctime(int fd)
{
  struct stat s;
  if ( fstat(fd,&s) < 0 ) return (time_t)-1;
  return s.st_ctime;
}

int server_get_param(const char *name, void *buffer, unsigned int maxlen, wzd_param_t *param_list)
{
  wzd_param_t * param;

  param = param_list;
  while (param) {
    if (strcmp(name,param->name)==0) {
      if (maxlen < param->length) return 2;
      memcpy(buffer,param->param,param->length);
      memset((char*)buffer+param->length,0,maxlen-param->length);
      return 0;
    }
    param = param->next_param;
  }

  return 1;
}

int server_set_param(const char *name, void *data, unsigned int length, wzd_param_t **plist)
{
  wzd_param_t * param, * insert_point;

  if (!plist) return -1;
  if (!name || !data || length==0) return -1;

  param = malloc(sizeof(wzd_param_t));
  /** \todo ensure param with same name is not already in list */
  param->name = strdup(name);
  param->param = malloc(length);
  memcpy(param->param,data,length);
  param->length = length;
  param->next_param = NULL;

  /* tail insertion */
  if (*plist) {
    insert_point = *plist;
    while (insert_point->next_param) insert_point = insert_point->next_param;
    insert_point->next_param = param;
  } else {
    *plist = param;
  }

  return 0;
}

void server_clear_param(wzd_param_t **plist)
{
  wzd_param_t * current, *next;

  if (!plist) return;
  current = *plist;

  while (current) {
    next = current->next_param;

    if (current->name) free(current->name);
    if (current->param) free(current->param);

    free(current);

    current = next;
  }
}

/** Checks server status */
int server_diagnose(void)
{
  if (!mainConfig) return -1;
  if (mainConfig->serverstop != 0) return -1;

  /** \todo implement more checks */

  return 0;
}


#define WORK_BUF_LEN	8192

/** \brief allocate buffer big enough to format arguments with printf
 *
 * Returned string must be freed with \ref wzd_free
 */
char * safe_vsnprintf(const char *format, va_list ap)
{
  int size = WORK_BUF_LEN;
  char * buffer = wzd_malloc(size);
  int result;

  result = vsnprintf(buffer, size, format, ap);
  if (result >= size)
  {
    buffer = wzd_realloc(buffer, result+1);
    result = vsnprintf(buffer, result+1, format, ap);
  }

  return buffer;
}

/** if code is negative, the last line will NOT be formatted as the end
 * of a normal ftp reply
 */
void v_format_message(int code, unsigned int *plength, char **pbuffer, va_list argptr)
{
  const char * token, *token2;
  const char * msg;
  char *ptr;
  unsigned int size;
  char work_buf[WORK_BUF_LEN];
  char cookies_buf[WORK_BUF_LEN];
  char is_terminated=1;
  int must_free;
  int ret;
  wzd_user_t * user;
  wzd_group_t * group;
  wzd_context_t * context;
  /* XXX 4096 should ALWAYS be >= length */
  char * old_buffer;
  unsigned int length;
  char * buffer;

#if 0
#ifdef DEBUG
  if (length > WORK_BUF_LEN) {
    out_err(LEVEL_HIGH,"*** WARNING *** message too long, will be truncated\n");
    length = WORK_BUF_LEN;
  }
#endif
#endif

  if (code < 0) {
    is_terminated = 0;
    code = abs(code);
  }

  msg = getMessage(code,&must_free);
  ptr = work_buf;

  context = GetMyContext();
  user = GetUserByID(context->userid);
  group = user ? GetGroupByID(user->groups[0]) : NULL;

  /* first, replace cookies */
  ret = cookie_parse_buffer(msg, user, group, context, cookies_buf, WORK_BUF_LEN);
  
  /* then format message */
  vsnprintf(work_buf,WORK_BUF_LEN,cookies_buf,argptr);

  if (must_free) {
    free ( (char*)msg );
  }

  length = (strlen(work_buf)*150)/100 + 11; /* empirical ratio: after/before interpreting cookies */
  buffer = malloc(length);
  *pbuffer = buffer;
  *plength = length;
  old_buffer = buffer;

  /* adjust size, we will need more space to put the code and \r\n */
  length -= 7;

  /* remove trailing garbage */
  {
    char * ptr = work_buf;
    unsigned int length = strlen(ptr);
    while ( *(ptr+length-1) == '\r' || *(ptr+length-1) == '\n') {
       *(ptr+length-1) = '\0';
       length--;
    }
  }
  
  if (!strpbrk(work_buf,"\r\n")) { /* simple case, msg on one line */
    if (is_terminated)
      snprintf(buffer,length,"%d %s\r\n",code,work_buf);
    else
      snprintf(buffer,length,"%d-%s\r\n",code,work_buf);
  }
  else { /* funnier, multiline */
    /* find first line break */
    token = strtok_r(work_buf,"\r\n",&ptr);

    /* first line begins by 123- */
    snprintf(buffer,length,"%d-%s\r\n",code,token);
    size = strlen(token);
    length = length - size - 6;
    buffer = buffer + size + 6;

    /* next line */
    token = strtok_r(NULL,"\r\n",&ptr);

    while (1) {
      size = strlen(token);
      /* find next token */
      token2 = strtok_r(NULL,"\r\n",&ptr);
      if (!token2) {
        /* check size for BOF here ! */
/*fprintf(stderr,"last: remaining %d (written %d, wants %d)\n",length,strlen(old_buffer),size+6);*/
        if (size+6 >= length) {
          out_err(LEVEL_CRITICAL,"Mayday, we're running into a BOF (%s:%d)\n",__FILE__,__LINE__);
          snprintf(old_buffer,20,"%d Truncated\r\n",code);
          break;
        }
        if (is_terminated) /* no more line, remove the - */
          snprintf(buffer,length,"%d %s\r\n",code,token);
        else
          snprintf(buffer,length,"%d-%s\r\n",code,token);
        break;
      }
      /* check remaining size */
      /* check size for BOF here ! */
/*fprintf(stderr,"remaining %d (written %d, wants %d)\n",length,strlen(old_buffer),size+2);*/
      if (size+2 >= length) {
        out_err(LEVEL_CRITICAL,"Mayday, we're running into a BOF (%s:%d)\n",__FILE__,__LINE__);
        snprintf(old_buffer,20,"%d Truncated\r\n",code);
        break;
      }
      /* copy line into out buffer */
      snprintf(buffer,length,"%s\r\n",token);
      /* adjust length */
      length = length - size - 2;
      /* adjust buffer position */
      buffer = buffer + size + 2;
      /* loop */
      token = token2;
    }
  }
}

void format_message(int code, unsigned int *plength, char **pbuffer, ...)
{
  va_list argptr;

  va_start(argptr,pbuffer); /* note: ansi compatible version of va_start */

  v_format_message(code,plength,pbuffer,argptr);
  va_end (argptr);
}


/************* BANDWIDTH LIMITATION *********/

unsigned long get_bandwidth(unsigned long *dl, unsigned long *ul)
{
  unsigned long ul_bandwidth=0, dl_bandwidth=0;
  unsigned int i;
  unsigned int id;
  wzd_user_t * user;
  wzd_context_t * context;

  for (i=0; i<HARD_USERLIMIT; i++) {
    if (context_list[i].magic == CONTEXT_MAGIC) {
      context = &context_list[i];
      id = context_list[i].userid;
      user = GetUserByID(id);
      if (strncasecmp(context->last_command,"retr",4)==0) {
        dl_bandwidth += (unsigned long)context->current_dl_limiter.current_speed;
      }
      if (strncasecmp(context->last_command,"stor",4)==0) {
        ul_bandwidth += (unsigned long)context->current_ul_limiter.current_speed;
      }
    } /* if CONTEXT_MAGIC */
  } /* forall contexts */

  if (dl) *dl = dl_bandwidth;
  if (ul) *ul = ul_bandwidth;

  return (dl_bandwidth+ul_bandwidth);
}


wzd_bw_limiter * limiter_new(int maxspeed)
{
  wzd_bw_limiter *l_new;
#ifndef _MSC_VER
  struct timezone tz;
#endif

  l_new = malloc(sizeof(wzd_bw_limiter));
  l_new->maxspeed = maxspeed;
  l_new->bytes_transfered = 0;
#ifndef _MSC_VER
  gettimeofday(&(l_new->current_time),&tz);
#else
  _ftime(&(l_new->current_time));
#endif

  return l_new;
}

void limiter_add_bytes(wzd_bw_limiter *l, wzd_mutex_t * mutex, int byte_count, int force_check)
{
#ifndef WIN32 /* FIXME VISUAL */
  struct timeval tv;
  struct timezone tz;
#else
  struct _timeb tb;
#endif
  unsigned long elapsed;
  unsigned long pause_time;
/*  double rate_ratio;*/
  unsigned int bw_rate;

  if (!l) return;
/*  if (l->maxspeed == 0) return;*/

wzd_mutex_lock(mutex);
  l->bytes_transfered += byte_count;
wzd_mutex_unlock(mutex);

  /* if at least 1 second of data is downloaded, assess the situation
   * and determine how much time to wait */
/*  if ( (l->bytes_transfered >= l->maxspeed) || force_check )
  {*/
#ifndef _MSC_VER
    gettimeofday( &tv, &tz );
    elapsed = (tv.tv_sec - l->current_time.tv_sec) * 1000000;
    elapsed += (tv.tv_usec - l->current_time.tv_usec);
#else
    _ftime(&tb);
    elapsed = (tb.time - l->current_time.time) * 1000000;
    elapsed += (tb.millitm - l->current_time.millitm) * 1000;
#endif
    if (elapsed==0) elapsed=1;
/*    bw_rate = (unsigned int)((double)l->bytes_transfered / elapsed);*/
    l->current_speed = (float)( (l->bytes_transfered * 1000000.f) / elapsed);
    bw_rate = (unsigned int)l->current_speed;
/*  }*/
  if (l->maxspeed == 0 || bw_rate <= l->maxspeed) {
    return;
  }
/*fprintf(stderr,"received: %d\n",l->bytes_transfered);*/
/*fprintf(stderr,"speed: %d max:%d\n",bw_rate,l->maxspeed);*/
/*  rate_ratio = (double)bw_rate / (double)l->maxspeed;*/
/*  pause_time = (rate_ratio - (double)1)*elapsed;*/
  pause_time = (bw_rate-l->maxspeed) * (elapsed / l->maxspeed);
#ifndef _MSC_VER
  usleep (pause_time);
#else
  Sleep((unsigned long)(pause_time / (double)1000));
#endif
/*  gettimeofday( &tv, &tz );
  l->current_time.tv_sec = tv.tv_sec;
  l->current_time.tv_usec = tv.tv_usec;
  l->bytes_transfered = 0;*/
}

void limiter_free(wzd_bw_limiter *l)
{
  if (l)
    free(l);
}

/** print_file : read file, replace cookies and prints it
 * header (200-) MUST have been sent, and end (200 ) is NOT sent)
 */
int print_file(const char *filename, int code, void * void_context)
{
  wzd_context_t * context = void_context;
  void * param;
  char complete_buffer[1024];
  char * buffer = complete_buffer + 4;
  int ret;
  FILE *fp;

  if (strlen(filename)==0) {
    out_log(LEVEL_HIGH,"Trying to print file (null) with code %d\n",code);
    return 1;
  }
  fp = fopen(filename,"r");
  if (!fp) {
    out_log(LEVEL_HIGH,"Problem opening file %s (code %d)\n",filename,code);
    return 1;
  }
  
  snprintf(complete_buffer,5,"%3d-",code);
  if ( (fgets(buffer,1018,fp))==NULL ) {
    out_log(LEVEL_HIGH,"File %s is empty (code %d)\n",filename,code);
    return 1;
  }

  param = NULL;
  do {
    ret = cookie_parse_buffer(buffer,NULL,NULL,context,NULL,0); /* TODO test ret */
  /* XXX FIXME TODO */
/*    out_log(LEVEL_HIGH,"READ: %s\n",complete_buffer);*/
    send_message_raw(complete_buffer,context);
  } while ( (fgets(buffer,1018,fp)) != NULL);

  return 0;
}

/** used to translate text to binary word for rights */
unsigned long right_text2word(const char * text)
{
  unsigned long word=0;
  const char * ptr = text;

  do {
    while ( (*ptr)==' ' || (*ptr)=='\t' || (*ptr)=='+' || (*ptr)=='|' ) {
      ptr++;
    }
    if (*ptr == '\0' || *ptr == '\r' || *ptr=='\n') break;

    if (strncasecmp(ptr,"RIGHT_LIST",strlen("RIGHT_LIST"))==0) {
     word += RIGHT_LIST;
     ptr += strlen("RIGHT_LIST");
    } else
    if (strncasecmp(ptr,"RIGHT_RETR",strlen("RIGHT_RETR"))==0) {
     word += RIGHT_RETR;
     ptr += strlen("RIGHT_RETR");
    } else
    if (strncasecmp(ptr,"RIGHT_STOR",strlen("RIGHT_STOR"))==0) {
     word += RIGHT_STOR;
     ptr += strlen("RIGHT_STOR");
    } else
    if (strncasecmp(ptr,"RIGHT_CWD",strlen("RIGHT_CWD"))==0) {
     word += RIGHT_CWD;
     ptr += strlen("RIGHT_CWD");
    } else
    if (strncasecmp(ptr,"RIGHT_RNFR",strlen("RIGHT_RNFR"))==0) {
     word += RIGHT_RNFR;
     ptr += strlen("RIGHT_RNFR");
    } else
    {
      return 0;
    }
  } while (*ptr);

  return word;
}


/** dst can be composed of wildcards */
int my_str_compare(const char * src, const char *dst)
{
  const char * ptr_src;
  const char * ptr_dst;
  char c;

  ptr_src = src;
  ptr_dst = dst;

  while ((c = *ptr_src)) {
    if (*ptr_dst=='*') { /* wildcard * */
      if (*(ptr_dst+1)=='\0') return 1; /* terminated with a *, ok */
      ptr_dst++;
      c = *ptr_dst;
      while (*ptr_src && c!=*ptr_src)
        ptr_src++;
      if (!*ptr_src) break; /* try next ip */
      continue;
    }
    if (*ptr_dst=='?') { /* wildcard ?, match one char and continue */
      ptr_src++;
      ptr_dst++;
      continue;
    }
    if (*ptr_dst!=c) break; /* try next ip */
    ptr_dst++;
    ptr_src++;
  }

  /* test if checking was complete */
  if (*ptr_dst == '\0' || (*ptr_dst=='*' && *(ptr_dst+1)=='\0') ) return 1;

  return 0;
}

/* lower only characters in A-Z ! */
void ascii_lower(char * s, unsigned int length)
{
  register unsigned int i=0;
  while (i<length) {
    if (s[i] >= 'A' && s[i] <= 'Z') {
      s[i] |= 0x20;
    }
    i++;
  }
}

/** \brief read next token
 * \return a pointer to the next token, or NULL if not found, or if there is \
 * only whitespaces, or if quotes are unbalanced
 * Read next token separated by a whitespace, except if string begins
 * with a ' or ", in this case it searches the matching character.
 * Note: input string is modified as a \0 is written.
 */
char * read_token(char *s, char **endptr)
{
  char *tok, c;
  char sep[2];

  if (s == NULL && (s = *endptr) == NULL)
  {
    return NULL;
  }

  /* skip leading spaces */
  while ( (c = *s) && isspace(c) ) s++;
  if (*s == '\0') /* only whitespaces */
  { *endptr = NULL; return NULL; }

  /* search for any whitespace or quote */
  tok = strpbrk(s, " \t\r\n\"'");

  if (!tok) {
    /* nothing, we return string */
    *endptr = NULL;
    return s;
  }

  /* the first char is a quote ? */
  if (*tok == '"' || *tok == '\'') {
    sep[0] = *tok;
    sep[1] = '\0';
    if (!strchr(tok+1,*tok)) { /* unbalanced quotes */
      *endptr = NULL;
      return NULL;
    }
    /** \bug we can't have escaped characters */
    return strtok_r(tok, sep, endptr);
  }

  /* normal case, we search a whitespace */
  return strtok_r(s, " \t\r\n", endptr);
}

/* replace all \ with / and lower string */
void win_normalize(char * s, unsigned int length, unsigned int lower)
{
  register unsigned int i=0;
  while (i<length) {
    if (lower && (s[i] >= 'A' && s[i] <= 'Z')) {
      s[i] |= 0x20;
    }
    if (s[i] == '\\') s[i] = '/';
    i++;
  }
}



/* \return 0 if ok, -1 if error, 1 if trying to kill myself */
int kill_child_new(unsigned long pid, wzd_context_t * context)
{
  int found=0;
  int i;

  /* preliminary check: i can't kill myself */
  if (pid==context->pid_child) return 1;

  /* checks that pid is really one of the users */
  for (i=0; i<HARD_USERLIMIT; i++)
  {
    if (context_list[i].magic == CONTEXT_MAGIC && context_list[i].pid_child == pid) { found = 1; break; }
  }
  if (!found) return -1;

  /* \todo XXX FIXME remove/fix test !! */
  context_list[i].exitclient = 1;
/*  ret = TerminateThread((HANDLE)pid,0);*/
/*  ret = pthread_cancel(pid);*/

  return 0;
}





short is_user_in_group(wzd_user_t * user, unsigned int gid)
{
  unsigned int i;

  if (!user || user->group_num<=0) return -1;
  for (i=0; i<user->group_num; i++)
    if (gid==user->groups[i]) return 1;
  return 0;
}


int group_remove_user(wzd_user_t * user, unsigned int gid)
{
  unsigned int i;
  unsigned int idx=(unsigned int)-1;

  if (!user || user->group_num<=0) return -1;
  for (i=0; i<user->group_num; i++)
  {
    if (user->groups[i]==gid) {
      idx = i;
    }
  }
  if (idx==(unsigned int)-1) return -1;

  for (i=idx; i<user->group_num; i++)
  {
    user->groups[i] = user->groups[i+1];
  }
  user->group_num--;
  
  return 0;
}


/** wrappers to context list */
void * GetMyContext(void)
{
  int i;
#ifdef WZD_MULTIPROCESS
  wzd_context_t * context=NULL;
  pid_t pid;

  pid = getpid();

  context = &context_list[0];
  /* TODO search context list and cleanup context */
  for (i=0; i<HARD_USERLIMIT; i++)
  {
    if (context_list[i].magic == CONTEXT_MAGIC && context_list[i].pid_child == pid) {
      return (&context_list[i]);
    }
  }

#elif defined(WZD_MULTITHREAD)
  wzd_context_t * context=NULL;

#ifdef _MSC_VER
  unsigned long thread_id;

  thread_id = (unsigned long)GetCurrentThreadId();
  context = &context_list[0];
  /* TODO search context list and cleanup context */
  for (i=0; i<HARD_USERLIMIT; i++)
  {
    if (context_list[i].magic == CONTEXT_MAGIC && context_list[i].thread_id == thread_id) {
      return (&context_list[i]);
    }
  }
#else /* _MSC_VER */
  pthread_t thread_id;

  thread_id = pthread_self();
  context = &context_list[0];
  /* TODO search context list and cleanup context */
  for (i=0; i<HARD_USERLIMIT; i++)
  {
    if (context_list[i].magic == CONTEXT_MAGIC &&
      pthread_equal((pthread_t)context_list[i].thread_id,thread_id)) {
        return (&context_list[i]);
    }
  }
#endif /* _MSC_VER */

#else
  /* we have only one process */
  for (i=0; i<HARD_USERLIMIT; i++)
  {
    if (context_list[i].magic == CONTEXT_MAGIC)
      return (&context_list[i]);
  }
#endif /* WZD_MULTITHREAD */

  return NULL;
}

