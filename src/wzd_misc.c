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

#ifdef __CYGWIN__
#include <w32api/windows.h>
#endif /* __CYGWIN__ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
/* for intel compiler */
#ifdef __INTEL_COMPILER
# define __SWORD_TYPE   int
#endif /* __INTEL_COMPILER */
#include <sys/vfs.h> /* statfs */

/* speed up compilation */
#define SSL     void
#define SSL_CTX void

#include "wzd_structs.h"

#include "wzd_log.h"
#include "wzd_misc.h"
#include "wzd_messages.h"
#include "wzd_ServerThread.h"

#ifdef __CYGWIN__
#define LONGBITS  0x20
#else
/* needed  for LONGBITS */
#include <values.h>
#endif

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

char *time_to_str(time_t time)
{ /* This support functionw as written by George Shearer (Dr_Delete) */

  static char workstr[100];
  unsigned short int days=(time/86400),hours,mins,secs;
  hours=((time-(days*86400))/3600);
  mins=((time-(days*86400)-(hours*3600))/60);
  secs=(time-(days*86400)-(hours*3600)-(mins*60));

  workstr[0]=(char)0;
  if(days)
    sprintf(workstr,"%dd",days);
  if(hours)
    sprintf(workstr,"%s%s%dh",workstr,(workstr[0])?", ":"",hours);
  if(mins)
    sprintf(workstr,"%s%s%dm",workstr,(workstr[0])?", ":"",mins);
  if(secs)
    sprintf(workstr,"%s%s%ds",workstr,(workstr[0])?", ":"",secs);
  if (!days && !hours && !mins && !secs)
    sprintf(workstr,"0 seconds");

  return(workstr);
}

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

/** returns system ip on specifed interface (e.g eth0) */
int get_system_ip(const char * itface, struct in_addr * ina)
{
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
  printf("IP: %s\n",inet_ntoa(*ina));

  close(s);
  return 0;
}

/** returns info on device containing dir/file */
int get_device_info(const char *file, long * f_type, long * f_bsize, long * f_blocks, long *f_free)
{
  struct statfs fs;

  if (statfs(file,&fs)==0) {
    if (f_bsize) *f_bsize = fs.f_bsize;
    if (f_type) *f_type = fs.f_type;
    if (f_blocks) *f_blocks = fs.f_blocks;
    if (f_free) *f_free = fs.f_bfree;
    return 0;
  }
  return -1;
}

/** internal fct, rename files by copying data */
int _int_rename(const char * src, const char *dst)
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
    DIR *dir;
    struct dirent *entr;
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
    if ((dir=opendir(src))==NULL) return -1;
    while ((entr=readdir(dir))!=NULL) {
      if (entr->d_name[0]=='.') {
	if (strcmp(entr->d_name,".")==0 ||
	    strcmp(entr->d_name,"..")==0)
	  continue;
      }
      strncpy(ptr_src,entr->d_name,length_src-1); /* FIXME check ret */
      strncpy(ptr_dst,entr->d_name,length_dst-1); /* FIXME check ret */
      ret = _int_rename(buf_src,buf_dst); /* FIXME check ret */
      *ptr_src = '\0';
      *ptr_dst = '\0';
    }
    rmdir(src);
  } else
  if (S_ISLNK(s.st_mode)) {
    char buf[2048];
    memset(buf,0,2048);
    ret = readlink(src,buf,2047);
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
    while ( (ret=read(fd_from,buffer,32768)) > 0)
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

/** returns 1 if file is perm file */
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

#define WORK_BUF_LEN	8192

/** if code is negative, the last line will NOT be formatted as the end
 * of a normal ftp reply
 */
void v_format_message(int code, unsigned int length, char *buffer, va_list argptr)
{
  const char * token, *token2;
  const char * msg;
  char *ptr;
  unsigned int size;
  char work_buf[WORK_BUF_LEN];
  char is_terminated=1;
  /* XXX 4096 should ALWAYS be >= length */

#ifdef DEBUG
  if (length > WORK_BUF_LEN) {
    fprintf(stderr,"*** WARNING *** message too long, will be truncated\n");
    length = WORK_BUF_LEN;
  }
#endif

  if (code < 0) {
    is_terminated = 0;
    code = abs(code);
  }

  msg = getMessage(code);
  ptr = work_buf;

  /* first, format message */
  vsnprintf(work_buf,WORK_BUF_LEN,msg,argptr);

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
	if (is_terminated) /* no more line, remove the - */
	  snprintf(buffer,length,"%d %s\r\n",code,token);
	else
	  snprintf(buffer,length,"%d-%s\r\n",code,token);
        break;
      }
      /* copy line into out buffer */
      snprintf(buffer,length,"%s\r\n",token);
      /* adjust length */
      length = length - size - 2;
      /* check remaining size */
      /* adjust buffer position */
      buffer = buffer + size + 2;
      /* loop */
      token = token2;
    }
  }
}

void format_message(int code, unsigned int length, char *buffer, ...)
{
  va_list argptr;

  va_start(argptr,buffer); /* note: ansi compatible version of va_start */

  v_format_message(code,length,buffer,argptr);
}


/************* BANDWIDTH LIMITATION *********/
wzd_bw_limiter * limiter_new(int maxspeed)
{
  wzd_bw_limiter *l_new;
  struct timezone tz;

  l_new = malloc(sizeof(wzd_bw_limiter));
  l_new->maxspeed = maxspeed;
  l_new->bytes_transfered = 0;
  gettimeofday(&(l_new->current_time),&tz);

  return l_new;
}

void limiter_add_bytes(wzd_bw_limiter *l, wzd_sem_t sem, int byte_count, int force_check)
{
  struct timeval tv;
  struct timezone tz;
  double elapsed;
  double pause_time;
  double rate_ratio;
  unsigned int bw_rate;

  if (!l) return;
/*  if (l->maxspeed == 0) return;*/

wzd_sem_lock(sem,1);
  l->bytes_transfered += byte_count;
wzd_sem_unlock(sem,1);

  /* if at least 1 second of data is downloaded, assess the situation
   * and determine how much time to wait */
/*  if ( (l->bytes_transfered >= l->maxspeed) || force_check )
  {*/
    gettimeofday( &tv, &tz );
    elapsed = (double) (tv.tv_sec - l->current_time.tv_sec);
    elapsed += (double) (tv.tv_usec - l->current_time.tv_usec) / (double)1000000;
    if (elapsed==(double)0) elapsed=0.01;
/*    bw_rate = (unsigned int)((double)l->bytes_transfered / elapsed);*/
    l->current_speed = (float)((double)l->bytes_transfered / elapsed);
    bw_rate = (unsigned int)l->current_speed;
/*  }*/
  if (l->maxspeed == 0 || bw_rate <= l->maxspeed) {
    return;
  }
  rate_ratio = (double)bw_rate / (double)l->maxspeed;
  pause_time = (rate_ratio - (double)1)*elapsed;
  usleep ((unsigned long)(pause_time * (double)1000000));
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

typedef enum {
  COOKIE_MY,
  COOKIE_USER,
  COOKIE_GROUP
} wzd_cookie_t;

/* cookies */
int cookies_replace(char * buffer, unsigned int buffersize, void * void_param, void * void_context)
{
  wzd_cookie_t cookie_type;
  unsigned long length=0;
  wzd_context_t * context = void_context;
  char work_buffer[4096];
  char tmp_buffer[4096];
  char *srcptr, *dstptr;
  unsigned int bytes_written=0;
  char * cookie;
  unsigned int cookielength;
  unsigned int l;
  char c;
  wzd_context_t * param_context=NULL;
  wzd_user_t * user = NULL;
  wzd_user_t * context_user = NULL;
  wzd_group_t * group;

  if (buffersize > 4095) {
#ifdef DEBUG
    fprintf(stderr,"BUFFER SIZE too long !!\n");
#endif
    return -1;
  }

  memset(work_buffer,0,4096);
  srcptr = buffer;
  dstptr = work_buffer;

  while ( (c=*srcptr++) != '\0' ) {
    if ( c != '%' ) {
      *dstptr++ = c;
      bytes_written++;
      if (bytes_written == buffersize) {
        memcpy(buffer,work_buffer,buffersize);
        return 1;
      }
      continue;
    }

    if ( *srcptr == '%' ) {
      *dstptr++ = c;
      srcptr++;
      bytes_written++;
      continue;
    }

    length = 0;

    /* test if a number is written here - is the exact length the cookie will have */
    if ( *srcptr>='0' && *srcptr <= '9') {
      char *ptr;
      length = strtol(srcptr,&ptr,10);
      if (*ptr != '.') {
	length = 0;
      }
      srcptr = ptr + 1;
    }

    cookielength = 0;
    cookie = NULL;

    if (strncmp(srcptr,"my",2)==0)
    { cookie_type=COOKIE_MY; param_context=context; srcptr += 2; }
    else if (strncmp(srcptr,"user",4)==0)
    { cookie_type=COOKIE_USER; param_context=void_param; srcptr += 4; }
    else if (strncmp(srcptr,"group",5)==0)
    {
      cookie_type=COOKIE_GROUP;
      param_context=void_param;
      group = GetGroupByID(param_context->userid);
        /* userid contains the gid ... Yes, I know ! */
      if (!group) { /* we really have a problem */
	return 1;
      }
      srcptr += 5;
    }

    if (param_context == NULL) {
      /* happens when using %username and void_param is not correctly set */
      return 1;
    }

    if (mainConfig->backend.backend_storage == 0) {
      user = GetUserByID(param_context->userid);
      context_user = GetUserByID(context->userid);
#if BACKEND_STORAGE
    } else {
      user = &param_context->user;
      context_user = &context->user;
#endif
    }

    if (param_context) {
      /* name */
      if (strncmp(srcptr,"name",4)==0) {
	if (cookie_type==COOKIE_GROUP)
	  cookie = group->groupname;
	else
	  cookie = user->username;
        cookielength = strlen(cookie);
        srcptr += 4; /* strlen("name"); */
      } else
      /* ip_allow */
      if (strncmp(srcptr,"ip_allow",8)==0) {
	char *endptr;
        srcptr += 8; /* strlen("ip_allow"); */
	l = strtoul(srcptr,&endptr,10);
	if (endptr-srcptr > 0) {
	  if (cookie_type==COOKIE_GROUP)
	  {
	    if (l < HARD_IP_PER_GROUP) {
	      strncpy(tmp_buffer,group->ip_allowed[l],4095);
	    } else {
	      snprintf(tmp_buffer,4096,"Invalid ip index %u",l);
	    }
	    srcptr = endptr;
	  } else { /* !COOKIE_GROUP */
	    if (l < HARD_IP_PER_USER) {
	      strncpy(tmp_buffer,user->ip_allowed[l],4095);
	    } else {
	      snprintf(tmp_buffer,4096,"Invalid ip index %u",l);
	    }
	    srcptr = endptr;
	  }
	} else {
	  snprintf(tmp_buffer,4096,"Invalid ip index");
	}
	cookie = tmp_buffer;
	cookielength = strlen(cookie);
      } else
      /* ip */
      if (strncmp(srcptr,"ip",2)==0) {
        if (context_user->flags && strchr(context_user->flags,FLAG_SEE_IP)) {
        snprintf(tmp_buffer,4096,"%d.%d.%d.%d",param_context->hostip[0],
  	  param_context->hostip[1],param_context->hostip[2],
          param_context->hostip[3]);
        } else { /* not allowed to see */
          strcpy(tmp_buffer,"xxx.xxx.xxx.xxx");
        }
        cookie = tmp_buffer;
        cookielength = strlen(cookie);
        srcptr += 2; /* strlen("ip"); */
      } else
      /* flags */
      if (strncmp(srcptr,"flags",5)==0) {
	if (user->flags && strlen(user->flags)>0) {
	  strncpy(tmp_buffer,user->flags,MAX_FLAGS_NUM);
	} else {
	  strcpy(tmp_buffer,"no flags");
	}
	cookie = tmp_buffer;
	cookielength = strlen(cookie);
	srcptr += 5; /* strlen("flags"); */
      } else
      /* group */
      if (strncmp(srcptr,"group",5)==0) {
        wzd_group_t group, *gptr;
	int gid;
	int ret;
        if ( (user->group_num > 0)) {
          ret = backend_find_group(user->groups[0],&group,&gid);
	  if (mainConfig->backend.backend_storage==0) {
	    gptr = GetGroupByID(ret);
	  } else {
	    gptr = &group;
	  }
          snprintf(tmp_buffer,4096,"%s",group.groupname);
        } else {
          strcpy(tmp_buffer,"nogroup");
        }
        cookie = tmp_buffer;
        cookielength = strlen(cookie);
        srcptr += 5; /* strlen("group"); */
      } else
      /* home */
      if (strncmp(srcptr,"home",4)==0) {
        if (context_user->flags && strchr(context_user->flags,FLAG_SEE_HOME)) {
	  if (cookie_type==COOKIE_GROUP)
	    cookie = group->defaultpath;
	  else
	    cookie = user->rootpath;
        } else { /* user not allowed to see */
          strcpy(tmp_buffer,"- some where -");
          cookie = tmp_buffer;
        }
        cookielength = strlen(cookie);
        srcptr += 4; /* strlen("home"); */
      } else
      /* lastcmd */
      if (strncmp(srcptr,"lastcmd",7)==0) {
	strncpy(tmp_buffer,param_context->last_command,4095);
	/* modify special commands, to not appear explicit */
	if (strncasecmp(tmp_buffer,"site",4)==0) {
/*	  char * ptr;
	  ptr = strpbrk(tmp_buffer+5," \t");
	  if (ptr) {
	    memset(ptr+1,'x',strlen(tmp_buffer)-(ptr-tmp_buffer+1));
	  }*/
	  strcpy(tmp_buffer,"SITE command");
	}
	else if (strncasecmp(tmp_buffer,"retr",4)==0) {
	  char *fname;
	  fname = strrchr(param_context->current_action.arg,'/')+1;
	  if (fname==NULL || *fname=='\0') fname = param_context->current_action.arg;
	  snprintf(tmp_buffer,4095,"DL: %s",fname);
	}
	else if (strncasecmp(tmp_buffer,"stor",4)==0) {
	  char *fname;
	  fname = strrchr(param_context->current_action.arg,'/')+1;
	  if (fname==NULL || *fname=='\0') fname = param_context->current_action.arg;
	  snprintf(tmp_buffer,4095,"UL: %s",fname);
	}
        cookie = tmp_buffer;
        cookielength = strlen(cookie);
        srcptr += 7; /* strlen("lastcmd"); */
      } else
      /* leechslots */
      if (strncmp(srcptr,"leechslots",10)==0) {
	snprintf(tmp_buffer,4096,"%hu",user->leech_slots);
	cookie = tmp_buffer;
        cookielength = strlen(cookie);
        srcptr += 10; /* strlen("leechslots"); */
      } else
      /* maxdl */
      if (strncmp(srcptr,"maxdl",5)==0) {
	if (cookie_type==COOKIE_GROUP)
	  snprintf(tmp_buffer,4096,"%ld",group->max_dl_speed);
	else
	  snprintf(tmp_buffer,4096,"%ld",user->max_dl_speed);
	cookie = tmp_buffer;
        cookielength = strlen(cookie);
        srcptr += 5; /* strlen("maxdl"); */
      } else
      /* maxidle */
      if (strncmp(srcptr,"maxidle",7)==0) {
	if (cookie_type==COOKIE_GROUP)
	  snprintf(tmp_buffer,4096,"%ld",group->max_idle_time);
	else
	  snprintf(tmp_buffer,4096,"%ld",user->max_idle_time);
	cookie = tmp_buffer;
        cookielength = strlen(cookie);
        srcptr += 7; /* strlen("maxidle"); */
      } else
      /* maxul */
      if (strncmp(srcptr,"maxul",5)==0) {
	if (cookie_type==COOKIE_GROUP)
	  snprintf(tmp_buffer,4096,"%ld",group->max_ul_speed);
	else
	  snprintf(tmp_buffer,4096,"%ld",user->max_ul_speed);
	cookie = tmp_buffer;
        cookielength = strlen(cookie);
        srcptr += 5; /* strlen("maxul"); */
      } else
      /* num_logins */
      if (strncmp(srcptr,"num_logins",10)==0) {
	snprintf(tmp_buffer,4096,"%d",user->num_logins);
	cookie = tmp_buffer;
        cookielength = strlen(cookie);
        srcptr += 10; /* strlen("num_logins"); */
      } else
#ifdef WZD_MULTIPROCESS
      /* pid */
      if (strncmp(srcptr,"pid",3)==0) {
	if (context_user->flags && strchr(context_user->flags,FLAG_SITEOP)) {
	  snprintf(tmp_buffer,4096,"%ld",param_context->pid_child);
	  cookie = tmp_buffer;
	  cookielength = strlen(cookie);
	  srcptr += 3; /* strlen("pid"); */
	}
      } else
#endif /* WZD_MULTIPROCESS */
#ifdef WZD_MULTITHREAD
      /* pid */
      if (strncmp(srcptr,"pid",3)==0) {
	if (context_user->flags && strchr(context_user->flags,FLAG_SITEOP)) {
	  snprintf(tmp_buffer,4096,"%ld",param_context->pid_child);
	  cookie = tmp_buffer;
	  cookielength = strlen(cookie);
	  srcptr += 3; /* strlen("pid"); */
	}
      } else
#endif /* WZD_MULTIPROCESS */
      /* ratio */
      if (strncmp(srcptr,"ratio",5)==0) {
	if (cookie_type==COOKIE_GROUP)
	{
	  if (group->ratio)
	    snprintf(tmp_buffer,4096,"1:%u",group->ratio);
	  else
	    strcpy(tmp_buffer,"unlimited");
	}
	else
	{
	  if (user->ratio)
	    snprintf(tmp_buffer,4096,"1:%u",user->ratio);
	  else
	    strcpy(tmp_buffer,"unlimited");
	}
	cookie = tmp_buffer;
        cookielength = strlen(cookie);
        srcptr += 5; /* strlen("ratio"); */
      } else
      /* slots */
      if (strncmp(srcptr,"slots",5)==0) {
	snprintf(tmp_buffer,4096,"%hu",user->user_slots);
	cookie = tmp_buffer;
        cookielength = strlen(cookie);
        srcptr += 5; /* strlen("slots"); */
      } else
      /* speed */
      if (strncmp(srcptr,"speed",5)==0) {
        if (strncasecmp(param_context->last_command,"retr",4)==0) {
          snprintf(tmp_buffer,4095,"%.1f kB/s",param_context->current_dl_limiter.current_speed/1024.f);
        }
        else {
	  if (strncasecmp(param_context->last_command,"stor",4)==0) {
            snprintf(tmp_buffer,4095,"%.1f kB/s",param_context->current_ul_limiter.current_speed/1024.f);
          }
          else {
	    tmp_buffer[0] = '\0'; /* if not DL/UL, do not show speed */
	  }
	}
        cookie = tmp_buffer;
        cookielength = strlen(cookie);
        srcptr += 5; /* strlen("speed"); */
      } else
      /* tag */
      if (strncmp(srcptr,"tag",3)==0) {
	if (user->flags && strchr(user->flags,FLAG_DELETED)) {
	  strcpy(tmp_buffer,"**DELETED**");
	  cookie = tmp_buffer;
	} else {
	  if (strlen(user->tagline) > 0) {
	    cookie = user->tagline;
	  } else {
	    strcpy(tmp_buffer,"no tagline set");
	    cookie = tmp_buffer;
	  }
	}
        cookielength = strlen(cookie);
        srcptr += 3; /* strlen("tag"); */
      } else
      /* total_dl, total_dl2 */
      if (strncmp(srcptr,"total_dl",8)==0) {
	float val;
	char c;
	short convert=0;
	if (*(srcptr+8)=='2') convert=1;
	if (cookie_type==COOKIE_GROUP)
	{
	  int gid, i;
	  unsigned long long total;
	  wzd_user_t * loop_user;
	  /* TODO iterate through users and sum */
	  gid = param_context->userid;
	  total = 0;
	  for (i=0; i<HARD_DEF_USER_MAX; i++)
	  {
	    loop_user = GetUserByID(i);
	    if (!loop_user) continue;
	    if (is_user_in_group(loop_user,gid)==1)
	    {
	      total += loop_user->bytes_dl_total;
	    }
	  }
	  if (convert) {
	    val = (float)total;
	    bytes_to_unit(&val,&c);
	    snprintf(tmp_buffer,4096,"%.2f %c",val,c);
	  } else
	    snprintf(tmp_buffer,4096,"%lld",total);
	} else {
	  if (convert) {
	    val = (float)user->bytes_dl_total;
	    bytes_to_unit(&val,&c);
	    snprintf(tmp_buffer,4096,"%.2f %c",val,c);
	  } else
	    snprintf(tmp_buffer,4096,"%lld",user->bytes_dl_total);
	}
	cookie = tmp_buffer;
        cookielength = strlen(cookie);
        srcptr += 8; /* strlen("total_dl"); */
	if (convert) srcptr++;
      } else
      /* total_ul */
      if (strncmp(srcptr,"total_ul",8)==0) {
	float val;
	char c;
	short convert=0;
	if (*(srcptr+8)=='2') convert=1;
	if (cookie_type==COOKIE_GROUP)
	{
	  int gid, i;
	  unsigned long long total;
	  wzd_user_t * loop_user;
	  /* TODO iterate through users and sum */
	  gid = param_context->userid;
	  total = 0;
	  for (i=0; i<HARD_DEF_USER_MAX; i++)
	  {
	    loop_user = GetUserByID(i);
	    if (!loop_user) continue;
	    if (is_user_in_group(loop_user,gid)==1)
	    {
	      total += loop_user->bytes_ul_total;
	    }
	  }
	  if (convert) {
	    val = (float)total;
	    bytes_to_unit(&val,&c);
	    snprintf(tmp_buffer,4096,"%.2f %c",val,c);
	  } else
	    snprintf(tmp_buffer,4096,"%lld",total);
	} else {
	  if (convert) {
	    val = (float)user->bytes_ul_total;
	    bytes_to_unit(&val,&c);
	    snprintf(tmp_buffer,4096,"%.2f %c",val,c);
	  } else
	    snprintf(tmp_buffer,4096,"%lld",user->bytes_ul_total);
	}
	cookie = tmp_buffer;
	cookielength = strlen(cookie);
	srcptr += 8; /* strlen("total_ul"); */
	if (convert) srcptr++;
      }
    } /* if param_context */
    /* end of cookies */


    /* TODO if length is non null, we will proceed differently: write maximum length chars, and pad with spaces (FIXME) */
    if (length <= 0) {
      if (bytes_written+cookielength >= buffersize) {
        return 1;
      }
  
      memcpy(dstptr,cookie,cookielength);
      bytes_written += cookielength;
      dstptr += cookielength;
    } else { /* length > 0 */
      if (bytes_written+cookielength >= buffersize) {
        return 1;
      }
  
      if (length < cookielength) {
        memcpy(dstptr,cookie,length);
        bytes_written += length;
        dstptr += length;
      } else {
        memcpy(dstptr,cookie,cookielength);
        bytes_written += cookielength;
        dstptr += cookielength;
	/* TODO check that total length will not exceed buffer size */
	while (cookielength < length) {
	  bytes_written++;
	  *dstptr++ = ' '; /* FIXME choose padding character */
	  cookielength++;
	}
      } /* length < cookielength */
    } /* length <= 0 */
    
  }

  memcpy(buffer,work_buffer,buffersize);
  return 0;
}

/** print_file : read file, replace cookies and prints it
 * header (200-) MUST have been sent, and end (200 ) is NOT sent)
 */
int print_file(const char *filename, int code, void * void_context)
{
  wzd_context_t * context = void_context;
  void * param;
  struct stat s;
  char complete_buffer[1024];
  char * buffer = complete_buffer + 4;
  int ret;
  FILE *fp;

  if (strlen(filename)==0) {
    out_log(LEVEL_HIGH,"Trying to print file (null) with code %d\n",code);
    return 1;
  }
  if (stat(filename,&s)==-1) {
    out_log(LEVEL_HIGH,"File %s does not exist (code %d)\n",filename,code);
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
    ret = cookies_replace(buffer,1018,param,context); /* TODO test ret */
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


/** IP allowing */
int ip_add(wzd_ip_t **list, const char *newip)
{
  wzd_ip_t * new_ip_t, *insert_point;

  /* of course this should never happen :) */
  if (list == NULL) return -1;

  if (strlen(newip) < 1) return -1;
  if (strlen(newip) >= MAX_IP_LENGTH) return -1; /* upper limit for an hostname */

  new_ip_t = malloc(sizeof(wzd_ip_t));
  new_ip_t->regexp = malloc(strlen(newip)+1);
  strcpy(new_ip_t->regexp,newip);
  new_ip_t->next_ip = NULL;

  /* tail insertion, be aware that order is important */
  insert_point = *list;
  if (insert_point == NULL) {
    *list = new_ip_t;
  } else {
    while (insert_point->next_ip != NULL)
      insert_point = insert_point->next_ip;

    insert_point->next_ip = new_ip_t;
  }

  return 0;
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
  if (*ptr_dst == '\0') return 1;

  return 0;
}
  

int ip_inlist(wzd_ip_t *list, const char *ip)
{
  wzd_ip_t * current_ip;
  const char * ptr_ip;
  char * ptr_test;
  struct hostent *host;

  current_ip = list;
  while (current_ip) {
    ptr_ip = ip;
    ptr_test = current_ip->regexp;
    if (*ptr_test == '\0') return 0; /* ip has length 0 ! */

    if (*ptr_test == '+') {
      char buffer[30];
      unsigned char * host_ip;

      ptr_test++;
      host = gethostbyname(ptr_test);
      if (!host) {
        /* XXX could not resolve hostname - warning in log ? */
        current_ip = current_ip->next_ip;
        continue;
      }

      host_ip = (unsigned char*)(host->h_addr);
      snprintf(buffer,29,"%d.%d.%d.%d",
        host_ip[0],host_ip[1],host_ip[2],host_ip[3]);
#if DEBUG
out_err(LEVEL_CRITICAL,"HOST IP %s\n",buffer);
#endif
      if (my_str_compare(buffer,ip)==1)
        return 1;
    } else
    if (*ptr_test == '-') {
      unsigned char host_ip[5];
      int i1, i2, i3, i4;

      ptr_test++;
      if (sscanf(ptr_ip,"%d.%d.%d.%d",&i1,&i2,&i3,&i4)!=4) {
        out_log(LEVEL_HIGH,"INVALID IP (%s:%d) %s\n",__FILE__,__LINE__,
          ptr_ip);
        return 0;
      }
      host_ip[0] = i1;
      host_ip[1] = i2;
      host_ip[2] = i3;
      host_ip[3] = i4;

      host = gethostbyaddr(host_ip,4,AF_INET);
      if (!host) {
        /* XXX could not resolve hostname - warning in log ? */
        current_ip = current_ip->next_ip;
        continue;
      }

      /* XXX do not forget the alias list ! */
#if DEBUG
out_err(LEVEL_CRITICAL,"HOST NAME %s\n",ptr_test);
#endif
      if (my_str_compare(host->h_name,ptr_test)==1)
        return 1;
    } else
    { /* ip does not begin with + or - */
#if DEBUG
out_err(LEVEL_CRITICAL,"IP %s\n",ptr_test);
#endif
      if (my_str_compare(ptr_ip,ptr_test)==1) return 1;
    } /* ip does not begin with + or - */
  
    current_ip = current_ip->next_ip;
  } /* while current_ip */
  
  return 0;
}

void ip_free(wzd_ip_t *list)
{
  wzd_ip_t * current, *next;

  if (!list) return;
  current = list;

  while (current) {
    next = current->next_ip;

    free(current->regexp);
    free(current);

    current = next;
  }
}

int user_ip_add(wzd_user_t * user, const char *newip)
{
  int i;

  /* of course this should never happen :) */
  if (user == NULL || newip==NULL);

  if (strlen(newip) < 1) return -1;
  if (strlen(newip) >= MAX_IP_LENGTH) return -1; /* upper limit for an hostname */

  /* tail insertion, be aware that order is important */
  for (i=0; i<HARD_IP_PER_USER; i++) {
    if (user->ip_allowed[i][0] == '\0') {
      strncpy(user->ip_allowed[i],newip,MAX_IP_LENGTH-1);
      return 0;
    }
  }
  return 1; /* full */
}

int user_ip_inlist(wzd_user_t * user, const char *ip)
{
  int i;
  const char * ptr_ip;
  char * ptr_test;
  struct hostent *host;

  i = 0;
  while (user->ip_allowed[i][0] != '\0') {
    ptr_ip = ip;
    ptr_test = user->ip_allowed[i];
    if (*ptr_test == '\0') return 0; /* ip has length 0 ! */
    
    if (*ptr_test == '+') {
      char buffer[30];
      unsigned char * host_ip;
      
      ptr_test++;
      host = gethostbyname(ptr_test);
      if (!host) {
        /* XXX could not resolve hostname - warning in log ? */
	i++;
        continue;
      }
      
      host_ip = (unsigned char*)(host->h_addr);
      snprintf(buffer,29,"%d.%d.%d.%d",
        host_ip[0],host_ip[1],host_ip[2],host_ip[3]);
#if DEBUG
out_err(LEVEL_CRITICAL,"HOST IP %s\n",buffer);
#endif
      if (my_str_compare(buffer,ip)==1)
        return 1;
    } else
    if (*ptr_test == '-') {
      unsigned char host_ip[5];
      int i1, i2, i3, i4;

      ptr_test++;
      if (sscanf(ptr_ip,"%d.%d.%d.%d",&i1,&i2,&i3,&i4)!=4) {
        out_log(LEVEL_HIGH,"INVALID IP (%s:%d) %s\n",__FILE__,__LINE__,
          ptr_ip);
        return 0;
      }
      host_ip[0] = i1;
      host_ip[1] = i2;
      host_ip[2] = i3;
      host_ip[3] = i4;

      host = gethostbyaddr(host_ip,4,AF_INET);
      if (!host) {
        /* XXX could not resolve hostname - warning in log ? */
	i++;
        continue;
      }

      /* XXX do not forget the alias list ! */
#if DEBUG
out_err(LEVEL_CRITICAL,"HOST NAME %s\n",ptr_test);
#endif
      if (my_str_compare(host->h_name,ptr_test)==1)
        return 1;
    } else
    { /* ip does not begin with + or - */
#if DEBUG
out_err(LEVEL_CRITICAL,"IP %s\n",ptr_test);
#endif
      if (my_str_compare(ptr_ip,ptr_test)==1) return 1;
    } /* ip does not begin with + or - */

    i++;
  } /* while current_ip */

  return 0;
}

int group_ip_add(wzd_group_t * group, const char *newip)
{
  int i;

  /* of course this should never happen :) */
  if (group == NULL || newip==NULL);

  if (strlen(newip) < 1) return -1;
  if (strlen(newip) >= MAX_IP_LENGTH) return -1; /* upper limit for an hostname */

  /* tail insertion, be aware that order is important */
  for (i=0; i<HARD_IP_PER_GROUP; i++) {
    if (group->ip_allowed[i][0] == '\0') {
      strncpy(group->ip_allowed[i],newip,MAX_IP_LENGTH-1);
      return 0;
    }
  }
  return 1; /* full */
}

int group_ip_inlist(wzd_group_t * group, const char *ip)
{
  int i;
  const char * ptr_ip;
  char * ptr_test;
  struct hostent *host;

  i = 0;
  while (group->ip_allowed[i][0] != '\0') {
    ptr_ip = ip;
    ptr_test = group->ip_allowed[i];
    if (*ptr_test == '\0') return 0; /* ip has length 0 ! */
    
    if (*ptr_test == '+') {
      char buffer[30];
      unsigned char * host_ip;
      
      ptr_test++;
      host = gethostbyname(ptr_test);
      if (!host) {
        /* XXX could not resolve hostname - warning in log ? */
	i++;
        continue;
      }
      
      host_ip = (unsigned char*)(host->h_addr);
      snprintf(buffer,29,"%d.%d.%d.%d",
        host_ip[0],host_ip[1],host_ip[2],host_ip[3]);
#if DEBUG
out_err(LEVEL_CRITICAL,"HOST IP %s\n",buffer);
#endif
      if (my_str_compare(buffer,ip)==1)
        return 1;
    } else
    if (*ptr_test == '-') {
      unsigned char host_ip[5];
      int i1, i2, i3, i4;

      ptr_test++;
      if (sscanf(ptr_ip,"%d.%d.%d.%d",&i1,&i2,&i3,&i4)!=4) {
        out_log(LEVEL_HIGH,"INVALID IP (%s:%d) %s\n",__FILE__,__LINE__,
          ptr_ip);
        return 0;
      }
      host_ip[0] = i1;
      host_ip[1] = i2;
      host_ip[2] = i3;
      host_ip[3] = i4;

      host = gethostbyaddr(host_ip,4,AF_INET);
      if (!host) {
        /* XXX could not resolve hostname - warning in log ? */
	i++;
        continue;
      }

      /* XXX do not forget the alias list ! */
#if DEBUG
out_err(LEVEL_CRITICAL,"HOST NAME %s\n",ptr_test);
#endif
      if (my_str_compare(host->h_name,ptr_test)==1)
        return 1;
    } else
    { /* ip does not begin with + or - */
#if DEBUG
out_err(LEVEL_CRITICAL,"IP %s\n",ptr_test);
#endif
      if (my_str_compare(ptr_ip,ptr_test)==1) return 1;
    } /* ip does not begin with + or - */

    i++;
  } /* while current_ip */

  return 0;
}

/** wrappers to user list */
wzd_user_t * GetUserByID(unsigned int id)
{
  if (!mainConfig->user_list || id >= HARD_DEF_USER_MAX) return NULL;

  return &mainConfig->user_list[id];
}

wzd_user_t * GetUserByName(const char *name)
{
  int i=0;
  if (!mainConfig->user_list || !name || strlen(name)<=0) return NULL;

  while (i<HARD_DEF_USER_MAX)
  {
    if (mainConfig->user_list[i].username[0] != '\0') {
      if (strcmp(name,mainConfig->user_list[i].username)==0)
	return &mainConfig->user_list[i];
    }
    i++;
  }

  return NULL;
}

/** wrappers to Group list */
wzd_group_t * GetGroupByID(unsigned int id)
{
  if (!mainConfig->group_list || id >= HARD_DEF_GROUP_MAX ) return NULL;

  return &mainConfig->group_list[id];
}

wzd_group_t * GetGroupByName(const char *name)
{
  int i=0;
  if (!mainConfig->group_list || !name || strlen(name)<=0) return NULL;

  while (i<HARD_DEF_GROUP_MAX)
  {
    if (mainConfig->group_list[i].groupname[0] != '\0') {
      if (strcmp(name,mainConfig->group_list[i].groupname)==0)
	return &mainConfig->group_list[i];
    }
    i++;
  }

  return NULL;
}

unsigned int GetUserIDByName(const char *name)
{
  int i=0;
  if (!mainConfig->user_list || !name || strlen(name)<=0) return 0;

  while (i<HARD_DEF_USER_MAX)
  {
    if (mainConfig->user_list[i].username[0] != '\0') {
      if (strcmp(name,mainConfig->user_list[i].username)==0)
	return i;
    }
    i++;
  }

  return 0;
}


unsigned int GetGroupIDByName(const char *name)
{
  unsigned int i=0;
  if (!mainConfig->group_list || !name || strlen(name)<=0) return 0;

  while (i<HARD_DEF_GROUP_MAX)
  {
    if (mainConfig->group_list[i].groupname[0] != '\0') {
      if (strcmp(name,mainConfig->group_list[i].groupname)==0)
	return i;
    }
    i++;
  }

  return 0;
}

short is_user_in_group(wzd_user_t * user, int gid)
{
	int i;

	if (!user || user->group_num<=0) return -1;
	for (i=0; i<user->group_num; i++)
		if (gid==user->groups[i]) return 1;
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

#else /* WZD_MULTIPROCESS */
  /* we have only one process */
  for (i=0; i<HARD_USERLIMIT; i++)
  {
    if (context_list[i].magic == CONTEXT_MAGIC)
      return (&context_list[i]);
  }
#endif /* WZD_MULTIPROCESS */

  return NULL;
}

