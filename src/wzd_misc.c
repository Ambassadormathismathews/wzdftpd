#include "wzd.h"

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

void chop(char *s)
{
  char *r;

  if ((r=(char*) strchr(s,'\r')))
    *r = '\0';
  if ((r=(char*) strchr(s,'\n')))
    *r = '\0';
}

#define WORK_BUF_LEN	8192

void v_format_message(int code, unsigned int length, char *buffer, va_list argptr)
{
  const char * token, *token2;
  const char * msg;
  char *ptr;
  unsigned int size;
  char work_buf[WORK_BUF_LEN];
  /* XXX 4096 should ALWAYS be >= length */

#ifdef DEBUG
  if (length > WORK_BUF_LEN) {
    fprintf(stderr,"*** WARNING *** message too long, will be truncated\n");
    length = WORK_BUF_LEN;
  }
#endif

  msg = getMessage(code);
  ptr = work_buf;

  /* first, format message */
  vsnprintf(work_buf,WORK_BUF_LEN,msg,argptr);

  /* adjust size, we will need more space to put the code and \r\n */
  length -= 7;
  
  if (!strpbrk(work_buf,"\r\n")) { /* simple case, msg on one line */
    snprintf(buffer,length,"%d %s\r\n",code,work_buf);
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
      if (!token2) { /* no more line, remove the - */
	snprintf(buffer,length,"%d %s\r\n",code,token);
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

void limiter_add_bytes(wzd_bw_limiter *l, int byte_count, int force_check)
{
  long dif;
  struct timeval tv;
  struct timezone tz;

  if (!l) return;

  l->bytes_transfered += byte_count;

  /* if at least 1 second of data is downloaded, assess the situation
   * and determine how much time to wait */
  if ( (l->bytes_transfered >= l->maxspeed) || force_check )
  {
    gettimeofday( &tv, &tz );
    dif = (tv.tv_sec - l->current_time.tv_sec) * 1000
      + (tv.tv_usec - l->current_time.tv_usec) / 1000;
    dif = (((1000L * l->bytes_transfered) / l->maxspeed) - dif) * 1000L;

    /* if usleep takes too long, this will compensate by
     * putting the expecting time after usleep into l->current_time
     * instead of reading the real time after an inacurrate
     * usleep, allowing the transfer to catch up */
    memcpy(&(l->current_time), &tv, sizeof(struct timeval));
    l->current_time.tv_usec += (dif % 1000000);
    l->current_time.tv_sec += (dif / 1000000);
fprintf(stderr,"dif: %ld\n",dif);
    if (dif > 0)
      usleep(dif);
    l->bytes_transfered = 0;
/*    l->bytes_transfered -= l->maxspeed;
    if (l->bytes_transfered < 0)
      l->bytes_transfered = 0;*/
  }
}

void limiter_free(wzd_bw_limiter *l)
{
  if (l)
    free(l);
}


/* cookies */
int cookies_replace(char * buffer, unsigned int buffersize, void * void_context)
{
  wzd_context_t * context = void_context;
  char work_buffer[4096];
  char *srcptr, *dstptr;
  unsigned int bytes_written=0;
  char * cookie;
  unsigned int cookielength;
  char c;

  if (buffersize > 4095) {
#ifdef DEBUG
    fprintf(stderr,"BUFFER SIZE too long !!\n");
#endif
    return -1;
  }

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

    cookielength = 0;
    cookie = NULL;

    /* %username */
    if (strncmp(srcptr,"username",8)==0) {
      cookie = context->userinfo.username;
      cookielength = strlen(context->userinfo.username);
      srcptr += 8; /* strlen("username"); */
    }
    /* end of cookies */
    
    if (bytes_written+cookielength >= buffersize) {
      return 1;
    }

    memcpy(dstptr,cookie,cookielength);
    bytes_written += cookielength;
    dstptr += cookielength;
  }

  memcpy(buffer,work_buffer,buffersize);
  return 0;
}
