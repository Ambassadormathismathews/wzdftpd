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

    while (1) {
      size = strlen(token);
      /* copy line into out buffer */
      snprintf(buffer,length,"%d-%s\r\n",code,token);
      /* find next token */
      token2 = strtok_r(NULL,"\r\n",&ptr);
      if (!token2) { /* no more line, remove the - */
	buffer[3] = ' ';
        break;
      }
      /* adjust length */
      length = length - size - 6;
      /* check remaining size */
      /* adjust buffer position */
      buffer = buffer + size + 6;
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
