#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <malloc.h>
#include <string.h>

/* speed up compilation */
#define	SSL	void
#define	SSL_CTX	void

#include "wzd_structs.h"
#include "wzd_log.h"
#include "wzd_crontab.h"

struct wzd_cronjob_t {
  int (*fn)(void);
  char * command;
  unsigned int interval;
  time_t timestamp;
  wzd_cronjob_t * next_cronjob;
};

int cronjob_add(wzd_cronjob_t ** crontab, int (*fn)(void), const char * command, unsigned int interval)
{
  wzd_cronjob_t * current = *crontab, *new;

  if (!fn && !command) return 1;
  if (fn && command) return 1;
  if (interval <= 3) return 2;

  new = malloc(sizeof(wzd_cronjob_t));
  new->fn = fn;
  new->command = command?strdup(command):NULL;
  new->interval = interval;
  time(&new->timestamp);
  new->next_cronjob = NULL;

  if (current==NULL) { /* first insertion */
    *crontab = new;
    return 0;
  }

  while (current->next_cronjob) current = current->next_cronjob;
  current->next_cronjob = new;
  
  return 0;
}

int cronjob_run(wzd_cronjob_t ** crontab)
{
  wzd_cronjob_t * job = *crontab;
  time_t now;

  time(&now);
  while (job) {
    if ( (now-job->timestamp) >= job->interval )
    {
      /* run job */
      if (job->fn) {
	(job->fn)();
      } else {
	char buffer[1024];
	FILE * command_output;
	if ( (command_output = popen(job->command,"r")) == NULL ) {
	  out_log(LEVEL_HIGH,"Cronjob command '%s': unable to popen\n",job->command);
	  return 1;
	}
	while (fgets(buffer,1023,command_output) != NULL)
	{
	  out_log(LEVEL_INFO,"cronjob: %s\n",buffer);
	}
	pclose(command_output);
      }
      job->timestamp = now;
    }
    job = job->next_cronjob;
  }
  
  return 0;
}

