#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "libwzd.h"


MODULE = wzdftpd		PACKAGE = wzdftpd		

PROTOTYPES: ENABLE

#/* we can use PREINIT to give default values
# * see perlxs(1)  The PROTOTYPE: Keyword
# */
int
wzd_init(host="localhost",port=21,user="wzdftpd",pass="wzdftpd")
    const char *	host
    int			port
    const char *	user
    const char *	pass
  CODE:
  {
    const char * 	horrible_tab[64];
    unsigned int	horrible_index=0;
    char 		intbuf[64];
    /* call wzd_parse_ags */
    horrible_tab[horrible_index++] = "wzdftpd.xs";
    if (host) {
      horrible_tab[horrible_index++] = "-h";
      horrible_tab[horrible_index++] = host;
    }
    if (port) {
      snprintf(intbuf,sizeof(intbuf),"%d",port);
      horrible_tab[horrible_index++] = "-p";
      horrible_tab[horrible_index++] = intbuf;
    }
    if (user) {
      horrible_tab[horrible_index++] = "-u";
      horrible_tab[horrible_index++] = user;
    }
    if (pass) {
      horrible_tab[horrible_index++] = "-w";
      horrible_tab[horrible_index++] = pass;
    }
    horrible_tab[horrible_index] = NULL;
    wzd_parse_args(horrible_index,horrible_tab);

    RETVAL = (!wzd_init());
  }
  OUTPUT:
    RETVAL

int
wzd_fini()
  CODE:
    RETVAL = wzd_fini();
  OUTPUT:
    RETVAL

char *
wzd_send_message(message)
    const char *	message
  INIT:
    wzd_reply_t * reply;
    unsigned int i;

  PPCODE:
    reply = wzd_send_message(message,strlen(message));
    if (!reply)
      XSRETURN_UNDEF;

      
    for (i=0; reply->data[i]!=NULL; i++) {
      XPUSHs(sv_2mortal(newSVpv(reply->data[i],strlen(reply->data[i]))));
    }

    wzd_free_reply(reply);

