#include "wzd.h"

void data_close(wzd_context_t * context)
{
  int ret;

#if SSL_SUPPORT
  if (context->ssl.data_mode == TLS_PRIV)
    ret = tls_close_data(context);
#endif
  ret = close(context->datafd);
  context->datafd = 0;
}

int data_set_fd(wzd_context_t * context, fd_set *fdr, fd_set *fdw, fd_set *fde)
{
  unsigned int action;

  if (!context) return -1;

  action = context->current_action.token;

  switch (action) {
  case TOK_RETR:
    FD_SET(context->datafd,fdw);
    FD_SET(context->datafd,fde);
    return context->datafd;
    break;
  case TOK_STOR:
    FD_SET(context->datafd,fdr);
    FD_SET(context->datafd,fde);
    return context->datafd;
    break;
  }
  return -1;
}

int data_check_fd(wzd_context_t * context, fd_set *fdr, fd_set *fdw, fd_set *fde)
{
  unsigned int action;

  if (!context) return -1;

  action = context->current_action.token;

  switch (action) {
  case TOK_RETR:
    if (FD_ISSET(context->datafd,fdw)) return 1;
    if (FD_ISSET(context->datafd,fde)) return -1;
    break;
  case TOK_STOR:
    if (FD_ISSET(context->datafd,fdr)) return 1;
    if (FD_ISSET(context->datafd,fde)) return -1;
    return context->datafd;
    break;
  }
  return 0;
}

int data_execute(wzd_context_t * context, fd_set *fdr, fd_set *fdw)
{
  char buffer[2048];
  int n;
  unsigned int action;
  int ret;

  if (!context) return -1;

  action = context->current_action.token;

  switch (action) {
  case TOK_RETR:
    n = fread(buffer,1,sizeof(buffer),context->current_action.current_file);
    if (n>0) {
      ret = (mainConfig.write_fct)(context->datafd,buffer,n,0,HARD_XFER_TIMEOUT,context);
      if (ret <= 0) {
        /* XXX error/timeout sending data */
	fclose(context->current_action.current_file);
	context->current_action.current_file = 0;
	context->current_action.bytesnow = 0;
	context->current_action.token = TOK_UNKNOWN;
	data_close(context);
	ret = send_message(426,context);
	limiter_free(context->current_limiter);
	context->current_limiter = NULL;
	return 1;
      }
      context->current_action.bytesnow += n;
      limiter_add_bytes(mainConfig.limiter_dl,n,0);
      limiter_add_bytes(context->current_limiter,n,0);
    } else { /* end */
      fclose(context->current_action.current_file);
      context->current_action.current_file = 0;
      context->current_action.bytesnow = 0;
      context->current_action.token = TOK_UNKNOWN;
      data_close(context);
      ret = send_message(226,context);
      limiter_free(context->current_limiter);
      context->current_limiter = NULL;
    }
    break;
  case TOK_STOR:
    n = (mainConfig.read_fct)(context->datafd,buffer,sizeof(buffer),0,HARD_XFER_TIMEOUT,context);
    if (n>0) {
      fwrite(buffer,1,n,context->current_action.current_file);
      context->current_action.bytesnow += n;
      limiter_add_bytes(mainConfig.limiter_ul,n,0);
      limiter_add_bytes(context->current_limiter,n,0);
    } else { /* consider it is finished */
      fclose(context->current_action.current_file);
      context->current_action.current_file = 0;
      context->current_action.bytesnow = 0;
      context->current_action.token = TOK_UNKNOWN;
      data_close(context);
      ret = send_message(226,context);
      limiter_free(context->current_limiter);
      context->current_limiter = NULL;
    }
    break;
  }

  return 0;
}
