#include "wzd.h"

void data_close(wzd_context_t * context)
{
  int ret;

#if SSL_SUPPORT
  if (context->ssl.data_mode == TLS_PRIV)
    ret = tls_close_data(context);
#endif
out_err(LEVEL_CRITICAL,"closing data connection fd: %d (control fd: %d)\n",context->datafd, context->controlfd);
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
  wzd_user_t * user;

#if BACKEND_STORAGE
  if (mainConfig->backend.backend_storage==0) {
    user = &context->userinfo;
  } else
#endif
    user = &mainConfig->user_list[context->userid];

  if (!context) return -1;

  action = context->current_action.token;

  switch (action) {
  case TOK_RETR:
    n = read(context->current_action.current_file,buffer,sizeof(buffer));
    if (n>0) {
#if SSL_SUPPORT
      if (context->ssl.data_mode == TLS_CLEAR)
	ret = clear_write(context->datafd,buffer,n,0,HARD_XFER_TIMEOUT,context);
      else
#endif
        ret = (context->write_fct)(context->datafd,buffer,n,0,HARD_XFER_TIMEOUT,context);
      if (ret <= 0) {
        /* XXX error/timeout sending data */
	close(context->current_action.current_file);
	context->current_action.current_file = 0;
	context->current_action.bytesnow = 0;
	context->current_action.token = TOK_UNKNOWN;
	data_close(context);
	ret = send_message(426,context);
out_err(LEVEL_INFO,"Send 426 message returned %d\n",ret);
/*	limiter_free(context->current_limiter);
	context->current_limiter = NULL;*/
	return 1;
      }
      context->current_action.bytesnow += n;
/*      limiter_add_bytes(mainConfig->limiter_dl,n,0);*/
      limiter_add_bytes(&mainConfig->global_dl_limiter,n,0);
      limiter_add_bytes(&context->current_dl_limiter,n,0);
/*      limiter_add_bytes(context->current_limiter,n,0);*/
      user->bytes_dl_total += n;
      context->idle_time_data_start = time(NULL);
    } else { /* end */
      close(context->current_action.current_file);
      context->current_action.current_file = 0;
      context->current_action.bytesnow = 0;
      context->current_action.token = TOK_UNKNOWN;
      data_close(context);
      ret = send_message(226,context);
out_err(LEVEL_INFO,"Send 226 message returned %d\n",ret);
/*      limiter_free(context->current_limiter);
      context->current_limiter = NULL;*/
    }
    break;
  case TOK_STOR:
#if SSL_SUPPORT
      if (context->ssl.data_mode == TLS_CLEAR)
	n = clear_read(context->datafd,buffer,sizeof(buffer),0,HARD_XFER_TIMEOUT,context);
      else
#endif
      n = (context->read_fct)(context->datafd,buffer,sizeof(buffer),0,HARD_XFER_TIMEOUT,context);
    if (n>0) {
      write(context->current_action.current_file,buffer,n);
      context->current_action.bytesnow += n;
/*      limiter_add_bytes(mainConfig->limiter_ul,n,0);*/
      limiter_add_bytes(&mainConfig->global_ul_limiter,n,0);
      limiter_add_bytes(&context->current_ul_limiter,n,0);
/*      limiter_add_bytes(context->current_limiter,n,0);*/
      user->bytes_ul_total += n;
      context->idle_time_data_start = time(NULL);
    } else { /* consider it is finished */
      close(context->current_action.current_file);
      context->current_action.current_file = 0;
      context->current_action.bytesnow = 0;
      context->current_action.token = TOK_UNKNOWN;
      data_close(context);
      ret = send_message(226,context);
out_err(LEVEL_INFO,"Send 226 message returned %d\n",ret);
/*      limiter_free(context->current_limiter);
      context->current_limiter = NULL;*/
      FORALL_HOOKS(EVENT_POSTUPLOAD)
        typedef int (*login_hook)(unsigned long, const char*, const char *);
        ret = (*(login_hook)hook->hook)(EVENT_POSTUPLOAD,user->username,context->current_action.arg);
      END_FORALL_HOOKS
    }
    break;
  }

  return 0;
}
