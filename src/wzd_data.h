#ifndef __WZD_DATA__
#define __WZD_DATA__

void data_close(wzd_context_t * context);

/* sets the correct fds and return the highest fd that was set or -1 */
int data_set_fd(wzd_context_t * context, fd_set *fdr, fd_set *fdw, fd_set *fde);

/* returns 1 if a set is ok, 0 if not fd set, -1 if error */
int data_check_fd(wzd_context_t * context, fd_set *fdr, fd_set *fdw, fd_set *fde);

/* send or retr data */
int data_execute(wzd_context_t * context, fd_set *fdr, fd_set *fdw);

#endif /* __WZD_DATA__ */
