
/*#define TEST*/

#ifdef TEST
#define OUT(x) fprintf(stdout,"%s\n",(x))
#endif

extern int list(int,wzd_context_t *,list_type_t,char *,char *,int callback(int,wzd_context_t*,char *));
extern int list_match(char *,char *);
