#ifndef __WZD_OPTS__
#define __WZD_OPTS__

/* wzd_opts.h 
   Based on wget's getopt.h
*/

struct option
{
#if     __STDC__
  const char *name;
#else
  char *name;
#endif
  /* has_arg can't be an enum because some compilers complain about
     type mismatches in all the code that assumes it is an int.  */
  int has_arg;
  int *flag;
  int val;
};

#define no_argument              0
#define required_argument      1
#define optional_argument       2

#if __STDC__
#if defined(__GNU_LIBRARY__)
extern int getopt (int argc, char *const *argv, const char *shortopts);
#else /* not __GNU_LIBRARY__ */
extern int getopt ();
#endif /* not __GNU_LIBRARY__ */
extern int getopt_long (int argc, char *const *argv, const char
*shortopts,                        const struct option *longopts, int
*longind); extern int getopt_long_only (int argc, char *const *argv,
                             const char *shortopts,
                             const struct option *longopts, int
*longind);

/* Internal only.  Users should not call this directly.  */
extern int _getopt_internal (int argc, char *const *argv,
                             const char *shortopts,
                             const struct option *longopts, int
*longind,                             int long_only);
#else /* not __STDC__ */
extern int getopt ();
extern int getopt_long ();
extern int getopt_long_only ();

extern int _getopt_internal ();
#endif /* not __STDC__ */

#endif /* __WZD_OPTS__ */
