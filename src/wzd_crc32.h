#ifndef __WZD_CRC32__
#define __WZD_CRC32__

/* inits an sfv struct
 */
void sfv_init(wzd_sfv_file *sfv);

/* reads sfv file
 */
int sfv_read(const char *filename, wzd_sfv_file *sfv);

/* frees contents of a sfv structure
 * if sfv was allocated on heap you MUST free sfv struct after
 */
void sfv_free(wzd_sfv_file *sfv);

/* checks sfv file
 * returns 0 if all ok
 * 1 if error occurs
 * 2 if missing files
 * 3 if missing + error
 * -1 for other errors
 * !! sfv_file path must be an ABSOLUTE path !!
 */
int sfv_check(const char * sfv_file);


/***** EVENT HOOKS *****/
int sfv_hook_preupload(unsigned long event_id, const char * username, const char * filename);
int sfv_hook_postupload(unsigned long event_id, const char * username, const char * filename);


#endif /* __WZD_CRC32__ */
