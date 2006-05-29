#ifndef __LIBWZD_SFV_INDICATORS_H__
#define __LIBWZD_SFV_INDICATORS_H__

#include "libwzd_sfv_main.h"

/** Converts cookies in incomplete indicators */
char *c_incomplete_indicator(const char * indicator, const char * currentdir , wzd_context_t * context);
/** Converts cookies in complete indicators and create the full path + bar */
char *c_complete_indicator(const char * indicator, const char * currentdir, wzd_release_stats * stats);
/** updates complete bar (erasing preceding one if existing) Making fully complete bar also if complete (for both .diz and .zip) */
void sfv_update_completebar(wzd_release_stats * stats, const char *directory, wzd_context_t *context);

#endif /* __LIBWZD_SFV_INDICATORS_H__*/
