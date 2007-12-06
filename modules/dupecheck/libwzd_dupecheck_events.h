#ifndef LIBWZD_DUPECHECK_EVENTS_H
#define LIBWZD_DUPECHECK_EVENTS_H

event_reply_t dupecheck_event_preupload(const char * args);
event_reply_t dupecheck_event_postupload_denied(const char * args);
event_reply_t dupecheck_event_dele(const char * args);
event_reply_t dupecheck_event_prerename(const char * args);
event_reply_t dupecheck_event_postrename(const char * args);

#endif
