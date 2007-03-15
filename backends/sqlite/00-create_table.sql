
CREATE TABLE IF NOT EXISTS groups (
  gref INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  gid INTEGER(10) NOT NULL UNIQUE,
  groupname TEXT NOT NULL,
  defaultpath TEXT NOT NULL,
  tagline TEXT DEFAULT NULL,
  groupperms INTEGER(10) default NULL,
  max_idle_time INTEGER(10) default NULL,
  num_logins INTEGER(5) default NULL,
  max_ul_speed DOUBLE default NULL,
  max_dl_speed DOUBLE default NULL,
  ratio INTEGER(10) default NULL
); 

CREATE TABLE IF NOT EXISTS users (
  uref INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  uid INTEGER(10) NOT NULL UNIQUE,
  username TEXT NOT NULL,
  userpass TEXT default NULL,
  rootpath TEXT NOT NULL,
  tagline TEXT default NULL,
  flags TEXT default NULL,
  max_idle_time INTEGER(10) default NULL,
  max_ul_speed DOUBLE default NULL,
  max_dl_speed DOUBLE default NULL,
  num_logins INTEGER(5) default NULL,
  ratio INTEGER(10) default NULL,
  user_slots INTEGER(10) default NULL,
  leech_slots INTEGER(10) default NULL,
  perms INTEGER(10) default NULL,
  credits BIGINT default NULL,
  last_login INTEGER(10) default NULL
);

CREATE TABLE IF NOT EXISTS ugr (
  uref INTEGER(10) NOT NULL,
  gref INTEGER(10) NOT NULL,
  PRIMARY KEY(uref,gref)
);

CREATE TABLE IF NOT EXISTS groupip (
  gref INTEGER(10) NOT NULL,
  ip TEXT NOT NULL,
  PRIMARY KEY(gref,ip)
);

CREATE TABLE userip (
  uref INTEGER(10) NOT NULL,
  ip TEXT NOT NULL,
  PRIMARY KEY(uref,ip)
);

CREATE TABLE stats (
  uref INTEGER NOT NULL PRIMARY KEY,
  bytes_ul_total BIGINT default NULL,
  bytes_dl_total BIGINT default NULL,
  files_ul_total INTEGER default NULL,
  files_dl_total INTEGER default NULL
);

