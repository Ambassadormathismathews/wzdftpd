
CREATE TABLE IF NOT EXISTS groups (
  gref INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  gid INTEGER(10) NOT NULL UNIQUE,
  groupname TEXT NOT NULL,
  defaultpath TEXT NOT NULL,
  tagline TEXT DEFAULT NULL,
  groupperms INTEGER(10) default NULL,
  max_idle_time INTEGER(10) default NULL,
  num_logins INTEGER(5) default NULL,
  max_ul_speed BIGINT default NULL,
  max_dl_speed BIGINT default NULL,
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
  max_ul_speed BIGINT default NULL,
  max_dl_speed BIGINT default NULL,
  num_logins INTEGER(5) default NULL,
  ratio INTEGER(10) default NULL,
  user_slots INTEGER(10) default NULL,
  leech_slots INTEGER(10) default NULL,
  perms BIGINT default NULL,
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
  bytes_ul_total BIGINT default 0,
  bytes_dl_total BIGINT default 0,
  files_ul_total INTEGER default 0,
  files_dl_total INTEGER default 0
);


INSERT INTO 
  groups (
    gref, gid, groupname,defaultpath,tagline
  ) 
  VALUES (
    1, 0,'admin','/','admin group'
  );

INSERT INTO 
  users (
    uref, uid, username, userpass, rootpath, tagline, flags, 
    max_idle_time, max_ul_speed, max_dl_speed, num_logins, ratio, 
    user_slots, leech_slots, perms, credits, last_login
  )
  VALUES (
    1, 0, 'wzdftpd', 'wzufwPCZFYH/6', '/', 'Admin', "O", NULL, NULL, NULL, 
    2, 0, NULL, NULL, 4294967295, NULL, NULL
  );

INSERT INTO ugr ( uref, gref ) VALUES (1, 1);
INSERT INTO userip ( uref, ip ) VALUES (1, '*@127.0.0.1');

INSERT INTO stats (uref) VALUES (1);
