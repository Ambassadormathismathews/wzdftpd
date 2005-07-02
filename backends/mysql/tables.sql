--
-- Create database
--
CREATE DATABASE IF NOT EXISTS wzdftpd;

GRANT ALL ON `wzdftpd`.* TO "wzdftpd"@"localhost" IDENTIFIED BY "wzdftpd";

FLUSH PRIVILEGES;


use wzdftpd;

--
-- Table structure for table `ugroups`
--

CREATE TABLE groups (
  ref INT(5) UNSIGNED NOT NULL AUTO_INCREMENT,
  groupname TINYTEXT NOT NULL,
  gid int(10) unsigned NOT NULL UNIQUE,
  defaultpath TINYTEXT NOT NULL,
  tagline TINYTEXT default NULL,
  groupperms int(10) unsigned default NULL,
  max_idle_time int(10) unsigned default NULL,
  num_logins smallint(5) unsigned default NULL,
  max_ul_speed double unsigned default NULL,
  max_dl_speed double unsigned default NULL,
  ratio int(10) unsigned default NULL,
  PRIMARY KEY (ref,gid)
) TYPE=MyISAM;

--
-- Dumping data for table `groups`
--

INSERT INTO groups (groupname,gid,defaultpath,tagline) VALUES ('admin',1,'/','admin group');


--
-- Table structure for table `users`
--

CREATE TABLE users (
  ref INT(5) UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  username TINYTEXT NOT NULL,
  userpass varchar(32) default NULL,
  rootpath TINYTEXT NOT NULL,
  tagline TINYTEXT default NULL,
  uid int(10) unsigned NOT NULL UNIQUE,
  flags varchar(32) default NULL,
  max_idle_time int(10) unsigned default NULL,
  max_ul_speed double unsigned default NULL,
  max_dl_speed double unsigned default NULL,
  num_logins smallint(5) unsigned default NULL,
  ratio int(10) unsigned default NULL,
  user_slots int(10) unsigned default NULL,
  leech_slots int(10) unsigned default NULL,
  perms int(10) unsigned default NULL,
  credits bigint unsigned default NULL,
  last_login time default NULL
) TYPE=MyISAM;

--
-- Dumping data for table `users`
--

INSERT INTO users VALUES ('','wzdftpd',NULL,'/','local admin',1,"OIstH",NULL,NULL,NULL,NULL,NULL,NULL,NULL,0xffffffff,NULL,NULL);

INSERT INTO users VALUES ('','novel',NULL,'/usr/home/novel',NULL,2,"OIstH",NULL,NULL,NULL,NULL,NULL,NULL,NULL,0xffffffff,NULL,NULL);
INSERT INTO users VALUES ('','anonymous',NULL,'/tmp',NULL,3,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0xffffffff,NULL,NULL);

--
-- Table structure for table `ugr` (User-Group Relations)
--

CREATE TABLE ugr (
  uref int(10) unsigned NOT NULL,
  gref int(10) unsigned NOT NULL,
  PRIMARY KEY(uref,gref)
) TYPE=MyISAM;

--
-- Table structure for table `IP` (User/Group IPs)
--

CREATE TABLE groupip (
  ref int(10) unsigned NOT NULL,
  ip VARCHAR(255) NOT NULL,
  PRIMARY KEY(ref,ip)
) TYPE=MyISAM;

--
-- Table structure for table `IP` (User/Group IPs)
--

CREATE TABLE userip (
  ref int(10) unsigned NOT NULL,
  ip VARCHAR(255) NOT NULL,
  PRIMARY KEY(ref,ip)
) TYPE=MyISAM;

INSERT INTO userip VALUES(1,"127.0.0.1");

INSERT INTO userip VALUES(2,"foobar@localhost");
INSERT INTO userip VALUES(2,"127.0.0.1");

--
-- Table structure for table `stats`
--

CREATE TABLE stats (
  ref int(10) unsigned NOT NULL,
  bytes_ul_total bigint unsigned default NULL,
  bytes_dl_total bigint unsigned default NULL,
  files_ul_total int(10) unsigned default NULL,
  files_dl_total int(10) unsigned default NULL,
  PRIMARY KEY(ref)
) TYPE=MyISAM;

INSERT INTO stats (ref) VALUES (1);
INSERT INTO stats (ref) VALUES (2);

--
-- hmm - moo, moo; I'm trying to insert references into ugr
--
INSERT into ugr (uref,gref) SELECT users.ref,groups.ref FROM users,groups WHERE users.uid=1 AND groups.gid=1;

-- insert novel into admin group (he's a good friend !)
INSERT into ugr (uref,gref) SELECT users.ref,groups.ref FROM users,groups WHERE users.uid=2 AND groups.gid=1;


--
-- find all groups (gid) given a uid
--   select gid from groups,users,ugr where users.uid=1 and users.ref=ugr.uref and groups.ref=ugr.gref;
--
-- find all infos given a uid (not very usable)
--   select * from groups,users,ugr,userip where users.uid=1 and users.ref=ugr.uref and groups.ref=ugr.gref AND userip.ref=users.ref;
--
-- find all ip for a user
--   select userip.ip from userip,users where users.ref=1 AND users.ref=userip.ref;
--
--
-- reset auto-increment: ALTER TABLE users AUTO_INCREMENT=4;
--
