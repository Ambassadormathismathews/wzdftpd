--
-- Create database
--
CREATE DATABASE IF NOT EXISTS wzdftpd;

GRANT USAGE ON *.* TO "wzdftpd"@"localhost" IDENTIFIED BY "wzdftpd";

GRANT ALL PRIVILEGES ON `wzdftpd`.* TO "wzdftpd"@"localhost";

FLUSH PRIVILEGES;


use wzdftpd;

--
-- Table structure for table `ugroups`
--

CREATE TABLE groups (
  ref INT(5) UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  groupname TINYTEXT NOT NULL,
  gid int(10) unsigned NOT NULL default '0'
) TYPE=MyISAM;

--
-- Dumping data for table `groups`
--

INSERT INTO groups VALUES ('','admin',1);


--
-- Table structure for table `users`
--

CREATE TABLE users (
  ref INT(5) UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  username TINYTEXT NOT NULL,
  userpass varchar(32) default NULL,
  rootpath TINYTEXT NOT NULL,
  uid int(10) unsigned NOT NULL,
  flags varchar(32) default NULL,
  max_ul_speed double unsigned default NULL,
  max_dl_speed double unsigned default NULL,
  num_logins smallint(5) unsigned default NULL,
  ip_allowed TINYTEXT,
  ratio int(10) unsigned default NULL,
  user_slots int(10) unsigned default NULL,
  leech_slots int(10) unsigned default NULL,
  last_login time default NULL
) TYPE=MyISAM;

--
-- Dumping data for table `users`
--

INSERT INTO users VALUES ('','novel',NULL,'/usr/home/novel',1,"OIstH",NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO users VALUES ('','anonymous',NULL,'/tmp',2,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);

--
-- Table structure for table `UGR` (User-Group Relations)
--

CREATE TABLE UGR (
  uref int(10) unsigned NOT NULL,
  gref int(10) unsigned NOT NULL,
  PRIMARY KEY(uref,gref)
) TYPE=MyISAM;

--
-- Table structure for table `IP` (User/Group IPs)
--

CREATE TABLE UserIP (
  ref int(10) unsigned NOT NULL,
  ip VARCHAR(255) NOT NULL,
  PRIMARY KEY(ref,ip)
) TYPE=MyISAM;

INSERT INTO UserIP VALUES(1,"foobar@localhost");
INSERT INTO UserIP VALUES(1,"127.0.0.1");

--
-- hmm - moo, moo; I'm trying to insert references into UGR
--

-- insert novel into admin group (he's a good friend !)
INSERT into UGR (uref,gref) SELECT users.ref,groups.ref FROM users,groups WHERE users.uid=1 AND groups.gid=1;


--
-- find all groups (gid) given a uid
--   select gid from groups,users,UGR where users.uid=1 and users.ref=UGR.uref and groups.ref=UGR.gref;
--
-- find all infos given a uid (not very usable)
--   select * from groups,users,UGR,UserIP where users.uid=1 and users.ref=UGR.uref and groups.ref=UGR.gref AND UserIP.ref=users.ref;
--
-- find all ip for a user
--   select UserIP.ip from UserIP,users where users.ref=1 AND users.ref=UserIP.ref;
