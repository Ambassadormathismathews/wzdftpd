-- MySQL dump 8.23
--
-- Host: localhost    Database: wzdftpd
---------------------------------------------------------
-- Server version	3.23.54

--
-- Table structure for table `ugroups`
--

CREATE TABLE ugroups (
  username blob NOT NULL,
  gid int(10) unsigned NOT NULL default '0'
) TYPE=MyISAM;

--
-- Dumping data for table `ugroups`
--



--
-- Table structure for table `users`
--

CREATE TABLE users (
  username blob NOT NULL,
  userpass varchar(32) default NULL,
  rootpath blob NOT NULL,
  uid int(10) unsigned NOT NULL,
  group_num int(10) unsigned default NULL,
  flags varchar(32) default NULL,
  max_ul_speed double unsigned default NULL,
  max_dl_speed double unsigned default NULL,
  num_logins smallint(5) unsigned default NULL,
  ip_allowed blob,
  ratio int(10) unsigned default NULL,
  user_slots int(10) unsigned default NULL,
  leech_slots int(10) unsigned default NULL,
  last_login time default NULL
) TYPE=MyISAM;

--
-- Dumping data for table `users`
--


INSERT INTO users VALUES ('novel',NULL,'/usr/home/novel',1,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
INSERT INTO users VALUES ('anonymous',NULL,'/tmp',2,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);

