
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

