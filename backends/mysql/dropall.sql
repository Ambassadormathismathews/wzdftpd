--
-- Use this to completely destroy wzdftpd
--

use mysql;

-- Deleting 'wzdftpd ...
DELETE FROM `user` WHERE `User` = "wzdftpd";

DELETE FROM `db` WHERE `User` = "wzdftpd";

DELETE FROM `tables_priv` WHERE `User` = "wzdftpd";

DELETE FROM `columns_priv` WHERE `User` = "wzdftpd";

DROP DATABASE IF EXISTS `wzdftpd` ;

-- Reloading the privileges ...
FLUSH PRIVILEGES ;
