--
-- Use this to completely destroy wzdftpd
--

-- Removing privileges
REVOKE ALL ON *.* FROM "wzdftpd"@"localhost";

-- Deleting user ...
DELETE FROM mysql.user WHERE User='wzdftpd';

-- Droping database and all the tables in it
DROP DATABASE IF EXISTS `wzdftpd`;

-- Reloading the privileges ...
FLUSH PRIVILEGES;
