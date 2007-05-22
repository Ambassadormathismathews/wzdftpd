--
-- Create database
--
CREATE DATABASE IF NOT EXISTS wzdftpd;

GRANT ALL ON `wzdftpd`.* TO "wzdftpd"@"localhost" IDENTIFIED BY "wzdftpd";

FLUSH PRIVILEGES;