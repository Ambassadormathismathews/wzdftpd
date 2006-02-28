Zeroconf Support For Wzdftpd
============================

Author: Daniel S. Haischt <me@daniel.stefan.haischt.name>

Known Issues:
-------------

* Bonjour support on Windows won't compile because of
  VC++ 6 incompatible headers (dns_sd.h)
* Missing process support on windows.

Description
-----------

This module adds support for Zeroconf using either...

 * Avahi (Linux)
 * Bonjour (BSD/Linux/OSX/Windows)
 * Howl (BSD/Linux/OSX/Windows)

Requirements to compile the module
----------------------------------

Either the Howl sources and binaries or the Apple
Bonjour SDK.

Further instructions
--------------------

The Wzdftpd wiki: http://www.wzdftpd.net/wiki/index.php/Zeroconf