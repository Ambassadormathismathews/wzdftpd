# general considerations:
#
# comment lines begin by #
# empty lines are removed
#
# directives have format: <tagname>=<value>
# with the regexp: ^([a-zA-Z0-9_]+)[ \t]*=[ \t]*(.+)
#
# directives are grouped into sections
# section begins by [SECTIONNAME]

# groups definitions
[GROUPS]
privgroup	admin
ip_allowed=127.0.0.1
ip_allowed=::ffff:127.0.0.1
ip_allowed=::1
default_home=@CMAKE_INSTALL_PREFIX@/@ftproot@/ftp
rights=0xffffffff
gid=0

# users definitions
# users MUST begin by line name=<>
[USERS]
name=wzdftpd
pass=Oz1iHGIgV8HIQ
home=@CMAKE_INSTALL_PREFIX@/@ftproot@/ftp
uid=0
groups=admin
rights=0xffffffff
tagline=wzdftpd
ip_allowed=127.0.0.1
ip_allowed=::ffff:127.0.0.1
ip_allowed=::1
bytes_ul_total=0
bytes_dl_total=0
num_logins=1
flags=OIstH