Name: wzdftpd
Summary: A very capable ftp server.
Version: 0.2.1
Release: 1
Packager: Chris Lount <mrlount@tiscali.co.uk>
URL: http://wzdftpd.sourceforge.net
Source: http://heanet.dl.sourceforge.net/sourceforge/wzdftpd/%{name}-%{version}.tar.gz
License: GPL
Group: System Environment/Daemons
BuildRoot: %{_tmppath}/%{name}-%{version}-build
Prefix: /usr/local
Prefix: %_sysconfdir
Provides: wzdftpd
Conflicts: wzdftpd-ssl

%description

A portable, modular and efficient ftp server, supporting SSL,
winsock, multithreaded, modules, externals scripts. unix-like
permissions+acls, virtual users/groups, security, speed, bandwith
limitation (user,group,global), group admins, per command auth

If you would like to use SSL, please download the package wzdftpd-ssl
from http://wzdftpd.sourceforge.net

%package devel
Summary: The header files needed to develop new modules for wzdftpd
Requires: wzdftpd
Group: Development/Libraries

%description devel

The header files needed to develop new modules for wzdftpd.
This package requires either wzdftpd or wzdftpd-ssl to be installed.

%package tools
Summary: Tools for use with wzftpd
Requires: wzdftpd
Group: Applications/System

%description tools

The site tools for the wzdftpd ftp daemon.

This package requires either wzftpd or wzftpd-ssl to be installed.

%prep

%setup -q

%build
./configure --prefix=/usr/local --enable-ipv6 --sysconfdir=%_sysconfdir

make CFLAGS="$RPM_OPT_FLAGS"

%install

mkdir -p $RPM_BUILD_ROOT/usr/local/{bin,lib,sbin,share}
mkdir -p $RPM_BUILD_ROOT/usr/local/share/wzdftpd/{modules,backends,logs}
mkdir -p $RPM_BUILD_ROOT%_sysconfdir/init.d/
%__install src/wzd.cfg $RPM_BUILD_ROOT/%_sysconfdir/
%__install src/wzd.pem $RPM_BUILD_ROOT/%_sysconfdir/
%__install -s tools/siteconfig/.libs/siteconfig $RPM_BUILD_ROOT/usr/local/bin/
%__install -s tools/siteuptime/siteuptime $RPM_BUILD_ROOT/usr/local/bin/
%__install -s tools/sitewho/sitewho $RPM_BUILD_ROOT/usr/local/bin/
%__install src/.libs/libwzd.a $RPM_BUILD_ROOT/usr/local/lib/
%__install src/.libs/libwzd.la $RPM_BUILD_ROOT/usr/local/lib/
%__install src/.libs/libwzd.so $RPM_BUILD_ROOT/usr/local/lib/
%__install -s src/.libs/wzdftpd $RPM_BUILD_ROOT/usr/local/sbin/
%__install backends/plaintext/.libs/libwzdplaintext.a $RPM_BUILD_ROOT/usr/local/share/wzdftpd/backends/
%__install backends/plaintext/.libs/libwzdplaintext.la $RPM_BUILD_ROOT/usr/local/share/wzdftpd/backends/
%__install backends/plaintext/.libs/libwzdplaintext.so $RPM_BUILD_ROOT/usr/local/share/wzdftpd/backends/
%__install src/file_ginfo.txt $RPM_BUILD_ROOT/usr/local/share/wzdftpd/
%__install src/file_group.txt $RPM_BUILD_ROOT/usr/local/share/wzdftpd/
%__install src/file_groups.txt $RPM_BUILD_ROOT/usr/local/share/wzdftpd/
%__install src/file_help.txt $RPM_BUILD_ROOT/usr/local/share/wzdftpd/
%__install src/file_rules.txt $RPM_BUILD_ROOT/usr/local/share/wzdftpd/
%__install src/file_swho.txt $RPM_BUILD_ROOT/usr/local/share/wzdftpd/
%__install src/file_user.txt $RPM_BUILD_ROOT/usr/local/share/wzdftpd/
%__install src/file_users.txt $RPM_BUILD_ROOT/usr/local/share/wzdftpd/
%__install src/file_vfs.txt $RPM_BUILD_ROOT/usr/local/share/wzdftpd/
%__install src/file_who.txt $RPM_BUILD_ROOT/usr/local/share/wzdftpd/
%__install modules/sfv/.libs/libwzd_sfv.a $RPM_BUILD_ROOT/usr/local/share/wzdftpd/modules/
%__install modules/sfv/.libs/libwzd_sfv.la $RPM_BUILD_ROOT/usr/local/share/wzdftpd/modules/
%__install modules/sfv/.libs/libwzd_sfv.so $RPM_BUILD_ROOT/usr/local/share/wzdftpd/modules/
%__install src/users $RPM_BUILD_ROOT/usr/local/share/wzdftpd/
%__install -m 755 init.d/wzdftpd $RPM_BUILD_ROOT%_sysconfdir/init.d/wzdftpd
touch $RPM_BUILD_ROOT/usr/local/share/wzdftpd/logs/xferlog
touch $RPM_BUILD_ROOT/usr/local/share/wzdftpd/logs/wzd.log
mkdir -p $RPM_BUILD_ROOT/usr/local/include/wzdftpd
%__install src/*.h $RPM_BUILD_ROOT/usr/local/include/wzdftpd/

%post

ldconfig

%clean
rm -Rf $RPM_BUILD_ROOT

%postun

rmdir --ignore-fail-on-non-empty -p $RPM_BUILD_ROOT/usr/local/include/wzdftpd/ $RPM_BUILD_ROOT/usr/local/share/wzdftpd/modules
rmdir --ignore-fail-on-non-empty -p $RPM_BUILD_ROOT/usr/local/share/wzdftpd/backends $RPM_BUILD_ROOT/usr/local/share/wzdftpd/logs $RPM_BUILD_ROOT/%_sysconfdir/init.d

%files

%doc README NEWS COPYING AUTHORS INSTALL TLS.ReadMeFirst ChangeLog
%config /%_sysconfdir/wzd.cfg
%config /%_sysconfdir/wzd.pem
/usr/local/lib/libwzd.a
/usr/local/lib/libwzd.la
/usr/local/lib/libwzd.so
/usr/local/sbin/wzdftpd
/usr/local/share/wzdftpd/backends
%config /usr/local/share/wzdftpd/file_ginfo.txt
%config /usr/local/share/wzdftpd/file_group.txt
%config /usr/local/share/wzdftpd/file_groups.txt
%config /usr/local/share/wzdftpd/file_help.txt
%config /usr/local/share/wzdftpd/file_rules.txt
%config /usr/local/share/wzdftpd/file_swho.txt
%config /usr/local/share/wzdftpd/file_user.txt
%config /usr/local/share/wzdftpd/file_users.txt
%config /usr/local/share/wzdftpd/file_vfs.txt
%config /usr/local/share/wzdftpd/file_who.txt
/usr/local/share/wzdftpd/logs/xferlog
/usr/local/share/wzdftpd/modules
%config /usr/local/share/wzdftpd/users
%_sysconfdir/init.d/wzdftpd

%files tools
/usr/local/bin/siteconfig
/usr/local/bin/siteuptime
/usr/local/bin/sitewho

%files devel

/usr/local/include/wzdftpd/list.h
/usr/local/include/wzdftpd/wzd_cache.h
/usr/local/include/wzdftpd/wzd_hardlimits.h
/usr/local/include/wzdftpd/wzd_mod.h
/usr/local/include/wzdftpd/wzd_site.h
/usr/local/include/wzdftpd/wzd_types.h
/usr/local/include/wzdftpd/ls.h
/usr/local/include/wzdftpd/wzd_crc32.h
/usr/local/include/wzdftpd/wzd_init.h
/usr/local/include/wzdftpd/wzd_opts.h
/usr/local/include/wzdftpd/wzd_site_group.h
/usr/local/include/wzdftpd/wzd_vfs.h
/usr/local/include/wzdftpd/stack.h
/usr/local/include/wzdftpd/wzd_crontab.h
/usr/local/include/wzdftpd/wzd_libmain.h
/usr/local/include/wzdftpd/wzd_perm.h
/usr/local/include/wzdftpd/wzd_site_user.h
/usr/local/include/wzdftpd/wzd_ClientThread.h
/usr/local/include/wzdftpd/wzd_data.h
/usr/local/include/wzdftpd/wzd_log.h
/usr/local/include/wzdftpd/wzd_ratio.h
/usr/local/include/wzdftpd/wzd_socket.h
/usr/local/include/wzdftpd/wzd_ServerThread.h
/usr/local/include/wzdftpd/wzd_debug.h
/usr/local/include/wzdftpd/wzd_md5.h
/usr/local/include/wzdftpd/wzd_savecfg.h
/usr/local/include/wzdftpd/wzd_strtok_r.h
/usr/local/include/wzdftpd/wzd_action.h
/usr/local/include/wzdftpd/wzd_dir.h
/usr/local/include/wzdftpd/wzd_messages.h
/usr/local/include/wzdftpd/wzd_section.h
/usr/local/include/wzdftpd/wzd_structs.h
/usr/local/include/wzdftpd/wzd_backend.h
/usr/local/include/wzdftpd/wzd_file.h
/usr/local/include/wzdftpd/wzd_misc.h
/usr/local/include/wzdftpd/wzd_shm.h
/usr/local/include/wzdftpd/wzd_tls.h

%changelog

* Sat Feb 14 2004 Chris Lount <mrlount@tiscali.co.uk>
- First binary release

