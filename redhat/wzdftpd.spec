
## Main package attributes

Name: wzdftpd
Summary: A very capable ftp server.
Version: 0.2.3
Release: 1
Packager: Chris Lount <mrlount@tiscali.co.uk>
URL: http://wzdftpd.sourceforge.net
Vendor: wzdftpd
Source: http://heanet.dl.sourceforge.net/sourceforge/wzdftpd/%{name}-%{version}.tar.gz
License: GPL
Group: System Environment/Daemons
BuildRoot: %{_tmppath}/%{name}-%{version}-build
Provides: wzdftpd
Conflicts: wzdftpd-ssl

%description

A portable, modular and efficient ftp server, supporting SSL,
winsock, multithreaded, modules, externals scripts. unix-like
permissions+acls, virtual users/groups, security, speed, bandwith
limitation (user,group,global), group admins, per command auth

If you would like to use SSL, please download the package wzdftpd-ssl
from http://wzdftpd.sourceforge.net

## Development package attributes

%package devel
Summary: The header files needed to develop new modules for wzdftpd
Requires: wzdftpd = %{version}
Group: Development/Libraries/C and C++

%description devel

The header files needed to develop new modules for wzdftpd.

This package requires either wzdftpd or wzdftpd-ssl to be installed.

## Tools package attributes

%package tools
Summary: Tools for use with wzftpd
Requires: wzdftpd = %{version}
Group: Applications/System

%description tools

The site tools for the wzdftpd ftp daemon.

This package requires either wzdftpd or wzdftpd-ssl to be installed.

## Package building

%prep

%setup -q

%build
./configure --prefix=/usr/local --enable-ipv6 --target=%{_target_cpu} --sysconfdir=%_sysconfdir

make CFLAGS="$RPM_OPT_FLAGS"

## Package installation

%install

mkdir -p $RPM_BUILD_ROOT/usr/local/{bin,lib,sbin,share}
mkdir -p $RPM_BUILD_ROOT/usr/local/share/wzdftpd/{modules,backends,logs}
mkdir -p $RPM_BUILD_ROOT%_sysconfdir/init.d/
%__install src/wzd.cfg $RPM_BUILD_ROOT%_sysconfdir/
%__install src/wzd.pem $RPM_BUILD_ROOT%_sysconfdir/
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

## Main package pre and post install scripts

%post
ldconfig

%postun

rmdir -p --ignore-fail-on-non-empty /usr/local/share/wzdftpd/

## Clean

%clean
rm -Rf $RPM_BUILD_ROOT

## Main package files

%files

%doc README NEWS COPYING AUTHORS INSTALL TLS.ReadMeFirst ChangeLog
%config %_sysconfdir/wzd.cfg
%config %_sysconfdir/wzd.pem
/usr/local/lib/libwzd.a
/usr/local/lib/libwzd.la
/usr/local/lib/libwzd.so
/usr/local/sbin/wzdftpd
/usr/local/share/wzdftpd/logs
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
/usr/local/share/wzdftpd/modules
%config /usr/local/share/wzdftpd/users
%_sysconfdir/init.d/wzdftpd

## Tools package files

%files tools
/usr/local/bin/siteconfig
/usr/local/bin/siteuptime
/usr/local/bin/sitewho

## Development package files

%files devel
/usr/local/include/wzdftpd/

## Changelog

%changelog
* Thu Feb 19 2004 Chris Lount <mrlount@tiscali.co.uk>
- First binary release
