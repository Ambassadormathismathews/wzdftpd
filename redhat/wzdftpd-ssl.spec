# Created from file wzdftpd.spec, therefore we have a lot of junk.

Name: wzdftpd-ssl
Summary: A very capable ftp server with ssl support
Version: 0.2
Release: 1
Packager: Chris Lount <mrlount@tiscali.co.uk>
URL: http://wzdftpd.sourceforge.net
Source: http://heanet.dl.sourceforge.net/sourceforge/wzdftpd/wzdftpd-%{version}.tar.gz
License: GPL
Group: System Environment/Daemons
BuildRoot: %{_tmppath}/%{name}-%{version}-build
Prefix: /usr/local
Prefix: %_sysconfdir

Provides: wzdftpd-ssl
Provides: wzdftpd

%description

A portable, modular and efficient ftp server, supporting SSL,
winsock, multithreaded, modules, externals scripts. unix-like
permissions+acls, virtual users/groups, security, speed, bandwith
limitation (user,group,global), group admins, per command auth


%prep

%setup -q

%build
./configure --prefix=/usr/local --enable-ssl --enable-ipv6 --sysconfdir=%_sysconfdir

make CFLAGS="$RPM_OPT_FLAGS"

%install

mkdir -p $RPM_BUILD_ROOT/usr/local/{bin,lib,sbin,share}
mkdir -p $RPM_BUILD_ROOT/usr/local/share/wzdftpd/{modules,backends,logs}
mkdir -p $RPM_BUILD_ROOT%_sysconfdir/init.d/
%__install src/wzd.cfg $RPM_BUILD_ROOT/%_sysconfdir/
%__install src/wzd.pem $RPM_BUILD_ROOT/%_sysconfdir/
#%__install -s tools/siteconfig/siteconfig $RPM_BUILD_ROOT/usr/local/bin/
#%__install -s tools/siteuptime/siteuptime $RPM_BUILD_ROOT/usr/local/bin/
#%__install -s tools/sitewho/sitewho $RPM_BUILD_ROOT/usr/local/bin/
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

%post

ldconfig

%clean
rm -Rf $RPM_BUILD_ROOT

%files

%doc README NEWS COPYING AUTHORS INSTALL TLS.ReadMeFirst ChangeLog
%config /%_sysconfdir/wzd.cfg
%config /%_sysconfdir/wzd.pem
#/usr/local/bin/siteconfig
#/usr/local/bin/siteuptime
#/usr/local/bin/sitewho
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

%changelog
* Fri Feb 08 2004 Chris Lount <mrlount@tiscali.co.uk>
- First binary release

