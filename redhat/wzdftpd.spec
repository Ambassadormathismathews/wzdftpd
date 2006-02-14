
## Main package attributes

Name: wzdftpd
Summary: A very capable ftp server.
Version: 0.7.0
Release: 1
Packager: Chris Lount <mrlount@tiscali.co.uk>
URL: http://www.wzdftpd.net
Vendor: wzdftpd
Source: http://heanet.dl.sourceforge.net/sourceforge/wzdftpd/%{name}-%{version}.tar.gz
License: GPL
Group: System Environment/Daemons
BuildRoot: %{_tmppath}/%{name}-%{version}-build

%description

wzdftpd is designed to be run as root or non-root, It supports IPv6, SSL, and
is multithreaded. Server is fully configurable online using SITE commands, and
implements the lastest RFC extensions to FTP protocol.

Features are: flexible user management, acls, virtual users/groups, security,
speed, bandwith limitation, per command authorization, virtual directories,
dynamic ip changes auto-detection, etc.

It includes several authentication backends, is easily scriptable and provides
a powerful event-driven system to extend server.

For more informations, see http://www.wzdftpd.net/

## Perl module package attributes

%package mod-perl
Summary: Perl module for wzdftpd
Requires: wzdftpd = %{version}
Group: Development/Libraries/C and C++

%description mod-perl

This package provides the necessary files to run Perl plugins in wzdftpd,
and the perl module used to access libwzd, in the Perl module.

This package requires wzdftpd to be installed.

## TCL module package attributes

%package mod-tcl
Summary: TCL module for wzdftpd
Requires: wzdftpd = %{version}
Group: Development/Libraries/C and C++

%description mod-tcl

This package provides the necessary files to run TCL plugins in wzdftpd,
in the TCL module.

This package requires wzdftpd to be installed.

## MySQL backend package attributes

%package back-mysql
Summary: MySQL backend for wzdftpd
Requires: wzdftpd = %{version}
Group: Development/Libraries/C and C++

%description back-mysql

This package provides the necessary files to store users and groups
in MySQL for wzdftpd.

This package requires wzdftpd to be installed.

## Development package attributes

%package devel
Summary: The header files needed to develop new modules for wzdftpd
Requires: wzdftpd = %{version}
Group: Development/Libraries/C and C++

%description devel

The header files needed to develop new modules for wzdftpd.

This package requires wzdftpd to be installed.

## Package building

%prep

%setup -q

%build
prefix=/usr
./configure --prefix=${prefix} --mandir=${prefix}/share/man --infodir=${prefix}/share/info --datadir=${prefix}/lib --localstatedir=/var --sysconfdir=/etc/wzdftpd --with-pam --enable-ipv6

make CFLAGS="$RPM_OPT_FLAGS"

## Package installation

%install

mkdir -p $RPM_BUILD_ROOT/etc/init.d/
mkdir -p $RPM_BUILD_ROOT/var/logs/wzdftpd

touch $RPM_BUILD_ROOT/var/logs/wzdftpd/wzd.log
touch $RPM_BUILD_ROOT/var/logs/wzdftpd/xferlog

make install DESTDIR=$RPM_BUILD_ROOT
%__install -m 755 init.d/wzdftpd $RPM_BUILD_ROOT/etc/init.d/wzdftpd
%__install -m 755 wzdftpd/wzd.cfg.sample $RPM_BUILD_ROOT/etc/wzdftpd/wzd.cfg
%__install -m 755 wzdftpd/users.sample $RPM_BUILD_ROOT/etc/wzdftpd/users

## Main package pre and post install scripts

%post
ldconfig

%postun

rmdir -p --ignore-fail-on-non-empty /usr/share/wzdftpd/

## Clean

%clean
rm -Rf $RPM_BUILD_ROOT

## Main package files

%files

%doc README NEWS COPYING AUTHORS INSTALL TLS.ReadMeFirst ChangeLog UPGRADING
/usr/lib/libwzd.a
/usr/lib/libwzd.la
/usr/lib/libwzd.so*
/usr/lib/libwzd_core.a
/usr/lib/libwzd_core.la
/usr/lib/libwzd_core.so*
/usr/sbin/wzdftpd
/var/logs/wzdftpd
/usr/lib/wzdftpd/backends/libwzdplaintext.so
/usr/lib/wzdftpd/backends/libwzdpam.so
/usr/lib/wzdftpd/modules/libwzd_sfv.so
%config /etc/wzdftpd/wzd.cfg
%config /etc/wzdftpd/wzd.pem
%config /etc/wzdftpd/file_ginfo.txt
%config /etc/wzdftpd/file_group.txt
%config /etc/wzdftpd/file_groups.txt
%config /etc/wzdftpd/file_help.txt
%config /etc/wzdftpd/file_rules.txt
%config /etc/wzdftpd/file_swho.txt
%config /etc/wzdftpd/file_user.txt
%config /etc/wzdftpd/file_users.txt
%config /etc/wzdftpd/file_vfs.txt
%config /etc/wzdftpd/file_who.txt
%config /etc/wzdftpd/users
/etc/init.d/wzdftpd
/usr/bin/siteconfig
/usr/bin/siteuptime
/usr/bin/sitewho
/usr/share/man/man1/site*
/usr/share/man/man8

## Perl module package files

%files mod-perl
/usr/lib/wzdftpd/modules/libwzd_perl.so
/usr/lib/perl5
/usr/share/man/man3/wzdftpd.3pm.gz

## TCL module package files

%files mod-tcl
/usr/lib/wzdftpd/modules/libwzd_tcl.so

## MySQL backend package files

%files back-mysql
/usr/lib/wzdftpd/backends/libwzdmysql.so

## Development package files

%files devel
/usr/include/wzdftpd/
/usr/share/man/man1/wzd-config.1.gz
/usr/bin/wzd-config
/usr/lib/aclocal

## Changelog

%changelog
* Wed Oct 23 2005 Pierre Chifflier <chifflier@cpe.fr>
- New upstream release

* Wed Oct 05 2005 Pierre Chifflier <chifflier@cpe.fr>
- New upstream release (Security update)

* Mon Jul 09 2005 Pierre Chifflier <chifflier@cpe.fr>
- New upstream release

* Mon May 18 2005 Pierre Chifflier <chifflier@cpe.fr>
- New upstream release

* Mon Apr 18 2005 Pierre Chifflier <chifflier@cpe.fr>
- New upstream release
- Added MySQL backend

* Mon Mar 07 2005 Pierre Chifflier <chifflier@cpe.fr>
- New upstream release

* Mon Feb 21 2005 Pierre Chifflier <chifflier@cpe.fr>
- New upstream release

* Tue Dec 07 2004 Pierre Chifflier <chifflier@cpe.fr>
- New upstream release

* Thu Oct 28 2004 Pierre Chifflier <chifflier@cpe.fr>
- New upstream release

* Tue Oct 05 2004 Pierre Chifflier <chifflier@cpe.fr>
- New upstream release

* Wed Sep 15 2004 Pierre Chifflier <chifflier@cpe.fr>
- New upstream release

* Sat Sep 04 2004 Pierre Chifflier <chifflier@cpe.fr>
- New upstream release

* Thu Feb 19 2004 Chris Lount <mrlount@tiscali.co.uk>
- First binary release
