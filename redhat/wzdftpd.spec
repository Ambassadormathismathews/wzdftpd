
## Main package attributes

Name: wzdftpd
Summary: A very capable ftp server.
Version: 0.4.0
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
in the Perl module.

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

%doc README NEWS COPYING AUTHORS INSTALL TLS.ReadMeFirst ChangeLog
/usr/lib/libwzd.a
/usr/lib/libwzd.la
/usr/lib/libwzd.so*
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

## Perl module package files

%files mod-perl
/usr/lib/wzdftpd/modules/libwzd_perl.so

## TCL module package files

%files mod-tcl
/usr/lib/wzdftpd/modules/libwzd_tcl.so

## Development package files

%files devel
/usr/include/wzdftpd/

## Changelog

%changelog
* Sat Sep 04 2004 Pierre Chifflier <chifflier@cpe.fr>
- New upstream release

* Thu Feb 19 2004 Chris Lount <mrlount@tiscali.co.uk>
- First binary release
