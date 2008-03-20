# Copyright 1999-2007 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

inherit eutils flag-o-matic cmake-utils

SLOT="0"
LICENSE="GPL-2"
KEYWORDS="~amd64 ~x86"
DESCRIPTION="A portable, modular, small, and efficient FTP server"
SRC_URI="mirror://sourceforge/${PN}/${P}.tar.gz"
HOMEPAGE="http://www.wzdftpd.net"
IUSE="mysql postgres sqlite ssl ipv6 sfv zeroconf pam gnutls tcl perl utf8 debug test"
RESTRICT="strip"

RDEPEND="sqlite? ( dev-db/sqlite )
	mysql? ( virtual/mysql )
	postgres? ( dev-db/postgresql )
	gnutls? ( net-libs/gnutls )
	!gnutls? ( ssl? ( dev-libs/openssl ) )
	pam? ( sys-libs/pam )
	tcl? ( dev-lang/tcl )
	perl? ( dev-lang/perl )
	zeroconf? ( net-dns/avahi )"

DEPEND="${RDEPEND}"

pkg_setup() {
	if use perl; then
		if ! built_with_use perl ithreads; then
			eerror "You must compile dev-lang/perl with the ithreads USE"
			eerror "flag if you want to build the wzdftpd Perl module."
			die "You must compile dev-lang/perl with the ithreads USE flag"
		fi
	fi
}

src_compile() {
	use debug && append-flags -ggdb -O1

	mycmakeargs="${mycmakeargs}
		$(cmake-utils_use_with sqlite SQLite3)
		$(cmake-utils_use_with mysql MySQL)
		$(cmake-utils_use_with postgres PostgreSQL)
		$(cmake-utils_use_with gnutls GnuTLS)
		$(cmake-utils_use_with ssl OpenSSL)
		$(cmake-utils_use_with pam PAM)
		$(cmake-utils_use_with tcl TCLDev)
		$(cmake-utils_use_with perl PerlDev)
		$(cmake-utils_use_with zeroconf Zeroconf)
		$(cmake-utils_use_with ipv6 IPV6)
		$(cmake-utils_use_with utf8 UTF8)
		$(cmake-utils_use_with sfv SFV)
		$(cmake-utils_use_with test TESTS)
		-DDEBUG:BOOL=$(use debug && echo ON || echo OFF)
		-DCONF_INSTALL_PATH:PATH=/etc/wzdftpd
	"
		
	cmake-utils_src_compile
}
