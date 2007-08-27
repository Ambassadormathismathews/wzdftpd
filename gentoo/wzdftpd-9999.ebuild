# Copyright 1999-2007 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

inherit eutils flag-o-matic subversion

SLOT="0"
LICENSE="GPL-2"
KEYWORDS="~amd64 ~x86"
DESCRIPTION="A portable, modular, small, and efficient FTP server"
SRC_URI=""
HOMEPAGE="http://www.wzdftpd.net"
IUSE="mysql postgres sqlite ssl ipv6 sfv zeroconf pam gnutls tcl perl utf8
		debug tests"
RESTRICT="strip"
ESVN_REPO_URI="https://svn.wzdftpd.net/svn/wzdftpd/trunk"
ESVN_PATCHES="${FILESDIR}/${P}-*.patch"

RDEPEND="sqlite? ( dev-db/sqlite )
			mysql? ( virtual/mysql )
			postgres? ( dev-db/postgresql )
			ssl? ( dev-libs/openssl )
			gnutls? ( net-libs/gnutls )
			pam? ( sys-libs/pam )
			tcl? ( dev-lang/tcl )
			perl? ( dev-lang/perl )
			zeroconf? ( net-dns/avahi )"

DEPEND="${RDEPEND}
			>=dev-util/cmake-2.4.6"

pkg_setup() {
	if use ssl && use gnutls; then
		eerror "You may select either OpenSSL (ssl) or GnuTLS (gnutls) USE"
		eerror "flags but not both at the same time. Please disable one of"
		eerror "these USE flags for the wzdftpd package."
		die "Cannot install with both ssl and gnutls flags selected"
	fi
	if use perl; then
		if ! built_with_use perl ithreads; then
			eerror "You must compile dev-lang/perl with the ithreads USE"
			eerror "flag if you want to build the wzdftpd Perl module."
			die "You must compile dev-lang/perl with the ithreads USE flag"
		fi
	fi
}

src_unpack() {
	subversion_src_unpack
}

src_compile() {
	local CMAKE_VARIABLES=""

	if use debug; then
		append-flags -ggdb -o1
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DDEBUG:BOOL=ON -DCMAKE_BUILD_TYPE:STRING=Debug"
	else
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DDEBUG:BOOL=OFF -DCMAKE_BUILD_TYPE:STRING=Release"
	fi

	if use sqlite; then
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_SQLite3:BOOL=ON"
	else
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_SQLite3:BOOL=OFF"
	fi

	if use mysql; then
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_MySQL:BOOL=ON"
	else
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_MySQL:BOOL=OFF"
	fi

	if use postgres; then
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_PostgreSQL:BOOL=ON"
	else
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_PostgreSQL:BOOL=OFF"
	fi

	if use ssl; then
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_OpenSSL:BOOL=ON"
	else
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_OpenSSL:BOOL=OFF"
	fi

	if use gnutls; then
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_GnuTLS:BOOL=ON"
	else
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_GnuTLS:BOOL=OFF"
	fi

	if use pam; then
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_PAM:BOOL=ON"
	else
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_PAM:BOOL=OFF"
	fi

	if use tcl; then
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_TCLDev:BOOL=ON"
	else
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_TCLDev:BOOL=OFF"
	fi

	if use perl; then
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_PerlDev:BOOL=ON"
	else
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_PerlDev:BOOL=OFF"
	fi

	if use zeroconf; then
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_Zeroconf:BOOL=ON"
	else
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_Zeroconf:BOOL=OFF"
	fi

	if use ipv6; then
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_IPV6:BOOL=ON"
	else
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_IPV6:BOOL=OFF"
	fi

	if use utf8; then
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_UTF8:BOOL=ON"
	else
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_UTF8:BOOL=OFF"
	fi

	if use tests; then
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_TESTS:BOOL=ON"
	else
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_TESTS:BOOL=OFF"
	fi
	
	if use sfv; then
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_SFV:BOOL=ON"
	else
		CMAKE_VARIABLES="${CMAKE_VARIABLES} -DWITH_SFV:BOOL=OFF"
	fi

	CMAKE_VARIABLES="${CMAKE_VARIABLES} -DCMAKE_INSTALL_PREFIX:PATH=/usr"
	CMAKE_VARIABLES="${CMAKE_VARIABLES} -DCONF_INSTALL_PATH:PATH=/etc/wzdftpd"

	mkdir "${WORKDIR}/${P}-cmake"
	cd "${WORKDIR}/${P}-cmake" || die "Could not create/access temporary CMake directory"

	cmake ${CMAKE_VARIABLES} "${S}" && cmake ${CMAKE_VARIABLES} "${S}"\
		|| die "CMake configuration failed"
	emake -j1 || die "emake build of wzdftpd failed"
}

src_install() {
	cd "${WORKDIR}/${P}-cmake" || die "Could not access temporary CMake directory"
	einstall -j1 DESTDIR="${D}" || die "Installation of wzdftpd failed"
}
