COMMENT =	password manager for any secret on seed-phrase standards

GH_ACCOUNT =	FuguBSD
GH_PROJECT =	FuguPass
GH_TAGNAME =	v0.1.1
PKGNAME =	${DISTNAME:L}

CATEGORIES =	security

HOMEPAGE =	https://github.com/FuguBSD/FuguPass

MAINTAINER =	Dick Olsson <hi@senzilla.io>

# ISC
PERMIT_PACKAGE =	Yes

WANTLIB =	c crypto m qrencode secp256k1 ssl tls util

# The core process links libsecp256k1, and the render helper links
# libqrencode (PROG-PORT-3). The FuguOracle repository holds the
# security/libsecp256k1 port.
LIB_DEPENDS =	graphics/libqrencode \
		security/libsecp256k1

# The interface program is Perl on the Fugu library (PROG-PORT-3).
# The build runs src/unveil-paths of this tree, and that script
# loads Fugu::Sandbox of the library, so the port takes p5-Fugu at
# build time as well.
RUN_DEPENDS =	devel/p5-Fugu
BUILD_DEPENDS =	${RUN_DEPENDS}

# src/Makefile is the entry point of the C build (PROG-BUILD-2). The
# build skips regress: bsd.regress.mk runs the tests on all, and the
# test target enters that directory (PROG-PORT-4).
WRKSRC =	${WRKDIST}/src
MAKE_FLAGS =	SKIPDIR=regress

# The C regress programs, and http.t against a fixture server on the
# loopback interface. The run needs no network beyond it.
do-test:
	cd ${WRKSRC}/regress && ${SETENV} ${MAKE_ENV} ${MAKE_PROGRAM} regress

# The three C programs of src/ with their pages, and the Perl
# interface program of bin/ with its page (PROG-PORT-2). The core
# process runs the helpers from ${LOCALBASE}/bin.
do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/fugupass/fugupass \
		${WRKSRC}/fugupass-qr/fugupass-qr \
		${WRKSRC}/fugupass-scan/fugupass-scan ${PREFIX}/bin
	${INSTALL_SCRIPT} ${WRKDIST}/bin/fugupass-repl ${PREFIX}/bin
	${INSTALL_MAN} ${WRKSRC}/fugupass/fugupass.1 \
		${WRKSRC}/fugupass-qr/fugupass-qr.1 \
		${WRKSRC}/fugupass-scan/fugupass-scan.1 \
		${WRKSRC}/fugupass-repl/fugupass-repl.1 ${PREFIX}/man/man1
	${INSTALL_MAN} ${WRKSRC}/fugupass/fugupass.7 ${PREFIX}/man/man7

.include <bsd.port.mk>
