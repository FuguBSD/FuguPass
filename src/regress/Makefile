#
# Copyright (c) 2026 Dick Olsson <hi@senzilla.io>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# envelope, http, kat, oracle-client, qr, sandbox, scan, share and
# vault, the nine programs of this directory. bsd.regress.mk builds
# each program of PROGS, and a run of exit 0 is a pass. envelope
# holds the known-answer tests of the oracle protocol, kat holds the
# tests of the derivation tree, qr holds the tests of the render
# helper, sandbox holds the test of the unveil list and the pledge
# call, scan holds the tests of the scan helper, share holds the
# tests of the custody layer, and vault holds the tests of the vault
# on disk. Each of those seven is a whole test, and REGRESS_TARGETS
# names the default target of it.
#
# sandbox runs on OpenBSD alone, because unveil(2) and pledge(2)
# restrict this process. qr runs there as well, for the pledge call
# of the render helper, and scan reads <sys/videoio.h> of that
# system. Every program of this directory builds on OpenBSD alone
# (PROG-BUILD-1).
#
# http is the driver of the transport tests, and it holds no test
# of its own. A test of a transport needs a peer, so http.t starts
# a fixture server of the base Perl, and it drives the program
# against that server. A bare run of the driver tests nothing, so
# REGRESS_TARGETS names run-http in place of the default target of
# that program. The script reads no standard input, and the rule
# below gives it none.
#
# oracle-client is the driver of the record tests, and it holds no
# test of its own. A test of a record needs a live counterparty, so
# the interop harness starts one and drives this program against it
# (TEST-HARNESS-1). A run of make regress must not start that
# counterparty, so this file names oracle-client in PROGS and in no
# REGRESS_TARGETS line. The program therefore builds here, and the
# harness runs it.
#
# REGRESS_TARGETS replaces the default list, so every program of
# PROGS needs a line there. A program that no line names builds and
# never runs. oracle-client is the one deliberate case of that
# above, for the reason that the paragraph before this one states.
# Every other program of PROGS takes a line.
#
# bsd.prog.mk takes the source of each program from the name of it,
# so envelope.c, http.c, kat.c, oracle-client.c, qr.c, sandbox.c,
# scan.c, share.c and vault.c need no SRCS line. Every test source
# sits in this one directory (PROG-BUILD-1).
#
# Two include directories reach the headers of a test. The first one
# holds the interfaces of the flat sources, and the second one holds
# the vectors, as vectors/derive.h, vectors/oracle.h, vectors/seal.h
# and vectors/share.h. Two files share the name derive.h, two files
# share the name share.h, and two files share the name seal.h.
# Neither directory holds the path of the other file of a name.
# envelope.c holds a name of its own in each directory: the interface
# is envelope.h, and the vectors are vectors/oracle.h.
#
# Five C files of this directory carry the name of an archive
# source: envelope.c, http.c, qr.c, sandbox.c and scan.c. This
# directory holds the test, and the directory above holds the
# archive source. This file sets no .PATH, so each program takes the
# source of this directory, and the archive carries the other one.
#
# The archive one directory up links nothing, so this directory owns
# the link line of the libraries. libsecp256k1 and libqrencode come
# from the ports tree, under LOCALBASE. bcrypt_pbkdf(3) comes from
# libutil of the base system. http.c reads <tls.h> of libtls, and libtls needs
# libssl. The vendored QR decoder comes from the archive of quirc
# (PROG-BUILD-5), and it calls rint(3) of libm. The lookup of an
# archive tests the obj directory of it. make obj puts an archive
# there, and a tree without make obj holds it in the source
# directory. This file writes the literal name obj, because make
# reads the condition before bsd.own.mk sets ${__objdir}.

.include <bsd.own.mk>

PROGS=		envelope http kat oracle-client qr sandbox scan share vault

# bsd.prog.mk takes a manual page name from each name of PROGS, and
# this directory holds no manual page. That line sets a value for an
# unset variable only, so the empty value here stops the default.
MAN=

CFLAGS+=	-Wall -Wextra -Werror
CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${.CURDIR}/../../tests

LOCALBASE?=	/usr/local
LIBFUGUPASS=	${.CURDIR}/../lib
LIBFUGUQUIRC=	${.CURDIR}/../quirc

# envelope.c and share.c read <secp256k1.h> of the ports tree.
CFLAGS+=	-I${LOCALBASE}/include

# scan.c reads quirc.h of the vendored decoder (PROG-BUILD-5).
CFLAGS+=	-I${LIBFUGUQUIRC}

# qr.c and scan.c read the pictures of tests/vectors/seedqr at a run.
# A picture is text and no C header, because vector4.picture is the
# byte-for-byte copy of the FuguSeed fixture. That directory holds
# the commit and the digest of each picture.
SEEDQR=		${.CURDIR}/../../tests/vectors/seedqr
CFLAGS+=	-DQR_PICTURE=\"${SEEDQR}/vector4.picture\"
CFLAGS+=	-DSEEDQR_DIR=\"${SEEDQR}\"

.if exists(${LIBFUGUPASS}/obj)
LDADD+=		-L${LIBFUGUPASS}/obj -lfugupass
DPADD+=		${LIBFUGUPASS}/obj/libfugupass.a
.else
LDADD+=		-L${LIBFUGUPASS} -lfugupass
DPADD+=		${LIBFUGUPASS}/libfugupass.a
.endif

.if exists(${LIBFUGUQUIRC}/obj)
LDADD+=		-L${LIBFUGUQUIRC}/obj -lfuguquirc
DPADD+=		${LIBFUGUQUIRC}/obj/libfuguquirc.a
.else
LDADD+=		-L${LIBFUGUQUIRC} -lfuguquirc
DPADD+=		${LIBFUGUQUIRC}/libfuguquirc.a
.endif

LDADD+=		-ltls -lssl -lcrypto -lutil -lm
LDADD+=		-L${LOCALBASE}/lib -lsecp256k1 -lqrencode
DPADD+=		${LIBTLS} ${LIBSSL} ${LIBCRYPTO} ${LIBUTIL} ${LIBM}

# http.t writes the request of one case, and the body of one case,
# in the object directory.
CLEANFILES+=	http.body http.request

REGRESS_TARGETS=	run-regress-envelope run-regress-kat \
			run-regress-qr run-regress-sandbox \
			run-regress-scan run-regress-share \
			run-regress-vault run-http

run-http: http
	perl ${.CURDIR}/http.t ${.OBJDIR}/http </dev/null

.PHONY: run-http

.include <bsd.regress.mk>
