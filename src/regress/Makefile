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

# kat, share and vault, the three known-answer test programs.
# bsd.regress.mk builds each program of PROGS and runs it, and a run
# of exit 0 is a pass. kat holds the tests of the derivation tree,
# share holds the tests of the custody layer, and vault holds the
# tests of the vault on disk. bsd.prog.mk takes the source of each
# program from the name of it, so kat.c, share.c and vault.c need no
# SRCS line. Every test source sits in this one directory
# (PROG-BUILD-1).
#
# Two include directories reach the headers of a test. The first one
# holds the interfaces of the flat sources, and the second one holds
# the vectors, as vectors/derive.h, vectors/share.h and
# vectors/seal.h. Two files share the name derive.h, two files share
# the name share.h, and two files share the name seal.h. Neither
# directory holds the path of the other file of a name.
#
# The archive one directory up links nothing, so this directory owns
# the link line of the three libraries. libsecp256k1 comes from the
# ports tree, under LOCALBASE, and bcrypt_pbkdf(3) comes from libutil
# of the base system. The lookup of the archive tests the obj
# directory of lib. make obj puts the archive there, and a tree
# without make obj holds the archive in lib. This file writes the
# literal name obj, because make reads the condition before
# bsd.own.mk sets ${__objdir}.

.include <bsd.own.mk>

PROGS=		kat share vault

# bsd.prog.mk takes a manual page name from each name of PROGS, and
# this directory holds no manual page. That line sets a value for an
# unset variable only, so the empty value here stops the default.
MAN=

CFLAGS+=	-Wall -Wextra -Werror
CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${.CURDIR}/../../tests

LOCALBASE?=	/usr/local
LIBFUGUPASS=	${.CURDIR}/../lib

# share.c reads <secp256k1.h> of the ports tree.
CFLAGS+=	-I${LOCALBASE}/include

.if exists(${LIBFUGUPASS}/obj)
LDADD+=		-L${LIBFUGUPASS}/obj -lfugupass
DPADD+=		${LIBFUGUPASS}/obj/libfugupass.a
.else
LDADD+=		-L${LIBFUGUPASS} -lfugupass
DPADD+=		${LIBFUGUPASS}/libfugupass.a
.endif

LDADD+=		-lcrypto -lutil -L${LOCALBASE}/lib -lsecp256k1
DPADD+=		${LIBCRYPTO} ${LIBUTIL}

.include <bsd.regress.mk>
