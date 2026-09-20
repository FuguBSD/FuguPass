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

# kat, the known-answer tests of the derivation tree. bsd.regress.mk
# builds the program of PROG and runs it, and a run of exit 0 is a
# pass.
#
# Two include directories reach the two headers of kat.c. The first
# one holds the interface of the flat sources, and the second one
# holds the vectors as vectors/derive.h. The two files share the name
# derive.h, and neither directory holds the path of the other file.
#
# The archive one directory up links nothing, so this directory owns
# the link line of the two libraries. libsecp256k1 comes from the
# ports tree, under LOCALBASE. The lookup of the archive follows
# usr.bin/ssh/Makefile.inc of the OpenBSD tree: an object directory
# holds the archive when it exists.

.include <bsd.own.mk>

PROG=		kat

CFLAGS+=	-Wall -Wextra -Werror
CFLAGS+=	-I${.CURDIR}/..
CFLAGS+=	-I${.CURDIR}/../../tests

LOCALBASE?=	/usr/local
LIBFUGUPASS=	${.CURDIR}/../lib

.if exists(${LIBFUGUPASS}/${__objdir})
LDADD+=		-L${LIBFUGUPASS}/${__objdir} -lfugupass
DPADD+=		${LIBFUGUPASS}/${__objdir}/libfugupass.a
.else
LDADD+=		-L${LIBFUGUPASS} -lfugupass
DPADD+=		${LIBFUGUPASS}/libfugupass.a
.endif

LDADD+=		-lcrypto -L${LOCALBASE}/lib -lsecp256k1
DPADD+=		${LIBCRYPTO}

.include <bsd.regress.mk>
