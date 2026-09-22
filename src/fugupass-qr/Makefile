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

# fugupass-qr, the render helper of PROG-SPLIT-1. This directory
# holds no C source: fugupass-qr.c sits flat one directory up, and
# .PATH finds it there (PROG-BUILD-1, PROG-BUILD-2).
#
# SRCS names the one source of this program. qr.c holds every other
# part of it, and src/regress links it as well, so that source
# belongs to the archive of lib (PROG-BUILD-1).
#
# The archive of lib holds qr.c and wordlist.c, and this file links
# it with the library list of that archive. libqrencode makes each
# code (PROG-QR-5), and it comes from the ports tree, under
# LOCALBASE. The lookup of the archive tests the obj directory of
# lib. make obj puts the archive there, and a tree without make obj
# holds the archive in lib. This file writes the literal name obj,
# because make reads the condition before bsd.own.mk sets
# ${__objdir}.

.include <bsd.own.mk>

PROG=		fugupass-qr
SRCS=		fugupass-qr.c

.PATH:		${.CURDIR}/..

CFLAGS+=	-Wall -Wextra -Werror
CFLAGS+=	-I${.CURDIR}/..

LOCALBASE?=	/usr/local
LIBFUGUPASS=	${.CURDIR}/../lib

CFLAGS+=	-I${LOCALBASE}/include

.if exists(${LIBFUGUPASS}/obj)
LDADD+=		-L${LIBFUGUPASS}/obj -lfugupass
DPADD+=		${LIBFUGUPASS}/obj/libfugupass.a
.else
LDADD+=		-L${LIBFUGUPASS} -lfugupass
DPADD+=		${LIBFUGUPASS}/libfugupass.a
.endif

LDADD+=		-L${LOCALBASE}/lib -lqrencode

.include <bsd.prog.mk>
