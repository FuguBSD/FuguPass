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

# fugupass, the core process of PROG-SPLIT-1. This directory holds
# no C source: each source of the program sits flat one directory
# up, and .PATH finds it there (PROG-BUILD-1, PROG-BUILD-2).
#
# SRCS names each source of this one program. A source that more
# than one directory shares belongs to the archive of lib, and
# src/lib/Makefile names it there.
#
# bsd.prog.mk derives the manual page name from PROG, so this
# directory holds fugupass.1 and this file holds no MAN line.
#
# The archive of lib holds every other source of the program, and
# this file links it with the library list of that archive.
# libsecp256k1 comes from the ports tree, under LOCALBASE.
# bcrypt_pbkdf(3) comes from libutil of the base system. http.c
# reads <tls.h> of libtls, and libtls needs libssl. The lookup of
# the archive tests the obj directory of lib. make obj puts the
# archive there, and a tree without make obj holds the archive in
# lib. This file writes the literal name obj, because make reads the
# condition before bsd.own.mk sets ${__objdir}.

.include <bsd.own.mk>

PROG=		fugupass
SRCS=		fugupass.c

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

LDADD+=		-ltls -lssl -lcrypto -lutil -L${LOCALBASE}/lib -lsecp256k1
DPADD+=		${LIBTLS} ${LIBSSL} ${LIBCRYPTO} ${LIBUTIL}

.include <bsd.prog.mk>
