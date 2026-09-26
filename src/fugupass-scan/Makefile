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

# fugupass-scan, the scan helper of PROG-SPLIT-1. This directory
# holds no C source: fugupass-scan.c sits flat one directory up, and
# .PATH finds it there (PROG-BUILD-1, PROG-BUILD-2).
#
# SRCS names the one source of this program. scan.c holds every other
# part of it, and src/regress links it as well, so that source
# belongs to the archive of lib (PROG-BUILD-1).
#
# The archive of lib holds scan.c and wordlist.c, and the archive of
# quirc holds the QR decoder (PROG-BUILD-5). This file links both.
# The lookup of an archive tests the obj directory of it. make obj
# puts the archive there, and a tree without make obj holds the
# archive in the source directory. This file writes the literal name
# obj, because make reads the condition before bsd.own.mk sets
# ${__objdir}.
#
# This program links no library of the ports tree, so no line here
# reads LOCALBASE. quirc needs the standard C functions alone.

.include <bsd.own.mk>

PROG=		fugupass-scan
SRCS=		fugupass-scan.c

.PATH:		${.CURDIR}/..

CFLAGS+=	-Wall -Wextra -Werror
CFLAGS+=	-I${.CURDIR}/..

LIBFUGUPASS=	${.CURDIR}/../lib
LIBFUGUQUIRC=	${.CURDIR}/../quirc

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

# rint(3) of the vendored decoder comes from libm of the base system.
# arm64 inlines the call, and amd64 does not.
LDADD+=		-lm
DPADD+=		${LIBM}

.include <bsd.prog.mk>
