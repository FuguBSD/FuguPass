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

# libfugupass.a, the archive of the flat sources one directory up.
# .PATH finds them there, and SRCS names each one. A program
# directory and the regress directory link this archive, so each
# source compiles once.
#
# The archive stays inside the tree. It installs nothing, and it
# builds no shared object and no profiling object.

.PATH:		${.CURDIR}/..

LIB=		fugupass
SRCS=		bip85.c derive.c pin.c seal.c share.c wordlist.c

CFLAGS+=	-Wall -Wextra -Werror
CFLAGS+=	-I${.CURDIR}/..

# libsecp256k1 comes from the ports tree, under LOCALBASE.
# bip85.c reads its header, and each directory that links this
# archive adds -L${LOCALBASE}/lib -lsecp256k1 to LDADD.
LOCALBASE?=	/usr/local

CFLAGS+=	-I${LOCALBASE}/include

# bcrypt_pbkdf(3) comes from libutil of the base system. pin.c reads
# <util.h>, and each directory that links this archive adds -lutil
# to LDADD.

NOPIC=		yes
NOPROFILE=	yes

install:
	@true

.include <bsd.lib.mk>
