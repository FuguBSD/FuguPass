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

# libfuguquirc.a, the QR decoder of the scan helper (PROG-BUILD-5).
# This directory holds quirc of Daniel Beer, byte for byte, and
# SOURCE.md records the release, the digest of each file, and the
# license.
#
# The archive name is libfuguquirc.a, and not libquirc.a. The ports
# tree holds graphics/libquirc, and that package installs
# /usr/local/lib/libquirc.a. A link line that reads LOCALBASE must
# never take that file in place of this one, so the two names differ.
#
# The vendored sources do not take -Wextra: identify.c holds one
# unused parameter and two comparisons of a signed value with an
# unsigned one. This directory therefore builds with -Wall -Werror,
# and every source of this repository keeps -Wextra. A patch of the
# vendored code would break the digests of SOURCE.md.
#
# The archive stays inside the tree. It installs nothing, and it
# builds no shared object and no profiling object.

LIB=		fuguquirc
SRCS=		quirc.c identify.c decode.c version_db.c

CFLAGS+=	-Wall -Werror
CFLAGS+=	-I${.CURDIR}

NOPIC=		yes
NOPROFILE=	yes

install:
	@true

.include <bsd.lib.mk>
