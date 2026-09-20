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

# The build of the source. OpenBSD make reads this file, and GNU make
# reads GNUmakefile for the document gates.
#
# The C sources sit flat in this directory, and the test sources sit
# in regress. lib builds the archive of the flat sources, and regress
# builds the tests of that archive. The layout follows usr.bin/ssh of
# the OpenBSD tree.
#
# The source holds no program yet, so SUBDIR names these two
# directories only. Each program gets a directory of its own, and
# that directory reads bsd.prog.mk.

# The regress loop links the archive of lib, so it must run after the
# build loop. bsd.subdir.mk declares regress with the double-colon
# operator, and this line must use the same operator.

regress:: all

SUBDIR=	lib regress

.include <bsd.subdir.mk>
