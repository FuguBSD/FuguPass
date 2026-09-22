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
# in regress. lib builds the archive of the flat sources, fugupass
# builds the core process from that archive, and regress builds the
# tests of it. The layout follows usr.bin/ssh of the OpenBSD tree.
#
# Each program gets a directory of its own, and a program with a C
# source builds there through bsd.prog.mk (PROG-BUILD-2). fugupass
# and fugupass-qr are two of them. fugupass-repl is Perl, so its
# directory holds the manual page of it alone, and SUBDIR below does
# not name that directory.
#
# The regress loop links the archive of lib, so it must run after the
# build loop. bsd.subdir.mk declares regress with the double-colon
# operator, and this line must use the same operator.
#
# SUBDIR holds the build order of the loop: lib builds the archive
# that each program links, and regress comes last.

regress:: all

SUBDIR=	lib fugupass fugupass-qr regress

.include <bsd.subdir.mk>
