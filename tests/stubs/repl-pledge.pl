#!/usr/bin/perl
# ex:ts=8 sw=4:
# $OpenBSD$
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

# repl-pledge.pl - prove the pledge of the interface program.
#
# usage: repl-pledge.pl <path of fugupass-repl> <path of a file>
#
# The harness leg 9-repl.pl runs this program in the guest
# (PROG-SPLIT-7, PROG-SPLIT-8). It loads the interface program as a
# module and calls main() of it, so the pledge call under test is
# the call of the shipped program and no copy of it.
#
# The program gets no request pipe and no reply pipe, so main()
# pledges, reports the absent pipe through Fugu::Log, and returns 1.
# This program then opens the file that the caller names. The
# promises hold no rpath, so that open must not reach the file.
#
# The program writes one line of each step, and the caller reads
# them. A pledge that holds kills this program on the open, so the
# 'open:' line never reaches the caller and the shell reports the
# signal.

use v5.34;
use warnings;
use experimental 'signatures';
no feature qw(indirect multidimensional bareword_filehandles);

use Fugu::Sandbox;

# The output goes line by line: the pledge kills this program in the
# middle of it, and a buffer would lose every line.
$| = 1;

my ( $program, $file ) = @ARGV;
die "usage: repl-pledge.pl <program> <file>\n"
    if !defined $program || !defined $file;

# The enforcement of this machine, before the pledge. The method
# calls no syscall, and it tells enforcement from emulation
# (PROG-SPLIT-8).
printf "supported: %d\n", Fugu::Sandbox->is_supported ? 1 : 0;

# The file must be there, so a failed open after the pledge names
# the pledge and not a wrong path.
printf "before: %d\n", -f $file ? 1 : 0;

# The interface program is a modulino, so this load defines main()
# and runs no session.
require $program;

printf "main: %d\n", main::main();

# The open of a path needs the rpath promise, and the promises of
# the interface program are 'stdio tty' (PROG-SPLIT-7). This line
# must not print.
my $open = open my $fh, '<', $file;
printf "open: %d\n", $open ? 1 : 0;
close $fh if $open;

exit 0;
