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

# damage.pl - change one byte of one file.
#
# usage: damage.pl <path>
#
# The harness leg 11-change.pl damages the slot file of a vault with
# this program (ORC-ENROLL-9). A sealed file holds the version byte,
# the nonce, the ciphertext and the tag (VAULT-SEAL-1). The program
# writes the last byte again, with each bit of it inverted, so the
# file keeps its length and the tag of it fails.
#
# One damaged byte is the smallest change that the seal rejects. A
# shorter file and a longer one each take another path of the
# reader, so this program changes no length.
#
# The program prints nothing, and it exits 0 after the write. A
# failed step dies with the cause.

use v5.34;
use warnings;
use experimental 'signatures';
no feature qw(indirect multidimensional bareword_filehandles);

use Fcntl qw(SEEK_END);

my ($path) = @ARGV;
die "usage: damage.pl <path>\n" if !defined $path;

open my $fh, '+<:raw', $path or die "$path: $!\n";
seek $fh, -1, SEEK_END or die "$path: the seek fails: $!\n";
read( $fh, my $byte, 1 ) == 1 or die "$path: the read fails: $!\n";
seek $fh, -1, SEEK_END or die "$path: the seek fails: $!\n";
print {$fh} chr( ord($byte) ^ 0xFF ) or die "$path: the write fails: $!\n";
close $fh                            or die "$path: the close fails: $!\n";

exit 0;
