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

# The enrollment leg (ORC-ENROLL-1 to ORC-ENROLL-3).
#
# One enrollment is one set_pin, and it writes the wrap of the
# record. A reveal of that record unmasks the wrap, and the driver
# compares the share against share(K_e, i). The state ok therefore
# proves the enrollment, the wrap and the unmask together.

use v5.36;

return sub ($t)
{
	my $vault = $t->vault('enroll');

	is( $t->file_exists( $t->wrap($vault) ),
		0, 'a new vault holds no wrap of the record' );

	my $enroll = $t->enroll($vault);
	is( $enroll->{state}, 'ok', 'the enrollment gives ok (ORC-ENROLL-1)' );
	is( $t->file_exists( $t->wrap($vault) ),
		1, 'the enrollment wrote the wrap (ORC-ENROLL-3)' );

	my $reveal = $t->reveal($vault);
	is( $reveal->{state}, 'ok',
		'the reveal of the enrolled record gives ok (ORC-REVEAL-3)' );
	like( $reveal->{share}, qr/\A[0-9a-f]{64}\z/,
		'the reveal gives the share of this oracle' );
	like( $reveal->{mask}, qr/\A[0-9a-f]{64}\z/,
		'the reveal gives the answer plaintext of the record' );

	my $again = $t->reveal($vault);
	is( $again->{state}, 'ok', 'a second reveal gives ok' );
	is( $again->{mask}, $reveal->{mask},
		'the second reveal gives the enrolled mask (ORC-REVEAL-2)' );
	is( $again->{share}, $reveal->{share},
		'the second reveal gives the same share' );

	return;
};
