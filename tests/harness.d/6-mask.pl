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

# The mask-stability leg (TEST-MASK-1 to TEST-MASK-4, TEST-MASK-6).
#
# The custody layer rests on the stable answer of an unchanged
# record, and stability is a consequence of the oracle behavior, not
# a stated interface guarantee. This leg pins it against the
# counterparty.
#
# The second field of a reveal is the answer plaintext s_ei, and
# every comparison of this leg reads that field. The share takes no
# mask: share(K_e, i) comes from the entry key alone (KEY-SHARE-5),
# so a re-enrollment keeps the share and moves the answer. A test of
# TEST-MASK-2 over the share would assert the opposite of the rule.
#
# The leg destroys a record, so the run needs a store of its own
# (TEST-MASK-6). The harness gives each counterparty a new store,
# and the first test reads the record count of that store.

use v5.36;

return sub ($t)
{
	is( $t->records_at_start, 0,
		'the run started a new record store (TEST-MASK-6)' );

	my $vault = $t->vault('mask');
	is( $t->enroll($vault)->{state}, 'ok', 'the record enrolls' );

	# Ten reveals of an unchanged record (TEST-MASK-1).
	my ( @answer, @share );
	for my $round ( 1 .. 10 ) {
		my $reveal = $t->reveal($vault);
		is( $reveal->{state}, 'ok', "reveal $round gives ok" );
		push @answer, $reveal->{mask};
		push @share,  $reveal->{share};
	}
	my %one = map { $_ => 1 } @answer;
	is( scalar keys %one, 1,
		'ten reveals give one answer plaintext (TEST-MASK-1)' );
	my $enrolled = $answer[0];

	# A re-enrollment (TEST-MASK-2).
	is( $t->enroll($vault)->{state}, 'ok', 'the record enrolls again' );
	my $after = $t->reveal($vault);
	is( $after->{state}, 'ok', 'the re-enrolled record reveals' );
	isnt( $after->{mask}, $enrolled,
		'a re-enrollment changes the answer (TEST-MASK-2)' );
	is( $after->{share}, $share[0],
		'a re-enrollment keeps the share (KEY-SHARE-5)' );

	# The third strike, and the wipe behind it (TEST-MASK-3).
	my @junk;
	for my $attempt ( 1 .. 3 ) {
		my $reveal = $t->reveal( $vault, pass => ['wrong'] );
		is( $reveal->{state}, 'junk',
			"wrong attempt $attempt gives junk" );
		push @junk, $reveal->{mask};
	}
	for my $round ( 1 .. 2 ) {
		my $reveal = $t->reveal($vault);
		is( $reveal->{state}, 'junk',
			"the wiped record gives junk on reveal $round "
			    . '(TEST-MASK-3)' );
		push @junk, $reveal->{mask};
	}

	for my $index ( 0 .. $#junk ) {
		isnt( $junk[$index], $enrolled,
			"junk answer $index is no enrolled answer "
			    . '(TEST-MASK-3)' );
		isnt( $junk[$index], $after->{mask},
			"junk answer $index is no re-enrolled answer "
			    . '(TEST-MASK-3)' );
	}

	# Junk carries a fresh random key, so no two junk answers
	# match (TEST-MASK-4).
	my %seen = map { $_ => 1 } @junk;
	is( scalar keys %seen, scalar @junk,
		'the junk answers differ from each other (TEST-MASK-4)' );

	return;
};
