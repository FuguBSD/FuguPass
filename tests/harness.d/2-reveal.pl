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

# The reveal leg (ORC-REVEAL-4).
#
# Three causes give one answer shape: a wrong passphrase, a wiped
# record, and a counter below the stored one. Each one gives the
# bytes of a mask, and the decrypt of the caller is the one junk
# detector. The driver stands in for that decrypt, so each of the
# three gives the state junk.
#
# The answer of the oracle is one AES key of a fixed length, and
# the hex fields of the driver carry it. A defect of the oracle
# shows in the state word or in the answer bytes, so this leg
# compares those two.

use v5.36;

return sub ($t)
{
	# The reveal of a live record, for the shape of an answer.
	my $live = $t->vault('reveal-live');
	is( $t->enroll($live)->{state}, 'ok', 'the live record enrolls' );
	my $ok = $t->reveal($live);
	is( $ok->{state}, 'ok', 'the live record reveals' );

	# A wrong passphrase.
	my $bad = $t->vault('reveal-wrong');
	is( $t->enroll($bad)->{state}, 'ok', 'the second record enrolls' );
	my $wrong = $t->reveal( $bad, pass => ['wrong'] );
	is( $wrong->{state}, 'junk', 'a wrong passphrase gives junk' );

	# A wiped record. The third wrong attempt destroys it
	# (ORC-REVEAL-5).
	my $gone = $t->vault('reveal-wiped');
	is( $t->enroll($gone)->{state}, 'ok', 'the third record enrolls' );
	for my $attempt ( 1 .. 3 ) {
		is( $t->reveal( $gone, pass => ['wrong'] )->{state},
			'junk', "wrong attempt $attempt gives junk" );
	}
	my $wiped = $t->reveal($gone);
	is( $wiped->{state}, 'junk',
		'the correct passphrase on a wiped record gives junk' );

	# A counter below the stored one. An enrollment persists the
	# stored counter 0 (FuguOracle OPS-SET-4), and a reveal
	# advances it, so the forged high counter goes on a reveal.
	# The reset file then sends a lower one (ORC-COUNTER-1).
	my $stale = $t->vault('reveal-stale');
	is( $t->enroll($stale)->{state}, 'ok', 'the fourth record enrolls' );
	$t->write_file( $t->counters($stale),
		$t->record($stale) . ': ' . $t->high_counter );
	is( $t->reveal($stale)->{state},
		'ok', 'the fourth record reveals with a high counter' );
	$t->write_file( $t->counters($stale), $t->record($stale) . ': 1' );
	my $low = $t->reveal($stale);
	is( $low->{state}, 'junk', 'a counter below the stored one gives junk' );

	# One answer shape for the three (ORC-REVEAL-4). Each case
	# reports the state word of the other two, and each answer
	# differs from the live answer and from the other two.
	my @junk = (
		[ 'the wrong passphrase', $wrong ],
		[ 'the wiped record',     $wiped ],
		[ 'the stale counter',    $low ] );
	for my $i ( 0 .. $#junk ) {
		my ( $what, $answer ) = @{ $junk[$i] };
		isnt( $answer->{mask}, $ok->{mask},
			"$what gives an answer other than the live answer" );
		for my $j ( $i + 1 .. $#junk ) {
			my ( $other, $second ) = @{ $junk[$j] };
			is( $answer->{state}, $second->{state},
				"$what and $other give one state word" );
			isnt( $answer->{mask}, $second->{mask},
				"$what and $other give two answers" );
		}
	}

	return;
};
