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
# Three causes give one state word, junk: a wrong passphrase, a
# wiped record, and a counter below the stored one. The caller
# cannot learn the cause from the response bytes (ORC-REVEAL-4).
# Each one gives the bytes of a mask, and the decrypt of the
# caller is the one junk detector. The driver stands in for that
# decrypt, so each of the three gives the state junk.
#
# The three causes act on one record, so one client key addresses
# every call of this leg. A difference between two answers is then
# the behavior of the oracle, and no second record.
#
# The rules of the oracle set the order of the calls. A correct
# pin resets the attempt count to 0 (FuguOracle OPS-GET-4), so
# the live reveal comes before the wrong attempts. The wipe
# prevents a counter violation after the third strike
# (ORC-REVEAL-5): FuguOracle OPS-WIPE-1 persists
# replay_counter = 0xFFFFFFFF. A counter violation burns no
# strike (ORC-COUNTER-6). The first two wrong attempts persist
# the counter of the client (FuguOracle OPS-GET-5). The third
# attempt takes FuguOracle OPS-GET-6, and OPS-WIPE-1 persists
# count = 3 and replay_counter = 0xFFFFFFFF. The counters file
# therefore takes a value above the forged one again, before the
# wrong attempts.

use v5.36;

return sub ($t)
{
	my $vault = $t->vault('reveal');
	my $file  = $t->counters($vault);
	my $name  = $t->record($vault);

	is( $t->enroll($vault)->{state}, 'ok', 'the record enrolls' );

	# The live answer. The high counter goes on this reveal,
	# because a later counter violation needs a stored counter
	# above the wall clock (ORC-COUNTER-1). FuguOracle OPS-GET-2
	# enforces anti-replay before the pin comparison of
	# OPS-GET-3, so a correct pin under a too-low counter gives
	# junk. The stale case below is the counterexample.
	$t->write_file( $file, "$name: " . $t->high_counter );
	my $live = $t->reveal($vault);
	is( $live->{state}, 'ok', 'the record reveals' );

	# A counter below the stored one.
	$t->write_file( $file, "$name: 1" );
	my $stale = $t->reveal($vault);
	is( $stale->{state}, 'junk',
		'a counter below the stored one gives junk' );

	# Three wrong attempts on that record. The first two burn
	# strike 1 and strike 2, and the third destroys the key
	# material of the record (ORC-REVEAL-5).
	$t->write_file( $file, "$name: " . ( $t->high_counter + 1 ) );
	my @wrong;
	for my $attempt ( 1 .. 3 ) {
		push @wrong, $t->reveal( $vault, pass => ['wrong'] );
		is( $wrong[-1]->{state}, 'junk',
			"wrong attempt $attempt gives junk" );
	}

	# The correct passphrase on the destroyed record.
	my $wiped = $t->reveal($vault);
	is( $wiped->{state}, 'junk',
		'the correct passphrase on the wiped record gives junk' );

	# The three junk answers of this one record, against the live
	# answer of it and against each other. A junk answer takes a
	# fresh random key (FuguOracle OPS-JUNK-1), so two junk
	# answers of one record differ. These comparisons prove
	# FuguOracle OPS-JUNK-1. They do not prove that the response
	# bytes hide the cause (ORC-REVEAL-4).
	my @junk = (
		[ 'the wrong passphrase', $wrong[0] ],
		[ 'the wiped record',     $wiped ],
		[ 'the stale counter',    $stale ] );
	for my $i ( 0 .. $#junk ) {
		my ( $what, $answer ) = @{ $junk[$i] };
		isnt( $answer->{mask}, $live->{mask},
			"$what gives an answer other than the live answer" );
		for my $j ( $i + 1 .. $#junk ) {
			my ( $other, $second ) = @{ $junk[$j] };
			isnt( $answer->{mask}, $second->{mask},
				"$what and $other give two answers" );
		}
	}

	return;
};
