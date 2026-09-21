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

# The counters leg (ORC-COUNTER-3, ORC-COUNTER-6).
#
# The counter of a request is max(wall-clock seconds, stored + 1),
# and the counters file holds the last sent value of each record.
# The loss of that file is safe, because the wall-clock term
# re-establishes a valid counter. A counter below the stored one
# takes the junk path, and it burns no strike: three of them leave
# the record whole.
#
# The counter has one-second resolution, so a reveal in the second
# of its enrollment carries the same value as that enrollment. The
# leg waits for the clock after it removes the file, because the
# file is then the only source of a greater value.

use v5.36;

return sub ($t)
{
	my $lost = $t->vault('counters-lost');
	my $name = $t->record($lost);
	my $file = $t->counters($lost);
	my $line = qr/^\Q$name\E: ([0-9]+)$/m;

	is( $t->enroll($lost)->{state}, 'ok', 'the record enrolls' );
	is( $t->file_exists($file),
		1, 'the enrollment wrote the counters file (ORC-COUNTER-2)' );
	like( $t->read_file($file), $line,
		'the counters file names the record (ORC-COUNTER-2)' );

	$t->remove_file($file);
	is( $t->file_exists($file), 0, 'the counters file is gone' );
	sleep 2;

	is( $t->reveal($lost)->{state},
		'ok', 'the clock re-establishes a valid counter '
		    . '(ORC-COUNTER-3)' );
	my ($value) = $t->read_file($file) =~ $line;
	ok( defined $value, 'the reveal wrote the counters file again' );
	cmp_ok( $value, '>', 1_700_000_000,
		'the new counter comes from the wall clock' );
	cmp_ok( $value, '<', $t->high_counter,
		'the new counter is no forged value' );

	# A counter below the stored one. An enrollment persists the
	# stored counter 0 (FuguOracle OPS-SET-4), and a reveal
	# advances it, so the forged high counter goes on a reveal.
	# The oracle keeps the attempt count of the record, so three
	# junk answers leave the record alive (ORC-COUNTER-6).
	my $stale = $t->vault('counters-stale');
	is( $t->enroll($stale)->{state}, 'ok', 'the second record enrolls' );
	$t->write_file( $t->counters($stale),
		$t->record($stale) . ': ' . $t->high_counter );
	is( $t->reveal($stale)->{state},
		'ok', 'the second record reveals with a high counter' );

	$t->write_file( $t->counters($stale), $t->record($stale) . ': 1' );
	for my $attempt ( 1 .. 3 ) {
		is( $t->reveal($stale)->{state},
			'junk', "the stale counter $attempt takes the "
			    . 'junk path' );
	}

	$t->write_file( $t->counters($stale),
		$t->record($stale) . ': ' . ( $t->high_counter + 1 ) );
	is( $t->reveal($stale)->{state},
		'ok', 'a greater counter recovers the record, so the three '
		    . 'junk answers burned no strike (ORC-COUNTER-6)' );

	return;
};
