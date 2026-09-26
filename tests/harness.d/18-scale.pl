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

# The scaling leg (TEST-CALIBRATE-3, ORC-RECORDS-4).
#
# Three machines enroll at one oracle instance. The first machine
# creates a vault with a pool of 100 slots, and each other machine
# takes a copy of the shared set and runs the provisioning ceremony.
# A ceremony enrolls one record per slot and one canary, so the
# store grows by 101 records per machine, and by 303 in all
# (ORC-RECORDS-1, ORC-RECORDS-2).
#
# The leg measures each ceremony: the seconds of it from the guest
# clock of the console, and the requests of it from the store. One
# set_pin request enrolls one record (ORC-RECORDS-4), so the growth
# of the store is the request count, and the counters file of the
# machine names the same records (ORC-COUNTER-2). The leg prints the
# numbers as one table, and docs/analysis/scaling-check.md records
# them against the workload posture of a few requests per day
# (FuguOracle D-04).
#
# The store measurement is a step of the counterparty table. A
# counterparty without that step gives none, and the leg skips it:
# the posture is the one of FuguOracle, so the record needs the
# FuguOracle store and no other.
#
# The harness empties the store after the run (TEST-HARNESS-6), and
# a snapshot of the guest holds the enrolled set (TEST-CALIBRATE-4).
# The leg therefore copies the store beside the vaults at the end.

use v5.36;
use File::Basename qw(dirname);

my $MACHINES = 3;
my $POOL     = 100;

# ratio($a, $b):
#	$a over $b, and 0 when $b is 0, so a failed ceremony breaks
#	no table line.
sub ratio ( $a, $b )
{
	return $b ? $a / $b : 0;
}

return sub ($t)
{
	my $store = $t->store;
	plan skip_all => 'the counterparty gives no store measurement, '
	    . 'and the record needs the FuguOracle store (ORC-RECORDS-4)'
	    if !defined $store;

	#
	# The three ceremonies.
	#
	my $first = $t->ceremony_vault( 'scale', oracles => 1, threshold => 1,
		pool => $POOL );
	my @row;
	my $before = $store;
	my $run    = $t->create($first);
	is( $run->{exit}, 0, "the creation with a pool of $POOL slots passes" )
	    or diag( $run->{error} );
	my $after = $t->store;
	push @row,
	    [
		'create', $first->{machine}, $after->{records} - $before->{records},
		scalar keys %{ $run->{counters} }, $t->elapsed($run) ];

	for my $n ( 2 .. $MACHINES ) {
		my $vault =
		    $t->ceremony_vault( "scale-$n", oracles => 1, threshold => 1 );
		$t->copy_shared( $first->{dir}, $vault->{dir} );
		$before = $after;
		$run    = $t->provision($vault);
		is( $run->{exit}, 0, "the provisioning of machine $n passes" )
		    or diag( $run->{error} );
		$after = $t->store;
		push @row,
		    [
			'provision', $vault->{machine},
			$after->{records} - $before->{records},
			scalar keys %{ $run->{counters} }, $t->elapsed($run) ];
	}

	#
	# The numbers (TEST-CALIBRATE-3). Each ceremony sent one set_pin
	# per slot and one per canary, and the counters file of the
	# machine holds one line per record.
	#
	my ( $requests, $seconds ) = ( 0, 0 );
	note( sprintf '%-9s %-14s %8s %8s %9s %10s', 'ceremony', 'machine',
		'requests', 'seconds', 's/request', 'requests/s' );
	for my $row (@row) {
		my ( $ceremony, $machine, $records, $counters, $elapsed ) = @$row;
		is( $records, $POOL + 1,
			"$ceremony on $machine enrolled one record per slot and the "
			    . 'canary (ORC-RECORDS-4)' );
		is( $counters, $records,
			"the counters file of $machine names each enrolled record "
			    . '(ORC-COUNTER-2)' );
		note( sprintf '%-9s %-14s %8d %8.1f %9.2f %10.2f',
			$ceremony, $machine, $records, $elapsed,
			ratio( $elapsed, $records ), ratio( $records, $elapsed ) );
		$requests += $records;
		$seconds  += $elapsed;
	}
	note( sprintf 'total: %d requests in %.1f seconds; the store holds %d '
		    . 'records in %d kilobytes', $requests, $seconds,
		$after->{records}, $after->{kilobytes} );
	is( $after->{records} - $store->{records}, $MACHINES * ( $POOL + 1 ),
		"the store grew by the records of $MACHINES machines "
		    . '(TEST-CALIBRATE-3)' );

	#
	# The enrolled set, for the snapshot of the guest.
	#
	my $keep = dirname( $first->{dir} ) . '/scale-store';
	$t->copy_dir( $store->{dir}, $keep );
	is( scalar( grep { /\.pin\z/ } $t->names("$keep/pins") ),
		$after->{records},
		"the copy at $keep holds every record of the store" );
	return;
};
