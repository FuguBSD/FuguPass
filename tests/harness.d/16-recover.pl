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

# The recovery leg (REC-PLATE, REC-VAULT, REC-RESTORE,
# REC-PRINCIPLE-4).
#
# A first machine creates a vault, imports two stored entries, and
# generates one derived entry. A second machine takes a copy of the
# shared set and provisions its own records. Every recovery of this
# leg then reads the plate and the shared set alone, so the harness
# stops every counterparty for the recovery paths (REC-PRINCIPLE-4).
# The restore of REC-RESTORE-1 reveals through the oracle, so that
# one part runs against a live counterparty.
#
# A recovered secret prints to the terminal, so a recovery runs over
# the console of the guest, and the terminal text of a step carries
# each secret (TEST-HARNESS-8, PROG-OUTPUT-1). The scan double prints
# the fixed test master, so a recovery reads no plate and no camera
# (TEST-KAT-4).
#
# Each assertion names the mutation that it catches. A membership
# assertion reads the terminal of the step and the standard output of
# it, and never a value that the step itself holds.

use v5.36;

# The example topology of TEST-HARNESS-5.
my $ORACLES   = 3;
my $THRESHOLD = 2;

# The slots of the creation. A small pool keeps the leg short, and
# three entries consume three of the slots.
my $POOL = 4;

# seen($t, $run):
#	The terminal lines of one step, as a set. A recovered secret
#	prints on the terminal, so a membership test reads this set
#	(PROG-OUTPUT-1).
sub seen ( $t, $run )
{
	return map { $_ => 1 } $t->terminal($run);
}

return sub ($t)
{
	my $secret  = $t->answer('secret');
	my $secret2 = $t->answer('secret2');

	#
	# The first machine: a creation, two stored entries, and one
	# derived entry. The derived secret comes back on the plate
	# alone, and the two stored secrets need the entry files.
	#
	my $first = $t->ceremony_vault( 'recover', oracles => $ORACLES,
		threshold => $THRESHOLD, pool => $POOL );
	my $made = $t->create($first);
	is( $made->{exit}, 0, 'the creation of the first machine passes' )
	    or diag( $made->{error} );

	my ( $a1, $a2, $g1, $shown ) = $t->console(
		$first,
		{ argv => [ 'add', '-T', 'password', 'a1' ],
			answers => [ 'right', 'secret' ] },
		{ argv => [ 'add', '-T', 'note', 'a2' ],
			answers => [ 'right', 'secret2' ] },
		{ argv => [ 'gen', '-T', 'password', 'g1' ],
			answers => ['right'] },
		{ argv => [ 'show', 'g1' ], answers => ['right'] } );
	is( $a1->{exit},    0, 'add writes the first stored entry' );
	is( $a2->{exit},    0, 'add writes the second stored entry' );
	is( $g1->{exit},    0, 'gen writes the derived entry' );
	is( $shown->{exit}, 0, 'the first machine reveals the derived entry' )
	    or diag( $shown->{error} );
	my ($derived) = $t->terminal($shown);

	#
	# The second machine provisions its own records from a copy of
	# the shared set (CER-PROVISION). Its counters file states the
	# requests of the ceremony, and a recovery must not move it.
	#
	my $second = $t->ceremony_vault( 'recover-second', oracles => $ORACLES,
		threshold => $THRESHOLD );
	$t->copy_shared( $first->{dir}, $second->{dir} );
	my $prov = $t->provision($second);
	is( $prov->{exit}, 0, 'the provisioning of the second machine passes' )
	    or diag( $prov->{error} );
	my $counters = $t->read_file( $t->counters($second) );

	#
	# The recovery paths run with every counterparty stopped
	# (REC-PRINCIPLE-4).
	#
	$t->stop;

	#
	# Plate-alone recovery (REC-PLATE). A fresh vault directory
	# holds no shared set, so the recovery takes the plate-alone
	# path. It re-materializes both BIP85 candidates of each slot up
	# to the ceiling, and it reports the scanned range.
	#
	# The mutations: a plate-alone path that reports no range gives
	# no range line. A path that materializes no candidate prints no
	# secret, so the derived secret is absent and the count is 0.
	#
	my $plate = $t->ceremony_vault( 'recover-plate', oracles => $ORACLES,
		threshold => $THRESHOLD );
	my ($alone) =
	    $t->console( $plate, { argv => [ 'recover', '--ceiling', 3 ] } );
	is( $alone->{exit}, 0,
		'plate-alone recovery passes with the counterparty stopped' )
	    or diag( $alone->{error} );
	like( $alone->{out}, qr/^plate slots 0 to 2$/m,
		'plate-alone recovery reports the scanned range (REC-PLATE-2)' );
	my %alone = seen( $t, $alone );
	ok( $alone{$derived},
		'plate-alone recovery re-materializes the derived secret of '
		    . 'the vault (REC-PLATE-1)' );
	is( scalar( $t->terminal($alone) ), 2 * 3,
		'plate-alone recovery prints the two candidates of each '
		    . 'scanned slot (REC-PLATE-1)' );

	#
	# Plate-plus-files recovery on the provisioned second machine,
	# still stopped (REC-VAULT, REC-PRINCIPLE-4). The machine holds a
	# full machine-local set and records, so a recovery that opened a
	# session would reach the stopped oracle and fail. The correct
	# path reads the plate and the shared set alone.
	#
	# The mutations: a recovery that opens a session reaches the
	# stopped oracle, so it fails and it moves the counters file. A
	# recovery that matches the entry file by another hash opens no
	# file, so no secret returns. A recovery that reads no index
	# names each entry by its file name, so the entry names are
	# absent.
	#
	my ($full) =
	    $t->console( $second,
		{ argv => ['recover'], answers => ['right'] } );
	is( $full->{exit}, 0,
		'plate-plus-files recovery on a provisioned machine passes '
		    . 'with the counterparty stopped (REC-PRINCIPLE-4)' )
	    or diag( $full->{error} );
	my %full = seen( $t, $full );
	ok( $full{$secret},  'the recovery returns the first stored secret '
		    . '(REC-VAULT-2)' );
	ok( $full{$secret2}, 'the recovery returns the second stored secret '
		    . '(REC-VAULT-2)' );
	ok( $full{$derived}, 'the recovery returns the derived secret '
		    . '(REC-VAULT-2)' );
	like( $full->{out}, qr/^a1$/m,
		'the recovery names the first entry from the index '
		    . '(REC-VAULT-3)' );
	like( $full->{out}, qr/^a2$/m,
		'the recovery names the second entry from the index '
		    . '(REC-VAULT-3)' );
	like( $full->{out}, qr/^g1$/m,
		'the recovery names the derived entry from the index '
		    . '(REC-VAULT-3)' );
	is( $t->read_file( $t->counters($second) ), $counters,
		'the recovery on the provisioned machine sent no request: the '
		    . 'counters file stays (REC-PRINCIPLE-4)' );

	#
	# Plate-plus-files recovery on a bare copy of the shared set, with
	# no machine-local set present (REC-VAULT-1 to REC-VAULT-3). The
	# copy proves that a recovery needs no machine-local file.
	#
	# The mutation: a recovery that reads the factor file, or opens a
	# session, stops on the bare copy, so no secret returns.
	#
	my $copy = $t->ceremony_vault( 'recover-copy', oracles => $ORACLES,
		threshold => $THRESHOLD );
	$t->copy_shared( $first->{dir}, $copy->{dir} );
	is( $t->file_exists("$copy->{dir}/machine"),
		0, 'the copy of the shared set holds no machine directory '
		    . '(REC-VAULT-1)' );
	my ($bare) = $t->console( $copy, { argv => ['recover'] } );
	is( $bare->{exit}, 0,
		'the recovery on a bare copy passes with the counterparty '
		    . 'stopped' )
	    or diag( $bare->{error} );
	my %bare = seen( $t, $bare );
	ok( $bare{$secret},  'the bare copy returns the first stored secret '
		    . '(REC-VAULT-1, REC-VAULT-2)' );
	ok( $bare{$secret2}, 'the bare copy returns the second stored secret '
		    . '(REC-VAULT-1, REC-VAULT-2)' );
	like( $bare->{out}, qr/^a1$/m,
		'the bare copy names the entries through the index '
		    . '(REC-VAULT-3)' );

	#
	# A copy without the index returns every entry by its file name
	# (REC-RESTORE-5). A stale index degrades the names alone.
	#
	# The mutation: a recovery that requires the index returns no
	# secret without it, so the stored secret is absent.
	#
	my $noidx = $t->ceremony_vault( 'recover-noindex', oracles => $ORACLES,
		threshold => $THRESHOLD );
	$t->copy_shared( $first->{dir}, $noidx->{dir} );
	$t->remove_file("$noidx->{dir}/index");
	my ($stale) = $t->console( $noidx, { argv => ['recover'] } );
	is( $stale->{exit}, 0, 'the recovery without the index passes' )
	    or diag( $stale->{error} );
	my %stale = seen( $t, $stale );
	ok( $stale{$secret}, 'the copy without the index returns the stored '
		    . 'secret (REC-RESTORE-5)' );
	my @files = grep { /\A[0-9a-f]{64}\z/ } split /\n/, $stale->{out};
	ok( @files >= 3,
		'the copy without the index lists each entry by its file name '
		    . '(REC-RESTORE-5)' );

	#
	# The restore from a backup copy onto the provisioned second
	# machine (REC-RESTORE-1, REC-RESTORE-2). The machine loses its
	# shared set and keeps its machine-local records. A file copy of
	# the shared set restores it, and a reveal goes through the
	# oracle, so this part runs against a live counterparty.
	#
	$t->start;

	# The second machine loses the index and every entry file of its
	# shared set, and it keeps its machine-local set.
	$t->remove_file( "$second->{dir}/index",
		map { "$second->{dir}/$_" }
		    grep { /\A[0-9a-f]{64}\z/ } $t->names( $second->{dir} ) );

	# The copy of the shared set touches no machine-local file, so the
	# counters of the receiving machine stay (REC-RESTORE-1). The
	# mutation: a restore that copies the machine-local set overwrites
	# the counters of the receiving machine.
	my $baseline = $t->read_file( $t->counters($second) );
	$t->copy_shared( $first->{dir}, $second->{dir} );
	is( $t->read_file( $t->counters($second) ), $baseline,
		'the shared-set copy left the machine-local counters of the '
		    . 'receiving machine (REC-RESTORE-1)' );

	# The restored machine reveals an entry through its own records,
	# and the counter that it sends stays valid (REC-RESTORE-2). The
	# mutation: a restore that copies no file leaves the shared set
	# lost, so the reveal opens no entry.
	my ($reveal) = $t->console( $second,
		{ argv => [ 'show', 'a1' ], answers => ['right'] } );
	is( $reveal->{exit}, 0,
		'the restored machine reveals an entry through its own '
		    . 'records (REC-RESTORE-1)' )
	    or diag( $reveal->{error} );
	is_deeply( [ $t->terminal($reveal) ], [$secret],
		'the reveal after the restore gives the stored secret, so the '
		    . 'counters stay valid (REC-RESTORE-2)' );
	return;
};
