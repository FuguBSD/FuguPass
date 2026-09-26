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

# The provisioning leg (CER-PROVISION-2 to CER-PROVISION-8,
# CER-PROVISION-10, CER-PROVISION-12, CER-PROVISION-18,
# TEST-HARNESS-5).
#
# A first machine creates a vault against the example topology of
# three oracles, and it adds two entries. A second machine takes a
# copy of the shared set, and the provisioning ceremony enrolls the
# records of the second machine for each slot. Every entry then
# reveals on the second machine through its own records.
#
# The ceremony reads the master from the scan double, and it reads
# the passphrase twice from the console of the guest, as the
# creation does (TEST-HARNESS-8). A confirmation is a read of the
# console as well, and the answer no stops the ceremony.
#
# The record set of an instance before a step and after it gives the
# records of that step at that oracle. A set_pin on an existing
# record adds no file, so the counters file of the vault states the
# requests of a re-run: a set_pin moves the counter of its record
# (ORC-COUNTER-2).
#
# Each assertion names the mutation that it catches. A step that
# reads a confirmation takes one answer more than the prompts of the
# mutated run, and the empty answer stops that run at the passphrase
# read, so no step waits for the timeout of the console.

use v5.36;

# The example topology of TEST-HARNESS-5. The leg takes one
# instance for each position, and the harness reads that count at
# the load.
my $ORACLES   = 3;
my $THRESHOLD = 2;
our $INSTANCES = $ORACLES;

# The slots of the creation. A small pool keeps the leg short, and
# two entries consume two of the slots.
my $POOL = 4;

# records_of($t):
#	The record file names of each instance, by oracle index.
sub records_of ($t)
{
	return { map { $_ => [ sort $t->records($_) ] } 1 .. $ORACLES };
}

# fresh($before, $after):
#	The record file names of $after that $before does not hold,
#	by oracle index, each list sorted.
sub fresh ( $before, $after )
{
	my %fresh;
	for my $oracle ( keys %$after ) {
		my %old = map { $_ => 1 } @{ $before->{$oracle} };
		$fresh{$oracle} =
		    [ sort grep { !$old{$_} } @{ $after->{$oracle} } ];
	}
	return \%fresh;
}

# entry_counters($run):
#	The counters of the entry records after one step, by record
#	name (ORC-COUNTER-2). The canary records stay out, because a
#	canary check moves them and sends no set_pin.
sub entry_counters ($run)
{
	my %counter = %{ $run->{counters} };
	delete $counter{$_} for grep { /\Acanary-/ } keys %counter;
	return \%counter;
}

# machine_files($t, $vault, $pattern):
#	The file names of the machine-local set of $vault that
#	$pattern matches.
sub machine_files ( $t, $vault, $pattern )
{
	return grep { $_ =~ $pattern } $t->names("$vault->{dir}/machine");
}

# oracle_line($t, $vault):
#	The oracle arguments of a command line, as create() gives
#	them.
sub oracle_line ( $t, $vault )
{
	return map { $t->pubkey($_) . ' ' . $t->url($_) }
	    1 .. $vault->{oracles};
}

return sub ($t)
{
	my $secret = $t->answer('secret');

	#
	# The first machine: a creation, and two entries.
	#
	my $first = $t->ceremony_vault( 'prov', oracles => $ORACLES,
		threshold => $THRESHOLD, pool => $POOL );
	my $made = $t->create($first);
	is( $made->{exit}, 0, 'the creation of the first machine passes' )
	    or diag( $made->{error} );

	my ( $gen, $add, $shown ) = $t->console(
		$first,
		{ argv => [ 'gen', '-T', 'password', 'g1' ],
			answers => ['right'] },
		{ argv => [ 'add', '-T', 'password', 'a1' ],
			answers => [ 'right', 'secret' ] },
		{ argv => [ 'show', 'g1' ], answers => ['right'] } );
	is( $gen->{exit}, 0, 'gen writes the derived entry of the first '
		    . 'machine' )
	    or diag( $gen->{error} );
	is( $add->{exit}, 0, 'add writes the stored entry of the first '
		    . 'machine' )
	    or diag( $add->{error} );
	is( $shown->{exit}, 0, 'the first machine reveals the derived entry' )
	    or diag( $shown->{error} );
	my ($derived) = $t->terminal($shown);

	#
	# The second machine, and the gates before the plate scan
	# (CER-PROVISION-2, CER-PROVISION-18, PROG-ONESHOT-4). Each
	# case stops before the plate scan and before the passphrase
	# read, so each one runs over ssh with no terminal.
	#
	my $second = $t->ceremony_vault( 'prov-second', oracles => $ORACLES,
		threshold => $THRESHOLD );
	my $dir  = $second->{dir};
	my @line = (
		'-k', $THRESHOLD, '-m', $second->{machine},
		'-r', 1, oracle_line( $t, $second ) );

	my $absent = $t->program( '-d', $dir, 'provision', @line );
	is( $absent->{exit}, 1,
		'a vault directory with no shared set stops the ceremony '
		    . '(CER-PROVISION-2)' );
	like( $absent->{error}, qr/the index is absent: copy the shared set/,
		'the refusal names the copy of the shared set as the path '
		    . '(CER-PROVISION-2)' );

	my $usage = $t->program( '-d', $dir, 'provision', '-k', $THRESHOLD );
	is( $usage->{exit}, 2, 'an absent mandatory option exits 2' );
	like( $usage->{error}, qr/the -k, -m and -r options/,
		'an absent mandatory option gives the reason' );
	like( $usage->{error}, qr/^usage: /m,
		'an absent mandatory option gives a usage line' );
	my $pool = $t->program( '-d', $dir, 'provision', '-p', 3, @line );
	is( $pool->{exit}, 2, 'the -p option of create exits 2 here' );

	#
	# The two -x gates of the command line (CER-PROVISION-16,
	# CER-PROVISION-17). The full run takes no -x option, and a
	# position above the count of the set names no oracle. Each
	# refusal stops before the plate scan, so no request went out,
	# and the counters file stays absent.
	#
	# The mutations: a line reader without the -a gate, or without
	# the count gate, starts the ceremony. The ceremony then stops
	# at the absent index with an exit of 1 and no usage line.
	#
	my $both = $t->program( '-d', $dir, 'provision', '-a', '-x', 1, @line );
	is( $both->{exit}, 2,
		'the -a full run with a -x option exits 2 (CER-PROVISION-17)' );
	like( $both->{error}, qr/takes no -x option/,
		'the -a and -x refusal gives the reason (CER-PROVISION-17)' );
	like( $both->{error}, qr/^usage: /m,
		'the -a and -x refusal gives a usage line' );
	my $over  = $ORACLES + 1;
	my $above = $t->program( '-d', $dir, 'provision', '-x', $over, @line );
	is( $above->{exit}, 2,
		'a -x position above the oracle count exits 2 (CER-PROVISION-16)' );
	like( $above->{error}, qr/the lost position $over is above the count/,
		'the -x count refusal names the position (CER-PROVISION-16)' );
	like( $above->{error}, qr/^usage: /m,
		'the -x count refusal gives a usage line' );
	is( $t->file_exists( $t->counters($second) ),
		0, 'the two -x refusals sent no request: no counters file exists' );

	$t->copy_shared( $first->{dir}, $dir );
	$t->make_dir("$dir/machine");
	$t->write_file( "$dir/machine/change", 'kind: passphrase' );
	my $pending = $t->program( '-d', $dir, 'provision', @line );
	is( $pending->{exit}, 1,
		'the ceremony refuses to start while the marker exists '
		    . '(CER-PROVISION-18)' );
	like( $pending->{error}, qr/incomplete passphrase change/,
		'the refusal names the incomplete change (CER-PROVISION-18)' );
	like( $pending->{error}, qr/"fugupass resume" completes it/,
		'the refusal names the resume command (CER-PROVISION-18)' );
	is( $t->file_exists("$dir/machine/factor"),
		0, 'the refused ceremony wrote no device factor' );
	$t->remove_file("$dir/machine/change");

	#
	# The ceremony on the second machine (CER-PROVISION-3 to
	# CER-PROVISION-8, CER-PROVISION-10).
	#
	# The mutations: a loop under the device factor of the first
	# machine replaces the records of that machine, and the store
	# then grows by no record. A loop that skips the canary
	# leaves each store one record short. A loop that enrolls at
	# the first oracle alone leaves two stores unchanged.
	#
	my $start = records_of($t);
	my $run   = $t->provision($second);
	is( $run->{exit}, 0, 'the provisioning ceremony passes' )
	    or diag( $run->{error} );
	my $after = records_of($t);
	my $new   = fresh( $start, $after );
	for my $oracle ( 1 .. $ORACLES ) {
		is( scalar @{ $new->{$oracle} }, $POOL + 1,
			"the store of oracle $oracle grew by the records of the "
			    . "second machine: $POOL slots and the canary "
			    . '(CER-PROVISION-6, CER-PROVISION-7)' );
	}

	is( $t->file_exists("$dir/machine/factor"),
		1, 'the ceremony wrote the device factor (CER-PROVISION-3)' );
	my $config = $t->read_file("$dir/machine/config") // '';
	my $check  = $t->plate_check;
	like( $config, qr/^plate-check: \Q$check\E$/m,
		'the config holds the plate check value of the plate '
		    . '(CER-PROVISION-4)' );
	like( $config, qr/^machine-name: \Q$second->{machine}\E$/m,
		'the config holds the machine name of the command line '
		    . '(CER-PROVISION-4)' );
	like( $config, qr/^threshold: $THRESHOLD$/m,
		'the config holds the threshold of the command line '
		    . '(CER-PROVISION-4)' );
	for my $oracle ( 1 .. $ORACLES ) {
		is( $t->file_exists( $t->seal( $second, oracle => $oracle ) ),
			1, "the ceremony sealed the canary check value of oracle "
			    . "$oracle (CER-PROVISION-6)" );
		is( $t->file_exists(
				$t->index_wrap( $second, oracle => $oracle ) ),
			1, "the ceremony wrote the index wrap of oracle $oracle "
			    . '(CER-PROVISION-6)' );
	}
	is( scalar machine_files( $t, $second, qr/\Awrap\.[0-9]+\.[0-9]+\z/ ),
		$POOL * $ORACLES,
		'the second machine holds one wrap of each slot at each live '
		    . 'oracle (CER-PROVISION-7)' );
	is( scalar $t->search( $dir, $t->master ),
		0, 'no file of the second machine holds the master '
		    . '(CER-PROVISION-10)' );

	# The ceremony writes no file of the shared set but the index
	# (VAULT-LAYOUT-3). The mutation: a loop that seals the slot
	# file of a slot, as a creation does, replaces the entry file
	# of a consumed slot.
	my @entry = grep { /\A[0-9a-f]{64}\z/ } $t->names($dir);
	is( scalar @entry, $POOL, 'the second machine holds each entry file '
		    . 'of the copy' );
	for my $name (@entry) {
		is( $t->digest("$dir/$name"),
			$t->digest("$first->{dir}/$name"),
			'the ceremony left the entry file of the copy as it was '
			    . '(CER-PROVISION-7)' );
	}

	#
	# Every entry reveals on the second machine (CER-PROVISION-7,
	# CER-PROVISION-11).
	#
	# The mutation: a wrap from a share at the wrong oracle index
	# reconstructs a wrong entry key, and the decrypt fails.
	#
	my ( $list, $stored, $again ) = $t->console(
		$second,
		{ argv => ['ls'],           answers => ['right'] },
		{ argv => [ 'show', 'a1' ], answers => ['right'] },
		{ argv => [ 'show', 'g1' ], answers => ['right'] } );
	is( $list->{exit}, 0, 'the second machine opens the index through '
		    . 'its own index wraps (CER-PROVISION-6)' )
	    or diag( $list->{error} );
	like( $list->{out}, qr/^g1$/m, 'the index names the derived entry' );
	like( $list->{out}, qr/^a1$/m, 'the index names the stored entry' );
	is( $stored->{exit}, 0, 'the second machine reveals the stored entry' )
	    or diag( $stored->{error} );
	is_deeply( [ $t->terminal($stored) ], [$secret],
		'the second machine reveals the stored entry through its own '
		    . 'records (CER-PROVISION-7, TEST-HARNESS-5)' );
	is_deeply( [ $t->terminal($again) ], [$derived],
		'the second machine reveals the derived entry of the first '
		    . 'machine (CER-PROVISION-7)' );

	#
	# The re-run on the provisioned machine (CER-PROVISION-12).
	#
	# The mutations: a loop that enrolls every pair moves the
	# counter of each entry record. A run that enrolls each canary
	# again writes a fresh seal and a fresh index wrap, and the
	# digests move.
	#
	my %seal = map { $_ => $t->digest( $t->seal( $second, oracle => $_ ) ) }
	    1 .. $ORACLES;
	my %wrap =
	    map { $_ => $t->digest( $t->index_wrap( $second, oracle => $_ ) ) }
	    1 .. $ORACLES;

	my $rerun = $t->provision($second);
	is( $rerun->{exit}, 0,
		'the re-run on the provisioned machine passes '
		    . '(CER-PROVISION-12)' )
	    or diag( $rerun->{error} );
	unlike( $rerun->{error}, qr/no file verifies this passphrase/,
		'the re-run warns of no absent verifier, because the canaries '
		    . 'verify the passphrase (ORC-CANARY-6)' );
	is_deeply( records_of($t), $after,
		'the re-run added no record to any store (CER-PROVISION-12)' );
	is_deeply( entry_counters($rerun), entry_counters($again),
		'the re-run sent no set_pin: the counter of each entry record '
		    . 'stays (CER-PROVISION-12)' );
	for my $oracle ( 1 .. $ORACLES ) {
		ok( $rerun->{counters}{"canary-$oracle"} >
			$again->{counters}{"canary-$oracle"},
			"the re-run verified the passphrase at the canary of "
			    . "oracle $oracle (CER-PROVISION-12)" );
		is( $t->digest( $t->seal( $second, oracle => $oracle ) ),
			$seal{$oracle},
			"the re-run kept the canary seal of oracle $oracle" );
		is( $t->digest( $t->index_wrap( $second, oracle => $oracle ) ),
			$wrap{$oracle},
			"the re-run kept the index wrap of oracle $oracle" );
	}

	# A mistyped passphrase fails at the first sealed canary, and
	# the walk stops there: the later canaries take no request, and
	# the re-run sends no set_pin (ORC-CANARY-4, ORC-CANARY-9). The
	# mutations: a walk that goes on past the first junk answer
	# moves the canary counter of oracle 2 and of oracle 3, and a
	# run that enrolls each failed canary again poisons the canaries
	# under the typo, so the seals catch it: an enrollment writes a
	# fresh seal, and a check writes none.
	my ($typo) = $t->provision( $second, answers => [ 'wrong', 'wrong' ] );
	isnt( $typo->{exit}, 0,
		'a mistyped passphrase stops the re-run (ORC-CANARY-9)' );
	like( $typo->{error}, qr/the cause is the passphrase/,
		'the report names the typo case (ORC-CANARY-9)' );
	like( $typo->{error}, qr/the ceremony sends no set_pin/,
		'the report states that no set_pin ran (ORC-CANARY-9)' );
	ok( $typo->{counters}{'canary-1'} > $rerun->{counters}{'canary-1'},
		'the mistyped re-run sent the check to the canary of oracle 1 '
		    . '(ORC-CANARY-4)' );
	for my $oracle ( 2 .. $ORACLES ) {
		is( $typo->{counters}{"canary-$oracle"},
			$rerun->{counters}{"canary-$oracle"},
			"the mistyped re-run sent no check to the canary of "
			    . "oracle $oracle: the walk stopped at oracle 1 "
			    . '(ORC-CANARY-4)' );
	}
	for my $oracle ( 1 .. $ORACLES ) {
		is( $t->digest( $t->seal( $second, oracle => $oracle ) ),
			$seal{$oracle},
			"the mistyped re-run enrolled the canary of oracle "
			    . "$oracle no second time: the seal stays "
			    . '(ORC-CANARY-9)' );
	}

	# The heal of a dead index wrap and of a stale seal
	# (CER-PROVISION-12, ORC-CANARY-8). The seal of oracle 1 in
	# the place of the seal of oracle 3 is a seal under another
	# key, so the check of oracle 3 fails after the pass at
	# oracle 1. The mutation: a re-run that stops at the first
	# junk answer leaves the wrap absent and the seal stale.
	$t->remove_file( $t->index_wrap( $second, oracle => 2 ) );
	$t->copy_file( $t->seal( $second, oracle => 1 ),
		$t->seal( $second, oracle => 3 ) );
	my $url  = $t->url(3);
	my $heal = $t->provision($second);
	is( $heal->{exit}, 0,
		'the re-run with a dead index wrap and a stale seal passes '
		    . '(CER-PROVISION-12)' )
	    or diag( $heal->{error} );
	is( $t->file_exists( $t->index_wrap( $second, oracle => 2 ) ),
		1, 'the re-run wrote the dead index wrap of oracle 2 again '
		    . '(CER-PROVISION-12, ORC-CANARY-8)' );
	like( $heal->{error},
		qr/the canary of oracle 3 \(\Q$url\E\) is enrolled again/,
		'the report names the canary that the re-run enrolled again '
		    . '(CER-PROVISION-12)' );
	isnt( $t->digest( $t->seal( $second, oracle => 3 ) ),
		$seal{1}, 'the re-run sealed the canary check value of oracle 3 '
		    . 'again (CER-PROVISION-12)' );
	is_deeply( entry_counters($heal), entry_counters($typo),
		'the heal sent no set_pin to an entry record '
		    . '(CER-PROVISION-12)' );
	my ($healed) = $t->console( $second,
		{ argv => [ 'show', 'a1' ], answers => ['right'] } );
	is( $healed->{exit}, 0,
		'the session opens through the healed wraps, and it reveals '
		    . 'the entry' )
	    or diag( $healed->{error} );

	# A command line that changes the round count, and a command
	# line of another machine name, each stop before the plate
	# scan. A change of the list or of the threshold is a variant
	# of the ceremony, and 14-variants.pl drives each one. The two
	# answers guard the console: a run that starts reads them as
	# the two passphrases, and the empty second one fails the read.
	my $changed = $t->provision( $second, rounds => 2,
		answers => [ 'none', 'none' ] );
	is( $changed->{exit}, 1,
		'a re-run under another round count stops (CER-PROVISION-12)' );
	like( $changed->{error}, qr/the round count of this machine differs/,
		'the refusal names the difference from the config' );
	like( $t->read_file("$dir/machine/config") // '',
		qr/^kdf-rounds: 16$/m,
		'the refused re-run left the round count of the config' );
	my $clone = $t->provision( $second, machine => 'create-prov-clone',
		answers => [ 'none', 'none' ] );
	is( $clone->{exit}, 1,
		'a run under another name in a provisioned directory stops '
		    . '(CER-PROVISION-19)' );
	like( $clone->{error}, qr/belongs to the machine \Q$second->{machine}\E/,
		'the refusal names the machine of the machine-local set' );

	#
	# The registry of the index (CER-PROVISION-3, CER-PROVISION-8).
	#
	# A fresh directory takes a copy of the shared set of the
	# second machine, and a run under each registered name warns
	# and reads a confirmation there: the registry holds the
	# name, and no machine-local set of that name exists. The
	# answer no stops the ceremony before any write.
	#
	# The mutation: a ceremony that registers no machine reads no
	# confirmation under the second name, and the run then takes
	# the two answers as the two passphrase reads. The second one
	# is the empty line, so the read fails, and the refusal text
	# is absent.
	#
	my $probe = $t->ceremony_vault( 'prov-probe', oracles => $ORACLES,
		threshold => $THRESHOLD );
	$t->copy_shared( $dir, $probe->{dir} );
	for my $name ( $first->{machine}, $second->{machine} ) {
		my $stop = $t->provision( $probe, machine => $name,
			answers => [ 'no', 'none' ] );
		is( $stop->{exit}, 1,
			"the run under the registered name $name stops without "
			    . 'a confirmation (CER-PROVISION-3)' );
		like( $stop->{error},
			qr/the registry of the index holds the machine \Q$name\E/,
			"the registry of the index names $name "
			    . '(CER-PROVISION-8)' );
		like( $stop->{error}, qr/replaces the records of the machine/,
			'the warning names the replacement (CER-PROVISION-3)' );
		is( $t->file_exists("$probe->{dir}/machine/config"),
			0, 'the stopped run wrote no config (CER-PROVISION-3)' );
	}

	# The confirmed run under the name of the second machine
	# (CER-PROVISION-3). The loop enrolls every record of that
	# name again, so the store of each oracle gains no record,
	# and the records answer fresh masks. The wraps of the second
	# directory are then stale, and that directory reveals
	# nothing. The mutation: a run that takes no confirmation
	# reads the word yes as the passphrase, and the second read
	# differs.
	my $before  = records_of($t);
	my $replace = $t->provision( $probe, machine => $second->{machine},
		answers => [ 'yes', 'right', 'right' ] );
	is( $replace->{exit}, 0, 'the confirmed run passes (CER-PROVISION-3)' )
	    or diag( $replace->{error} );
	is_deeply( records_of($t), $before,
		'the confirmed run replaced the records of that name, and it '
		    . 'added none (CER-PROVISION-3)' );
	my ($stale) = $t->console( $second,
		{ argv => [ 'show', 'a1' ], answers => ['right'] } );
	isnt( $stale->{exit}, 0,
		'the old machine-local set of that name reveals nothing after '
		    . 'the replacement (CER-PROVISION-3)' );
	my ($moved) = $t->console( $probe,
		{ argv => [ 'show', 'a1' ], answers => ['right'] } );
	is_deeply( [ $t->terminal($moved) ], [$secret],
		'the new machine-local set of that name reveals the entry '
		    . '(CER-PROVISION-3)' );
	return;
};
