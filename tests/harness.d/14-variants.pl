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

# The provisioning variants leg (CER-PROVISION-13 to CER-PROVISION-18,
# ORC-ENROLL-12, ORC-PROVISION-6, ORC-PROVISION-7, REC-WIPE-2,
# REC-WIPE-6, KEY-MASK-10, TEST-HARNESS-5).
#
# Each case creates one vault against the example topology of three
# oracles with a threshold of two, and it drives one variant of the
# provisioning ceremony on that machine (CER-PROVISION-13). The
# subcommands read the passphrase from the console of the guest, so
# each ceremony runs there (TEST-HARNESS-8).
#
# The added-oracle case starts from two oracles, because the harness
# holds three instances: an added position at the fourth index takes
# the first instance again, and a config change must not give two
# positions one value. A third position takes the third instance, a
# fresh oracle, so the add is a clean append.
#
# Each case names the mutation that it catches. A state assertion
# compares the state of the moment with a state that this file
# recorded before the step, and never with a value that the step
# itself writes. A canary check moves a canary counter and sends no
# set_pin, so a set_pin assertion reads the entry counters alone.

use v5.36;

# The example topology of TEST-HARNESS-5.
my $ORACLES   = 3;
my $THRESHOLD = 2;

# A small pool keeps each ceremony short, and one entry consumes one
# slot.
my $POOL = 2;

# oracle_arg($t, $o):
#	The oracle argument of one position: the static public key,
#	one space, and the URL (ORC-PROVISION-1).
sub oracle_arg ( $t, $o )
{
	return $t->pubkey($o) . ' ' . $t->url($o);
}

# prov_argv($vault, %opt):
#	The command line of one provisioning run. 'oracle' is the
#	array of oracle arguments, 'threshold' and 'machine' each
#	replace the value of the vault, and 'full' adds the -a flag
#	(CER-PROVISION-17).
sub prov_argv ( $vault, %opt )
{
	my @argv = ('provision');
	push @argv, '-a' if $opt{full};
	push @argv, '-k', $opt{threshold} // $vault->{threshold},
	    '-m', $opt{machine} // $vault->{machine}, '-r', $main::ROUNDS;
	push @argv, @{ $opt{oracle} };
	return @argv;
}

# wraps_of($t, $vault):
#	The digest of each wrap file of the machine, by "slot.oracle"
#	(VAULT-LAYOUT). A set_pin gives a fresh mask, so the wrap of a
#	re-enrolled record then holds other bytes (ORC-ENROLL-3).
sub wraps_of ( $t, $vault )
{
	my %digest;
	for my $name ( $t->names("$vault->{dir}/machine") ) {
		next if $name !~ /\Awrap\.([0-9]+)\.([0-9]+)\z/;
		$digest{"$1.$2"} = $t->digest("$vault->{dir}/machine/$name");
	}
	return \%digest;
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

# marker($vault):
#	The path of the change marker (VAULT-LAYOUT-4).
sub marker ($vault)
{
	return "$vault->{dir}/machine/change";
}

# built($t, $vault, $pool):
#	A vault with one stored entry. The creation fills the pool,
#	and add writes the entry a1 with the answer 'secret'.
sub built ( $t, $vault )
{
	my $made = $t->create($vault);
	is( $made->{exit}, 0, 'the creation passes' )
	    or diag( $made->{error} );

	my ($add) = $t->console( $vault,
		{ argv => [ 'add', '-T', 'password', 'a1' ],
			answers => [ 'right', 'secret' ] } );
	is( $add->{exit}, 0, 'add writes the stored entry' )
	    or diag( $add->{error} );
	return $add;
}

# reveals($t, $vault, $secret, $what):
#	One reveal of a1 on the console, and the assertion of the
#	secret on the terminal (PROG-OUTPUT-1).
sub reveals ( $t, $vault, $secret, $what )
{
	my ($show) = $t->console( $vault,
		{ argv => [ 'show', 'a1' ], answers => ['right'] } );
	is( $show->{exit}, 0, "$what: the entry reveals" )
	    or diag( $show->{error} );
	is_deeply( [ $t->terminal($show) ], [$secret],
		"$what: the reveal gives the stored secret" );
	return;
}

# added_oracle_case($t):
#	An added oracle takes the next free position, and the loop
#	enrolls exactly the new pairs (CER-PROVISION-14). The vault
#	starts with two oracles, and the third position takes the
#	third instance.
#
#	The mutation: a loop that enrolls every pair moves the wraps
#	and the entry counters of the two live oracles. The digests of
#	the existing wraps, and the entry counters, then move.
sub added_oracle_case ($t)
{
	my $secret = $t->answer('secret');
	my $v      = $t->ceremony_vault( 'v-add',
		oracles => 2, threshold => $THRESHOLD, pool => $POOL );
	my $add = built( $t, $v );

	my %before = map { $_ => [ sort $t->records($_) ] } 1 .. $ORACLES;
	my $wbefore = wraps_of( $t, $v );

	my @argv = prov_argv( $v,
		oracle => [ map { oracle_arg( $t, $_ ) } 1 .. 3 ] );
	my ($run) = $t->console( $v,
		{ argv => \@argv, answers => [ 'right', 'right' ] } );
	is( $run->{exit}, 0, 'the added-oracle ceremony passes (CER-PROVISION-14)' )
	    or diag( $run->{error} );

	my %o3 = map { $_ => 1 } @{ $before{3} };
	my @new3 = grep { !$o3{$_} } sort $t->records(3);
	is( scalar @new3, $POOL + 1,
		'oracle 3 gained the slot records and the canary of this '
		    . 'machine (CER-PROVISION-14)' );
	is_deeply( [ sort $t->records(1) ], $before{1},
		'the store of oracle 1 is unchanged (CER-PROVISION-14)' );
	is_deeply( [ sort $t->records(2) ], $before{2},
		'the store of oracle 2 is unchanged (CER-PROVISION-14)' );

	my $wafter = wraps_of( $t, $v );
	for my $slot ( 0 .. $POOL - 1 ) {
		for my $o ( 1, 2 ) {
			is( $wafter->{"$slot.$o"}, $wbefore->{"$slot.$o"},
				"the wrap of slot $slot at oracle $o is "
				    . 'unchanged (CER-PROVISION-14)' );
		}
		ok( defined $wafter->{"$slot.3"},
			"the ceremony wrote the wrap of slot $slot at oracle 3 "
			    . '(CER-PROVISION-14)' );
	}
	is( $t->file_exists( $t->seal( $v, oracle => 3 ) ),
		1, 'the canary seal of oracle 3 exists (CER-PROVISION-14)' );
	is( $t->file_exists( $t->index_wrap( $v, oracle => 3 ) ),
		1, 'the index wrap of oracle 3 exists (CER-PROVISION-14)' );

	my %e_run = %{ entry_counters($run) };
	my %e_run12 = map { $_ => $e_run{$_} } grep { !/-3\z/ } keys %e_run;
	is_deeply( \%e_run12, entry_counters($add),
		'the added oracle sent no set_pin to oracle 1 or oracle 2 '
		    . '(CER-PROVISION-14)' );

	reveals( $t, $v, $secret, 'the added oracle' );
	return;
}

# retirement_case($t):
#	A retirement of position 3 deletes this machine's wrap files,
#	canary seal, and index wrap of that position, and the report
#	names the kit (CER-PROVISION-16, ORC-PROVISION-6). A reveal
#	still works on the two live oracles (REC-WIPE-6).
#
#	The mutation: a retirement that skips the deletion leaves the
#	wrap files, the canary seal, and the index wrap of position 3.
sub retirement_case ($t)
{
	my $secret = $t->answer('secret');
	my $v      = $t->ceremony_vault( 'v-retire',
		oracles => $ORACLES, threshold => $THRESHOLD, pool => $POOL );
	built( $t, $v );

	ok( scalar( grep { /\Awrap\.[0-9]+\.3\z/ }
			$t->names("$v->{dir}/machine") ) > 0,
		'the machine holds wraps of position 3 before the retirement' );
	is( $t->file_exists( $t->seal( $v, oracle => 3 ) ),
		1, 'the canary seal of position 3 exists before the retirement' );
	is( $t->file_exists( $t->index_wrap( $v, oracle => 3 ) ),
		1, 'the index wrap of position 3 exists before the retirement' );

	my @argv = prov_argv( $v,
		oracle => [ oracle_arg( $t, 1 ), oracle_arg( $t, 2 ),
			'retired' ] );
	my ($run) = $t->console( $v,
		{ argv => \@argv, answers => [ 'right', 'right' ] } );
	is( $run->{exit}, 0, 'the retirement ceremony passes (CER-PROVISION-16)' )
	    or diag( $run->{error} );

	is( scalar( grep { /\Awrap\.[0-9]+\.3\z/ }
			$t->names("$v->{dir}/machine") ),
		0, 'the retirement deleted the wrap files of position 3 '
		    . '(CER-PROVISION-16)' );
	is( $t->file_exists( $t->seal( $v, oracle => 3 ) ),
		0, 'the retirement deleted the canary seal of position 3 '
		    . '(CER-PROVISION-16)' );
	is( $t->file_exists( $t->index_wrap( $v, oracle => 3 ) ),
		0, 'the retirement deleted the index wrap of position 3 '
		    . '(CER-PROVISION-16)' );
	like( $run->{error}, qr/fugupass kit/,
		'the report names the kit subcommand (CER-PROVISION-16)' );
	like( $t->read_file("$v->{dir}/machine/config") // '',
		qr/^oracle-3: retired$/m,
		'the config names position 3 retired (ORC-PROVISION-6)' );

	reveals( $t, $v, $secret, 'the retirement' );
	return;
}

# threshold_case($t):
#	A threshold change from two to three re-splits every share and
#	re-enrolls every record with a fresh mask (CER-PROVISION-15,
#	KEY-MASK-10). An interrupted change leaves the threshold
#	marker, a session refuses and names the re-run, and the re-run
#	removes the marker.
#
#	The interrupt stops oracle 1, so the first set_pin of the
#	change fails. The marker must already stand.
#
#	The mutations: a marker written after the first set_pin leaves
#	no marker after the interrupt. A change that keeps one old wrap
#	(no fresh set_pin for one record) leaves that wrap digest.
sub threshold_case ($t)
{
	my $secret = $t->answer('secret');
	my $v      = $t->ceremony_vault( 'v-thresh',
		oracles => $ORACLES, threshold => $THRESHOLD, pool => $POOL );
	built( $t, $v );

	my $wbefore = wraps_of( $t, $v );
	my @argv    = prov_argv( $v, threshold => 3,
		oracle => [ map { oracle_arg( $t, $_ ) } 1 .. 3 ] );

	$t->stop_oracle(1);
	my ($stop) = $t->console( $v,
		{ argv => \@argv, answers => [ 'right', 'right' ] } );
	$t->start_oracle(1);

	isnt( $stop->{exit}, 0,
		'the stopped oracle interrupts the threshold change '
		    . '(CER-PROVISION-15)' );
	is( $t->file_exists( marker($v) ),
		1, 'the interrupted change left the marker before the first '
		    . 'set_pin (CER-PROVISION-15)' );
	like( $t->read_file( marker($v) ) // '', qr/\Akind: threshold$/m,
		'the marker holds the threshold kind (CER-PROVISION-15)' );
	like( $t->read_file("$v->{dir}/machine/config") // '',
		qr/^threshold: 3$/m,
		'the ceremony wrote the new threshold before any enrollment '
		    . '(CER-PROVISION-13)' );

	my ($refuse) = $t->console( $v,
		{ argv => [ 'show', 'a1' ], answers => ['right'] } );
	isnt( $refuse->{exit}, 0,
		'a session refuses under the threshold marker (ORC-ENROLL-10)' );
	like( $refuse->{error}, qr/incomplete threshold change/,
		'the refusal names the threshold change (CER-PROVISION-18)' );
	like( $refuse->{error}, qr/"fugupass provision" completes it/,
		'the refusal names the re-run (CER-PROVISION-18)' );
	is( scalar( $t->terminal($refuse) ),
		0, 'the refused session writes no secret to the terminal' );

	my ($rerun) = $t->console( $v,
		{ argv => \@argv, answers => [ 'right', 'right' ] } );
	is( $rerun->{exit}, 0,
		'the threshold re-run completes (CER-PROVISION-15)' )
	    or diag( $rerun->{error} );
	is( $t->file_exists( marker($v) ),
		0, 'the re-run removed the threshold marker (CER-PROVISION-15)' );

	my $wafter = wraps_of( $t, $v );
	for my $k ( sort keys %$wbefore ) {
		isnt( $wafter->{$k}, $wbefore->{$k},
			"the threshold change moved the wrap $k (KEY-MASK-10)" );
	}

	reveals( $t, $v, $secret, 'the threshold change on three oracles' );
	return;
}

# full_run_case($t):
#	A full run removes a passphrase marker (CER-PROVISION-17,
#	ORC-ENROLL-12). A stopped passphrase change leaves the marker,
#	a session refuses, and the -a full run re-enrolls every record
#	and removes the marker.
#
#	The mutation: a full run that does not remove the marker leaves
#	it, so a later session refuses.
sub full_run_case ($t)
{
	my $secret = $t->answer('secret');
	my $v      = $t->ceremony_vault( 'v-full',
		oracles => $ORACLES, threshold => $THRESHOLD, pool => $POOL );
	built( $t, $v );

	$t->write_file( marker($v), 'kind: passphrase' );
	my ($refuse) = $t->console( $v,
		{ argv => [ 'show', 'a1' ], answers => ['right'] } );
	isnt( $refuse->{exit}, 0,
		'a session refuses under the passphrase marker (ORC-ENROLL-10)' );
	like( $refuse->{error}, qr/incomplete passphrase change/,
		'the refusal names the passphrase change (ORC-ENROLL-10)' );
	like( $refuse->{error}, qr/"fugupass resume" completes it/,
		'the refusal names the resume command (ORC-ENROLL-10)' );

	my @argv = prov_argv( $v, full => 1,
		oracle => [ map { oracle_arg( $t, $_ ) } 1 .. 3 ] );
	my ($full) = $t->console( $v,
		{ argv => \@argv, answers => [ 'right', 'right' ] } );
	is( $full->{exit}, 0, 'the -a full run passes (CER-PROVISION-17)' )
	    or diag( $full->{error} );
	is( $t->file_exists( marker($v) ),
		0, 'the full run removed the passphrase marker '
		    . '(CER-PROVISION-17, ORC-ENROLL-12)' );
	like( $full->{error}, qr/removed the change marker/,
		'the report names the removal (ORC-ENROLL-12)' );

	reveals( $t, $v, $secret, 'the full run' );
	return;
}

# wipe_case($t):
#	A wiped record at one oracle blocks no reveal while two records
#	remain, and the ceremony restores the third (REC-WIPE-6). The
#	wipe removes one record file from the store of oracle 3. The
#	deletion of this machine's local files of position 3, and the
#	stop of oracle 2, then prove the loss, and the ceremony heals
#	it (REC-WIPE-2).
sub wipe_case ($t)
{
	my $secret = $t->answer('secret');
	my $v      = $t->ceremony_vault( 'v-wipe',
		oracles => $ORACLES, threshold => $THRESHOLD, pool => $POOL );
	built( $t, $v );

	reveals( $t, $v, $secret, 'before the wipe' );

	my ($rec3) = sort $t->records(3);
	ok( defined $rec3, 'the store of oracle 3 holds a record to wipe' );
	$t->wipe( 3, $rec3 );
	reveals( $t, $v, $secret,
		'a wiped record blocks no reveal while two remain (REC-WIPE-6)' );

	$t->remove_file(
		$t->seal( $v, oracle => 3 ),
		$t->index_wrap( $v, oracle => 3 ),
		map { $t->wrap( $v, slot => $_, oracle => 3 ) } 0 .. $POOL - 1 );

	$t->stop_oracle(2);
	my ($lost) = $t->console( $v,
		{ argv => [ 'show', 'a1' ], answers => ['right'] } );
	$t->start_oracle(2);
	isnt( $lost->{exit}, 0,
		'the reveal by oracle 3 fails while its local files are gone '
		    . '(REC-WIPE-6)' );

	my @argv = prov_argv( $v,
		oracle => [ map { oracle_arg( $t, $_ ) } 1 .. 3 ] );
	my ($run) = $t->console( $v,
		{ argv => \@argv, answers => [ 'right', 'right' ] } );
	is( $run->{exit}, 0, 'the ceremony restores position 3 (REC-WIPE-2)' )
	    or diag( $run->{error} );
	is( $t->file_exists( $t->index_wrap( $v, oracle => 3 ) ),
		1, 'the ceremony wrote the index wrap of position 3 again '
		    . '(REC-WIPE-2)' );
	is( $t->file_exists( $t->seal( $v, oracle => 3 ) ),
		1, 'the ceremony sealed the canary of position 3 again '
		    . '(REC-WIPE-2)' );

	$t->stop_oracle(2);
	my ($healed) = $t->console( $v,
		{ argv => [ 'show', 'a1' ], answers => ['right'] } );
	$t->start_oracle(2);
	is( $healed->{exit}, 0,
		'the reveal by oracle 3 works after the ceremony (REC-WIPE-6)' )
	    or diag( $healed->{error} );
	is_deeply( [ $t->terminal($healed) ], [$secret],
		'the healed reveal gives the stored secret (REC-WIPE-6)' );
	return;
}

return sub ($t)
{
	subtest 'the added oracle'   => sub { added_oracle_case($t) };
	subtest 'the retirement'     => sub { retirement_case($t) };
	subtest 'the threshold change' => sub { threshold_case($t) };
	subtest 'the full run'       => sub { full_run_case($t) };
	subtest 'the wiped record'   => sub { wipe_case($t) };
	return;
};
