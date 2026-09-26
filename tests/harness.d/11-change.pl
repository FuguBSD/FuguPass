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

# The change leg (ORC-ENROLL-4 to ORC-ENROLL-11, CER-REFILL-2,
# CER-REFILL-4, CER-REFILL-8, TEST-HARNESS-5).
#
# The leg runs the passphrase change, the resume of it, and the pool
# refill against the example topology of three oracles with a
# threshold of two (TEST-HARNESS-5). Each case takes a vault of its
# own: a change replaces the pin of every record of one vault, and a
# refill extends the pool of one vault. One case takes a threshold
# of three over the same three instances, and the comment of that
# case states the reason.
#
# The three subcommands read the passphrases from /dev/tty, so each
# one runs on the console of the guest (TEST-HARNESS-8). passwd and
# resume read four answers: each passphrase twice (ORC-ENROLL-8,
# ORC-CANARY-6). refill reads one answer, and create reads two.
#
# A ceremony vault takes the machine name of its tag, so each vault
# of this leg addresses records of its own at the counterparty
# (KEY-DEVICE-1).
#
# Each case names the mutation that it catches. An assertion that no
# mutation fails proves nothing, so a state assertion compares the
# state of the moment with a state that this file recorded before
# the step, and never with a value that the step itself writes.

use v5.36;

# The example topology of TEST-HARNESS-5, for every case of this
# leg. The leg takes one instance for each position, and the
# harness reads that count at the load.
my $ORACLES   = 3;
my $THRESHOLD = 2;
our $INSTANCES = $ORACLES;

# The greatest counter of a record (ORC-COUNTER-5). The client sends
# the stored value plus one at least, and it never sends this value,
# so a record of this counter takes no request of this machine.
my $MAX_COUNTER = 4_294_967_295;

# marker($vault):
#	The path of the change marker of the machine
#	(VAULT-LAYOUT-4).
sub marker ($vault)
{
	return "$vault->{dir}/machine/change";
}

# done_lines($t, $vault):
#	The record names of the done lines of the marker, in the
#	order of the file (ORC-ENROLL-10). An absent marker gives the
#	empty list.
sub done_lines ( $t, $vault )
{
	my $text = $t->read_file( marker($vault) ) // q{};
	return $text =~ /^done: (\S+)$/mg;
}

# slot_files($t, $vault):
#	The slot file names of the vault (VAULT-LAYOUT-5). The name
#	of one file is the hex of the hash of the entry key, so the
#	count of the names is the count of the reserved slots.
sub slot_files ( $t, $vault )
{
	return grep { /\A[0-9a-f]{64}\z/ } $t->names( $vault->{dir} );
}

# machine_state($t, $vault):
#	The digest of each wrap, each index wrap and each canary seal
#	of the machine, by file name (VAULT-LAYOUT). A set_pin gives
#	a fresh mask, and the wrap of that record then holds other
#	bytes (ORC-ENROLL-3). A canary enrollment writes the seal and
#	the index wrap of that oracle again (ORC-ENROLL-6).
sub machine_state ( $t, $vault )
{
	my %digest;

	for my $name ( $t->names("$vault->{dir}/machine") ) {
		next if $name !~ /\A(?:wrap[.]|canary[.])/;
		$digest{$name} = $t->digest("$vault->{dir}/machine/$name");
	}
	return %digest;
}

# change_case($t):
#	The whole passphrase change (ORC-ENROLL-4, TEST-HARNESS-5).
#	The change ends with no marker, with fresh bytes in every
#	file of the machine that a record writes, and with every
#	record under the new pin.
#
#	The digests come from the state before the change, and no
#	step of this leg writes one of them. The reveal of the new
#	passphrase and the refused reveal of the old one prove the
#	pin of the records, and the counterparty holds that pin.
#
#	The last reveal stops oracle 1, so the quorum takes oracle 2
#	and oracle 3. It therefore proves the records of the oracle
#	that the first quorum does not hold.
#
#	The mutation: a slot loop that steps over the last oracle
#	keeps the wrap of that oracle, and the fresh-bytes assertion
#	then holds that file. A change that sends no set_pin keeps
#	every wrap, and the old passphrase then reveals the entry.
sub change_case ($t)
{
	my $secret = $t->answer('secret');
	my $pool   = 4;
	my $vault  = $t->ceremony_vault(
		'c-new',
		oracles   => $ORACLES,
		threshold => $THRESHOLD,
		pool      => $pool );

	my $made = $t->create($vault);
	is( $made->{exit}, 0, 'the creation of the change vault passes' )
	    or diag( $made->{error} );

	my ($add) = $t->console( $vault,
		{ argv => [ 'add', '-T', 'password', 'a1' ],
			answers => [ 'right', 'secret' ] } );
	is( $add->{exit}, 0, 'add writes the entry of the change vault' )
	    or diag( $add->{error} );

	my %before = machine_state( $t, $vault );
	is( scalar keys %before, ( $pool + 2 ) * $ORACLES,
		'the machine holds one wrap of each record, one index wrap '
		    . 'of each oracle, and one canary seal of each oracle' );

	my ($change) = $t->console( $vault,
		{ argv => ['passwd'],
			answers => [ 'right', 'right', 'other', 'other' ] } );
	is( $change->{exit}, 0, 'the passphrase change passes '
		    . '(ORC-ENROLL-4)' )
	    or diag( $change->{error} );
	is( $t->file_exists( marker($vault) ),
		0, 'the complete change removed the marker (ORC-ENROLL-10)' );

	my %after = machine_state( $t, $vault );
	is_deeply( [ sort keys %after ], [ sort keys %before ],
		'the change holds the file set of the machine' );
	my @stale = grep { ( $after{$_} // q{} ) eq $before{$_} }
	    sort keys %before;
	is_deeply( \@stale, [],
		'each file of the machine holds fresh bytes, so each record '
		    . 'took a set_pin of the new pin (ORC-ENROLL-3, '
		    . 'ORC-ENROLL-6)' );

	my ( $new, $old ) = $t->console(
		$vault,
		{ argv => [ 'show', 'a1' ], answers => ['other'] },
		{ argv => [ 'show', 'a1' ], answers => ['right'] } );

	is( $new->{exit}, 0, 'the new passphrase opens a session and '
		    . 'reveals the entry (ORC-ENROLL-4)' )
	    or diag( $new->{error} );
	is_deeply( [ $t->terminal($new) ], [$secret],
		'the reveal of the new passphrase gives the secret of the '
		    . 'entry (ORC-ENROLL-4)' );
	isnt( $old->{exit}, 0,
		'the old passphrase opens no session after the change '
		    . '(ORC-ENROLL-4)' );
	like( $old->{error}, qr/the canary of oracle 1 .* the check fails/,
		'the report of the old passphrase names the first canary '
		    . '(ORC-CANARY-4)' );
	is( scalar( $t->terminal($old) ),
		0, 'the old passphrase reveals no secret' );

	$t->stop_oracle(1);
	my ($far) = $t->console( $vault,
		{ argv => [ 'show', 'a1' ], answers => ['other'] } );
	$t->start_oracle(1);

	is( $far->{exit}, 0, 'the quorum of oracle 2 and oracle 3 reveals '
		    . 'the entry under the new passphrase (ORC-ENROLL-4)' )
	    or diag( $far->{error} );
	is_deeply( [ $t->terminal($far) ], [$secret],
		'the records of the third oracle answer the new pin '
		    . '(ORC-ENROLL-4)' );
	return;
}

# stop_case($t):
#	A change that stops after the third record, and the resume of
#	it (ORC-ENROLL-10).
#
#	The counters file gives the record of slot 1 at oracle 1 the
#	greatest counter, so this machine sends no request of that
#	record (ORC-COUNTER-5). The change therefore ends the first
#	slot, and it stops at the first record of the second one.
#
#	The marker then holds the three records of the first slot,
#	and a session refuses a reveal. The restored counter lets the
#	resume complete the change.
#
#	The mutation: a done line that comes before its set_pin gives
#	the marker a fourth line, and the marker assertion holds
#	three names. A session that reveals while the marker exists
#	fails the refusal assertion. A resume that takes the new pin
#	for an unlisted record fails at the first quorum.
sub stop_case ($t)
{
	my $secret = $t->answer('secret2');
	my $vault  = $t->ceremony_vault(
		'c-stop',
		oracles   => $ORACLES,
		threshold => $THRESHOLD,
		pool      => 2 );

	my $made = $t->create($vault);
	is( $made->{exit}, 0, 'the creation of the stop vault passes' )
	    or diag( $made->{error} );

	my ($add) = $t->console( $vault,
		{ argv => [ 'add', '-T', 'password', 'a1' ],
			answers => [ 'right', 'secret2' ] } );
	is( $add->{exit}, 0, 'add writes the entry of the stop vault' )
	    or diag( $add->{error} );

	# The counter of that one record, above every value that this
	# machine sends. Every other line of the file stays.
	my $record = $t->record( $vault, slot => 1, oracle => 1 );
	my $file   = $t->counters($vault);
	my $text   = $t->read_file($file) // q{};
	my ($keep) = $text =~ /^\Q$record\E: ([0-9]+)$/m;
	ok( defined $keep,
		"the counters file holds the record $record (ORC-COUNTER-2)" );
	my @line = grep { !/\A\Q$record\E: / } split /\n/, $text;
	$t->write_file( $file, @line, "$record: $MAX_COUNTER" );

	my ($stop) = $t->console( $vault,
		{ argv => ['passwd'],
			answers => [ 'right', 'right', 'other', 'other' ] } );

	my $url = $t->url(1);
	isnt( $stop->{exit}, 0,
		'the record of the greatest counter stops the change '
		    . '(ORC-COUNTER-5)' );
	like( $stop->{error},
		qr/slot 1 at oracle 1 \(\Q$url\E\): the request fails/,
		'the report names the record that stopped the change' );
	like( $stop->{error},
		qr/the change stays incomplete, and "fugupass resume"/,
		'the report names the resume command (ORC-ENROLL-10)' );
	is( $t->file_exists( marker($vault) ),
		1, 'the stopped change leaves the marker (ORC-ENROLL-10)' );
	like( $t->read_file( marker($vault) ), qr/\Akind: passphrase$/m,
		'the marker holds the kind of a passphrase change '
		    . '(ORC-ENROLL-10)' );
	is_deeply( [ done_lines( $t, $vault ) ], [ '0-1', '0-2', '0-3' ],
		'the marker holds one done line of each record of the first '
		    . 'slot, and no line of the stopped record '
		    . '(ORC-ENROLL-10)' );

	# The canary records re-enroll last, so the session of this
	# marker opens under the old passphrase (ORC-ENROLL-10).
	my ($refuse) = $t->console( $vault,
		{ argv => [ 'show', 'a1' ], answers => ['right'] } );
	isnt( $refuse->{exit}, 0,
		'a session refuses the reveal while the marker exists '
		    . '(ORC-ENROLL-10)' );
	like( $refuse->{error}, qr/incomplete passphrase change/,
		'the refusal names the incomplete change (ORC-ENROLL-10)' );
	like( $refuse->{error}, qr/"fugupass resume" completes it/,
		'the refusal names the resume command (ORC-ENROLL-10)' );
	is( scalar( $t->terminal($refuse) ),
		0, 'the refused session writes no secret to the terminal' );

	# The counter of the record, as it stood before the change.
	# No request of it reached the oracle, so the stored counter
	# of the record stands where the creation left it.
	@line = grep { !/\A\Q$record\E: / }
	    split /\n/, $t->read_file($file) // q{};
	$t->write_file( $file, @line, "$record: $keep" );

	my ($resume) = $t->console( $vault,
		{ argv => ['resume'],
			answers => [ 'right', 'right', 'other', 'other' ] } );
	is( $resume->{exit}, 0, 'the resume completes the change '
		    . '(ORC-ENROLL-10)' )
	    or diag( $resume->{error} );
	is( $t->file_exists( marker($vault) ),
		0, 'the resume removed the marker (ORC-ENROLL-10)' );

	my ($show) = $t->console( $vault,
		{ argv => [ 'show', 'a1' ], answers => ['other'] } );
	is( $show->{exit}, 0,
		'the new passphrase opens a session after the resume '
		    . '(ORC-ENROLL-10)' )
	    or diag( $show->{error} );
	is_deeply( [ $t->terminal($show) ], [$secret],
		'every record answers the new pin after the resume '
		    . '(ORC-ENROLL-10)' );
	return;
}

# down_case($t):
#	A change with one oracle stopped (ORC-ENROLL-11). The change
#	needs every live oracle, so it stops at the record of the
#	stopped one, and the marker stays.
#
#	The restart after the return of the oracle completes the
#	change. The resume takes the new pin for each record of the
#	marker list, and the old pin for every other record
#	(ORC-ENROLL-10).
#
#	The mutation: a change that steps over an unreachable oracle
#	passes, and the exit assertion holds a failure. A change that
#	removes the marker on a failure fails the marker assertion.
sub down_case ($t)
{
	my $secret = $t->answer('secret');
	my $vault  = $t->ceremony_vault(
		'c-down',
		oracles   => $ORACLES,
		threshold => $THRESHOLD,
		pool      => 2 );

	my $made = $t->create($vault);
	is( $made->{exit}, 0, 'the creation of the down vault passes' )
	    or diag( $made->{error} );

	my ($add) = $t->console( $vault,
		{ argv => [ 'add', '-T', 'password', 'a1' ],
			answers => [ 'right', 'secret' ] } );
	is( $add->{exit}, 0, 'add writes the entry of the down vault' )
	    or diag( $add->{error} );

	$t->stop_oracle($ORACLES);
	my ($down) = $t->console( $vault,
		{ argv => ['passwd'],
			answers => [ 'right', 'right', 'other', 'other' ] } );
	$t->start_oracle($ORACLES);

	my $url = $t->url($ORACLES);
	isnt( $down->{exit}, 0,
		'the stopped oracle leaves the change incomplete '
		    . '(ORC-ENROLL-11)' );
	like( $down->{error},
		qr/oracle $ORACLES \(\Q$url\E\) stays out of reach/,
		'the report names the oracle that no request reaches '
		    . '(ORC-ENROLL-11)' );
	is( $t->file_exists( marker($vault) ),
		1, 'the incomplete change leaves the marker '
		    . '(ORC-ENROLL-11)' );
	is_deeply( [ done_lines( $t, $vault ) ], [ '0-1', '0-2' ],
		'the marker holds the records of the two reachable oracles '
		    . 'of the first slot (ORC-ENROLL-10)' );

	my ($back) = $t->console( $vault,
		{ argv => ['resume'],
			answers => [ 'right', 'right', 'other', 'other' ] } );
	is( $back->{exit}, 0,
		'the restart after the return of the oracle completes the '
		    . 'change (ORC-ENROLL-11)' )
	    or diag( $back->{error} );
	is( $t->file_exists( marker($vault) ),
		0, 'the complete change removed the marker (ORC-ENROLL-10)' );

	my ($show) = $t->console( $vault,
		{ argv => [ 'show', 'a1' ], answers => ['other'] } );
	is( $show->{exit}, 0,
		'the new passphrase opens a session after the restart' )
	    or diag( $show->{error} );
	is_deeply( [ $t->terminal($show) ], [$secret],
		'every record answers the new pin after the restart '
		    . '(ORC-ENROLL-11)' );
	return;
}

# reach_case($t):
#	A change that starts with fewer than k reachable oracles
#	(ORC-ENROLL-11). The change stops before the marker write,
#	and before the first re-enrollment.
#
#	The vault of this case takes a threshold of three over the
#	three instances. A record-side canary failure needs a pass at
#	another oracle before it (ORC-CANARY-4), so a start with one
#	such failure holds two answers at least. A threshold of two
#	therefore admits no start below k with a canary to repair.
#
#	The canary seal of the second oracle takes the seal of the
#	first one. That file opens under no canary mask of the second
#	oracle, so the check of it gives a junk answer after the pass
#	at the first oracle (ORC-CANARY-9). The third oracle stops,
#	so two of the three oracles answer.
#
#	The mutation: a repair of that second canary before the reach
#	gate sends a set_pin of the canary record. It writes the
#	canary seal of that oracle again, and it takes the index wrap
#	of that oracle away, so the state of the machine then moves.
#	The report states that the change sends no set_pin, and that
#	statement holds while the machine keeps its bytes.
sub reach_case ($t)
{
	my $vault = $t->ceremony_vault(
		'c-reach',
		oracles   => $ORACLES,
		threshold => $ORACLES,
		pool      => 1 );

	my $made = $t->create($vault);
	is( $made->{exit}, 0, 'the creation of the reach vault passes' )
	    or diag( $made->{error} );

	$t->copy_file( $t->seal( $vault, oracle => 1 ),
		$t->seal( $vault, oracle => 2 ) );
	my %before = machine_state( $t, $vault );

	$t->stop_oracle($ORACLES);
	my ($run) = $t->console( $vault,
		{ argv => ['passwd'],
			answers => [ 'right', 'right', 'other', 'other' ] } );
	$t->start_oracle($ORACLES);

	isnt( $run->{exit}, 0,
		'a start below the threshold stops the change '
		    . '(ORC-ENROLL-11)' );
	like( $run->{error},
		qr/the quorum takes $ORACLES reachable oracles, and 2 answered/,
		'the report names the threshold and the count of the oracles '
		    . 'that answered (ORC-ENROLL-11)' );
	like( $run->{error}, qr/the change sends no set_pin/,
		'the report states that no record takes a set_pin '
		    . '(ORC-ENROLL-11)' );
	is( $t->file_exists( marker($vault) ),
		0, 'the stopped change wrote no marker, and the marker comes '
		    . 'before the first set_pin (ORC-ENROLL-10)' );
	is_deeply( { machine_state( $t, $vault ) },
		\%before,
		'each wrap, each index wrap and each canary seal holds the '
		    . 'bytes of the step before, so the change re-enrolled '
		    . 'no canary (ORC-ENROLL-11, ORC-CANARY-5)' );
	return;
}

# typo_case($t):
#	A mistyped old passphrase (ORC-ENROLL-8). The change checks
#	the canary of the first oracle, and that check fails. The
#	change then sends no set_pin, and it writes no marker.
#
#	The counters file after the step states the requests of the
#	step, so the counters of the step before it give the measure
#	(ORC-COUNTER-2). Each record but the canary of the first
#	oracle keeps its counter.
#
#	The mutation: a canary re-enrollment at the first canary
#	sends a set_pin of that record, and the counter of the canary
#	of the second oracle then moves as well. A change that writes
#	the marker before the verification fails the marker
#	assertion.
sub typo_case ($t)
{
	my $vault = $t->ceremony_vault(
		'c-typo',
		oracles   => $ORACLES,
		threshold => $THRESHOLD,
		pool      => 1 );

	my $made = $t->create($vault);
	is( $made->{exit}, 0, 'the creation of the typo vault passes' )
	    or diag( $made->{error} );

	my ( $base, $typo ) = $t->console(
		$vault,
		{ argv => ['ls'], answers => ['right'] },
		{ argv => ['passwd'],
			answers => [ 'wrong', 'wrong', 'other', 'other' ] } );

	my $url = $t->url(1);
	is( $base->{exit}, 0, 'ls opens the session of the typo vault' )
	    or diag( $base->{error} );
	isnt( $typo->{exit}, 0,
		'a mistyped old passphrase stops the change (ORC-ENROLL-8)' );
	like( $typo->{error},
		qr/the canary of oracle 1 \(\Q$url\E\): the check fails/,
		'the report names the canary of the first oracle '
		    . '(ORC-CANARY-4)' );
	like( $typo->{error}, qr/the cause is the passphrase/,
		'the report of the first canary holds the typo case '
		    . '(ORC-CANARY-4)' );
	like( $typo->{error}, qr/the change sends no set_pin/,
		'the report states that no record takes a set_pin '
		    . '(ORC-ENROLL-8)' );
	is( $t->file_exists( marker($vault) ),
		0, 'the stopped change wrote no marker, and the marker '
		    . 'comes before the first set_pin (ORC-ENROLL-10)' );

	my %was = %{ $base->{counters} };
	my %now = %{ $typo->{counters} };
	is_deeply( [ sort keys %now ], [ sort keys %was ],
		'the stopped change enrolled no record of a new name' );
	ok( ( $now{'canary-1'} // 0 ) > ( $was{'canary-1'} // 0 ),
		'the change checked the canary of the first oracle '
		    . '(ORC-CANARY-1)' );
	my @moved = grep { $_ ne 'canary-1' && ( $now{$_} // -1 ) != $was{$_} }
	    sort keys %was;
	is_deeply( \@moved, [],
		'the walk stopped at the first canary, so no other record '
		    . 'takes a request (ORC-CANARY-4, ORC-ENROLL-8)' );
	return;
}

# resume_typo_case($t):
#	A mistyped old passphrase of a resume (ORC-CANARY-4,
#	ORC-CANARY-10). The marker of the resume holds the canary of
#	the first oracle, so that canary answers the new passphrase
#	and every other canary answers the old one (ORC-ENROLL-10).
#
#	The counters file gives the canary of the second oracle the
#	greatest counter, so this machine sends no request of that
#	record (ORC-COUNTER-5). The first change therefore ends the
#	canary of the first oracle, and it stops at the canary of the
#	second one. The restored counter lets the last resume
#	complete the change.
#
#	The resume between the two mistypes the old passphrase. The
#	canary of the first oracle passes under the new passphrase,
#	and the canary of the second one gives a junk answer under
#	the mistyped old one. That junk answer is the first of the
#	old passphrase, so it holds the typo case and it stops the
#	resume (ORC-CANARY-4).
#
#	The mutation: one pass count over both passphrases takes the
#	pass of the first oracle for the old passphrase as well. The
#	junk answer then looks record-side, and the resume re-enrolls
#	the canary of the second oracle under the mistyped
#	passphrase. That canary then accepts the mistyped passphrase,
#	which is the poisoned canary of ORC-CANARY-10. The resume
#	completes, so the exit assertion and the state of the machine
#	both hold the mutation.
sub resume_typo_case ($t)
{
	my $secret = $t->answer('secret');
	my $vault  = $t->ceremony_vault(
		'c-rtypo',
		oracles   => $ORACLES,
		threshold => $THRESHOLD,
		pool      => 2 );

	my $made = $t->create($vault);
	is( $made->{exit}, 0, 'the creation of the resume typo vault passes' )
	    or diag( $made->{error} );

	my ($add) = $t->console( $vault,
		{ argv => [ 'add', '-T', 'password', 'a1' ],
			answers => [ 'right', 'secret' ] } );
	is( $add->{exit}, 0, 'add writes the entry of the resume typo vault' )
	    or diag( $add->{error} );

	# The counter of the canary of the second oracle, above every
	# value that this machine sends. Every other line stays.
	my $canary = $t->canary_record( $vault, oracle => 2 );
	my $file   = $t->counters($vault);
	my $text   = $t->read_file($file) // q{};
	my ($keep) = $text =~ /^\Q$canary\E: ([0-9]+)$/m;
	ok( defined $keep,
		"the counters file holds the record $canary (ORC-COUNTER-2)" );
	my @line = grep { !/\A\Q$canary\E: / } split /\n/, $text;
	$t->write_file( $file, @line, "$canary: $MAX_COUNTER" );

	my ($stop) = $t->console( $vault,
		{ argv => ['passwd'],
			answers => [ 'right', 'right', 'other', 'other' ] } );
	isnt( $stop->{exit}, 0,
		'the canary of the greatest counter stops the change '
		    . '(ORC-COUNTER-5)' );
	is_deeply( [ done_lines( $t, $vault ) ],
		[ '0-1', '0-2', '0-3', '1-1', '1-2', '1-3', 'canary-1' ],
		'the marker holds each record of the two slots and the '
		    . 'canary of the first oracle (ORC-ENROLL-10)' );

	# The counter of the canary, as it stood before the change.
	# No request of it reached the oracle.
	@line = grep { !/\A\Q$canary\E: / }
	    split /\n/, $t->read_file($file) // q{};
	$t->write_file( $file, @line, "$canary: $keep" );

	my %before = machine_state( $t, $vault );
	my $url    = $t->url(2);
	my ($typo) = $t->console( $vault,
		{ argv => ['resume'],
			answers => [ 'wrong', 'wrong', 'other', 'other' ] } );

	isnt( $typo->{exit}, 0,
		'a mistyped old passphrase stops the resume (ORC-CANARY-4)' );
	like( $typo->{error},
		qr/the canary of oracle 2 \(\Q$url\E\): the check fails/,
		'the report names the canary of the first oracle of the old '
		    . 'passphrase (ORC-CANARY-4)' );
	like( $typo->{error}, qr/the cause is the passphrase/,
		'the report holds the typo case, because no canary of the '
		    . 'old passphrase passed (ORC-CANARY-4)' );
	unlike( $typo->{error}, qr/the passphrase passed at oracle/,
		'the report names no pass of the other passphrase '
		    . '(ORC-CANARY-4)' );
	like( $typo->{error}, qr/the change sends no set_pin/,
		'the report states that no record takes a set_pin '
		    . '(ORC-ENROLL-8)' );
	is( $t->file_exists( marker($vault) ),
		1, 'the stopped resume leaves the marker (ORC-ENROLL-10)' );
	is_deeply( { machine_state( $t, $vault ) },
		\%before,
		'each wrap, each index wrap and each canary seal holds the '
		    . 'bytes of the step before, so the resume re-enrolled '
		    . 'no canary under the mistyped passphrase '
		    . '(ORC-CANARY-10)' );

	my ($done) = $t->console( $vault,
		{ argv => ['resume'],
			answers => [ 'right', 'right', 'other', 'other' ] } );
	is( $done->{exit}, 0,
		'the old passphrase completes the change after the stopped '
		    . 'resume (ORC-ENROLL-10)' )
	    or diag( $done->{error} );
	is( $t->file_exists( marker($vault) ),
		0, 'the resume removed the marker (ORC-ENROLL-10)' );

	my ($show) = $t->console( $vault,
		{ argv => [ 'show', 'a1' ], answers => ['other'] } );
	is( $show->{exit}, 0,
		'the new passphrase opens a session after the resume' )
	    or diag( $show->{error} );
	is_deeply( [ $t->terminal($show) ], [$secret],
		'every record answers the new pin after the resume '
		    . '(ORC-ENROLL-10)' );
	return;
}

# damage_case($t):
#	A slot file with one damaged byte (ORC-ENROLL-9). The change
#	reconstructs the entry key of the slot, and the file of it
#	does not open. Each quorum of the reachable oracles gives the
#	same key, so the change stops before the first set_pin of
#	that slot.
#
#	The pool of this vault holds one slot, so the vault holds one
#	slot file and the leg needs no map of a name to a slot index.
#	tests/stubs/damage.pl writes the last byte of that file
#	again, with each bit inverted, and the file keeps its length
#	(VAULT-SEAL-1).
#
#	The mutation: a change that takes a failed decrypt as a pass
#	enrolls the slot, and the exit assertion holds a failure. A
#	change that enrolls before the decrypt writes the wraps of
#	the slot, and the digests of the machine then move.
sub damage_case ($t)
{
	my $vault = $t->ceremony_vault(
		'c-damage',
		oracles   => $ORACLES,
		threshold => $THRESHOLD,
		pool      => 1 );

	my $made = $t->create($vault);
	is( $made->{exit}, 0, 'the creation of the damage vault passes' )
	    or diag( $made->{error} );

	my @file = slot_files( $t, $vault );
	is( scalar @file, 1, 'the pool of one slot holds one slot file '
		    . '(ENTRY-POOL-2)' );
	my $path = "$vault->{dir}/$file[0]";
	my $was  = $t->digest($path);

	my $run = $t->perl( 'tests/stubs/damage.pl', $path );
	is( $run->{exit}, 0, 'the stub damaged one byte of the slot file' )
	    or diag( $run->{error} );
	isnt( $t->digest($path), $was,
		'the slot file holds other bytes than the creation wrote' );

	my %before = machine_state( $t, $vault );
	my ($stop) = $t->console( $vault,
		{ argv => ['passwd'],
			answers => [ 'right', 'right', 'other', 'other' ] } );

	isnt( $stop->{exit}, 0,
		'the damaged slot file stops the change (ORC-ENROLL-9)' );
	my @attempt = $stop->{error} =~ /slot 0: the file of this quorum/g;
	is( scalar @attempt, 2,
		'the change tried a second quorum after the first failure, '
		    . 'and each one failed the decrypt (ORC-ENROLL-9, '
		    . 'ORC-QUORUM-5)' );
	for my $oracle ( 1 .. $ORACLES ) {
		my $url = $t->url($oracle);
		like( $stop->{error},
			qr/the attempt holds oracle $oracle \(\Q$url\E\)/,
			"the report names oracle $oracle of a quorum "
			    . '(ORC-ENROLL-9)' );
	}
	like( $stop->{error},
		qr/slot 0: no untried reachable oracle remains/,
		'the report names the slot of the stop (ORC-ENROLL-9)' );
	is( $t->file_exists( marker($vault) ),
		1, 'the stopped change leaves the marker (ORC-ENROLL-10)' );
	is_deeply( [ done_lines( $t, $vault ) ], [],
		'the marker holds no done line (ORC-ENROLL-10)' );
	is_deeply( { machine_state( $t, $vault ) },
		\%before,
		'each wrap, each index wrap and each canary seal holds the '
		    . 'bytes of the creation, so the change sent no set_pin '
		    . 'of the slot (ORC-ENROLL-9)' );
	return;
}

# refill_case($t):
#	The pool refill (CER-REFILL-2, CER-REFILL-4). The vault takes
#	the pool of a creation with no -p option, so the config holds
#	64 slots and the refill adds 64 (ENTRY-POOL-2).
#
#	The digests come from the state before the refill, and the
#	refill writes no file of that set (CER-REFILL-4). The two
#	entries of the vault stand on the first two slots, and the
#	reveal of one of them proves the entry after the refill.
#
#	The second refill takes a config of two slots, and it proves
#	the pool-next line of the index: the two new slots stand
#	above every slot of the first refill (CER-REFILL-2). A refill
#	that records no pool-next reserves the indexes of the first
#	refill again, and the count of the slot files then stays.
#
#	The mutation: a refill that reserves from 0 writes the file
#	of an existing entry again, and the digest of that file then
#	moves. A refill that records a stale pool-next leaves the
#	count of the second refill at 128.
sub refill_case ($t)
{
	my $secret = $t->answer('secret2');
	my $vault  = $t->ceremony_vault( 'r-pool', oracles => $ORACLES,
		threshold => $THRESHOLD );

	my $made = $t->create($vault);
	is( $made->{exit}, 0, 'the creation of the refill vault passes' )
	    or diag( $made->{error} );

	my ( $add, $gen ) = $t->console(
		$vault,
		{ argv => [ 'add', '-T', 'password', 'a1' ],
			answers => [ 'right', 'secret2' ] },
		{ argv => [ 'gen', '-T', 'password', 'g1' ],
			answers => ['right'] } );
	is( $add->{exit}, 0, 'add writes the stored entry of the vault' )
	    or diag( $add->{error} );
	is( $gen->{exit}, 0, 'gen writes the derived entry of the vault' )
	    or diag( $gen->{error} );

	my %before = map { $_ => $t->digest("$vault->{dir}/$_") }
	    slot_files( $t, $vault );
	is( scalar keys %before, 64,
		'the creation wrote the 64 slot files of the pool '
		    . '(ENTRY-POOL-2)' );
	my $index = $t->digest("$vault->{dir}/index");

	my ($refill) = $t->console( $vault,
		{ argv => ['refill'], answers => ['right'] } );
	is( $refill->{exit}, 0, 'the refill ceremony passes (CER-REFILL-2)' )
	    or diag( $refill->{error} );

	my @now = slot_files( $t, $vault );
	is( scalar @now, 128,
		'the refill reserved 64 slot indexes above the pool of the '
		    . 'creation (CER-REFILL-2)' );
	my @changed = grep { $t->digest("$vault->{dir}/$_") ne $before{$_} }
	    sort keys %before;
	is_deeply( \@changed, [],
		'every file of the creation holds its bytes, so the refill '
		    . 'changed no entry (CER-REFILL-4)' );
	isnt( $t->digest("$vault->{dir}/index"),
		$index, 'the refill wrote the pool state to the index '
		    . '(CER-REFILL-2)' );

	my ($show) = $t->console( $vault,
		{ argv => [ 'show', 'a1' ], answers => ['right'] } );
	is( $show->{exit}, 0, 'the session opens the index after the refill' )
	    or diag( $show->{error} );
	is_deeply( [ $t->terminal($show) ], [$secret],
		'the entry of the first slot still reveals its secret '
		    . '(CER-REFILL-4)' );

	# The pool size of the config gives the count of one refill,
	# so a config of two slots holds the second one at two
	# (ENTRY-POOL-2). Every other line of the file stays.
	my $config = "$vault->{dir}/machine/config";
	my @line   = map { /\Apool-size: / ? 'pool-size: 2' : $_ }
	    split /\n/, $t->read_file($config) // q{};
	$t->write_file( $config, @line );

	my ($second) = $t->console( $vault,
		{ argv => ['refill'], answers => ['right'] } );
	is( $second->{exit}, 0, 'the second refill passes' )
	    or diag( $second->{error} );
	is( scalar( () = slot_files( $t, $vault ) ),
		130, 'the second refill reserved two indexes above the '
		    . 'slots of the first one, so the index holds the '
		    . 'pool-next of it (CER-REFILL-2)' );
	return;
}

# pending_case($t):
#	The refill of a vault that holds the change marker
#	(CER-REFILL-8). The ceremony refuses to start, and the report
#	names the resume command.
#
#	The marker of this case is a file of one kind line, because
#	the refusal reads the marker file and no line of it. The
#	vault is complete, so a refill that starts extends the pool
#	of it.
#
#	The step holds one answer, and the refusal leaves it unsent:
#	the console sends an answer to a prompt alone, and the
#	refusal comes before the read of the passphrase. A refill
#	that starts reads that answer, and the step then ends at the
#	assertions below and not at the timeout of the console.
#
#	The mutation: a refill without the marker gate runs the slot
#	loop, and the count of the slot files then moves. It sends a
#	set_pin of each new record, and the counters of the vault
#	then move as well.
sub pending_case ($t)
{
	my $vault = $t->ceremony_vault(
		'r-marker',
		oracles   => $ORACLES,
		threshold => $THRESHOLD,
		pool      => 1 );

	my $made = $t->create($vault);
	is( $made->{exit}, 0, 'the creation of the marker vault passes' )
	    or diag( $made->{error} );

	my @before = slot_files( $t, $vault );
	my $index  = $t->digest("$vault->{dir}/index");
	$t->write_file( marker($vault), 'kind: passphrase' );

	my ($run) = $t->console( $vault,
		{ argv => ['refill'], answers => ['right'] } );
	isnt( $run->{exit}, 0,
		'the refill refuses to start while the marker exists '
		    . '(CER-REFILL-8)' );
	like( $run->{error}, qr/incomplete passphrase change/,
		'the refusal names the incomplete change (CER-REFILL-8)' );
	like( $run->{error}, qr/"fugupass resume" completes it/,
		'the refusal names the resume command (CER-REFILL-8)' );
	is_deeply( [ slot_files( $t, $vault ) ], \@before,
		'the refused refill reserved no slot (CER-REFILL-8)' );
	is( $t->digest("$vault->{dir}/index"),
		$index, 'the refused refill wrote no index (CER-REFILL-8)' );
	is_deeply( $run->{counters}, $made->{counters},
		'the refused refill sent no request (CER-REFILL-8)' );

	$t->remove_file( marker($vault) );
	return;
}

return sub ($t)
{
	subtest 'the passphrase change of three oracles' =>
	    sub { change_case($t) };
	subtest 'the stopped change and the resume of it' =>
	    sub { stop_case($t) };
	subtest 'the change with one oracle stopped' =>
	    sub { down_case($t) };
	subtest 'the change that starts below the threshold' =>
	    sub { reach_case($t) };
	subtest 'the mistyped old passphrase' => sub { typo_case($t) };
	subtest 'the mistyped old passphrase of a resume' =>
	    sub { resume_typo_case($t) };
	subtest 'the damaged slot file'       => sub { damage_case($t) };
	subtest 'the pool refill'             => sub { refill_case($t) };
	subtest 'the refill with the change marker' =>
	    sub { pending_case($t) };
	return;
};
