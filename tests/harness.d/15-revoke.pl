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

# The revocation leg (ORC-REVOKE-3, ORC-REVOKE-4, ORC-REVOKE-8,
# ORC-REVOKE-10 to ORC-REVOKE-12, ORC-COUNTER-5, VAULT-INDEX-7,
# CER-PROVISION-3, CER-PROVISION-11, TEST-HARNESS-3, TEST-HARNESS-5).
#
# A stolen machine creates a vault against the example topology of
# three oracles with a threshold of two, and it adds one entry. A
# surviving machine takes a copy of the shared set and provisions.
# The revoke subcommand then runs on the surviving machine, from the
# plate, against the records of the stolen machine.
#
# One lock at oracle 3 makes the records of the stolen machine there
# answer junk to every caller, and a later set_pin of such a record
# fails with an HTTP error. The stolen machine still reveals through
# the two other oracles. A second lock at oracle 2 denies it every
# quorum: n - k + 1 locks. The surviving machine keeps revealing.
#
# The first lock takes the last position, because a session walks
# the list in order and stops at the first junk canary (ORC-CANARY-9).
# A lock at position 1 would stop every session of the stolen
# machine before the two other oracles get a request, and the leg
# would then prove the stop and not the quorum. The driver counts
# the obtainable masks, so the quorum claim rests on the records
# and not on the walk of the session.
#
# A lock retires the stolen name in the registry of the index. A
# provisioning under that name refuses, and the refusal names a new
# machine name. A later ceremony keeps the mark. The replacement
# path retires no name, and it leaves a set_pin of the record
# possible. The driver sends the lock of one record on its own,
# because TEST-HARNESS-3 pins the lock at each counterparty.
#
# Each assertion names the mutation that it catches. A state
# assertion compares the state of the moment with a state that this
# file recorded before the step, and never with a value that the
# step itself writes.

use v5.36;

# The example topology of TEST-HARNESS-5.
my $ORACLES   = 3;
my $THRESHOLD = 2;

# A small pool keeps each ceremony short, and one entry consumes one
# slot. The records of a machine at one oracle are the slots and the
# canary.
my $POOL    = 2;
my $RECORDS = $POOL + 1;

# records_of($t):
#	The record file names of each instance, by oracle index.
sub records_of ($t)
{
	return { map { $_ => [ sort $t->records($_) ] } 1 .. $ORACLES };
}

# driver_vault($vault, $slot):
#	The vault hash of the driver for one ceremony vault. The
#	driver derives the device factor from the machine name of the
#	config, so it addresses the records of that machine.
sub driver_vault ( $vault, $slot )
{
	return { dir => $vault->{dir}, slot => $slot };
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
	return $show;
}

# refuses($t, $vault, $what):
#	One reveal of a1 on the console that must fail, with no
#	secret on the terminal.
sub refuses ( $t, $vault, $what )
{
	my ($show) = $t->console( $vault,
		{ argv => [ 'show', 'a1' ], answers => ['right'] } );
	isnt( $show->{exit}, 0, "$what: the reveal fails" );
	is( scalar( $t->terminal($show) ),
		0, "$what: the failed reveal writes no secret" );
	return $show;
}

# revoke($t, $vault, @argv):
#	One run of the revoke subcommand on the console of $vault.
#	The plate scan takes the double, so the run goes over the
#	console, and the subcommand reads no passphrase, so the step
#	takes no answer (TEST-HARNESS-8).
sub revoke ( $t, $vault, @argv )
{
	my ($run) = $t->console( $vault, { argv => [ 'revoke', @argv ] } );
	return $run;
}

# locked_case($t, $stolen, $oracle, $what):
#	The driver against one locked record and the locked canary
#	of the stolen machine at $oracle (ORC-REVOKE-8,
#	TEST-HARNESS-3). Every get_pin answers junk, and every
#	set_pin answers an HTTP error. Three junk answers burn no
#	strike, so the record file stays.
#
#	The mutations: a lock at an ordinary counter leaves the
#	set_pin passing, and the enrollment then gives ok. A lock
#	that skips the canary leaves the canary enrollment passing.
sub locked_case ( $t, $stolen, $oracle, $what )
{
	my $dv = driver_vault( $stolen, 0 );
	for my $attempt ( 1 .. 3 ) {
		is( $t->reveal( $dv, oracle => $oracle )->{state},
			'junk', "$what: the get_pin $attempt of the locked "
			    . 'record answers junk (ORC-REVOKE-8)' );
	}
	is( $t->enroll( $dv, oracle => $oracle )->{state},
		'status', "$what: the set_pin of the locked record answers "
		    . 'an HTTP error (ORC-REVOKE-8, TEST-HARNESS-3)' );
	is( $t->canary( $dv, oracle => $oracle )->{state},
		'status', "$what: the set_pin of the locked canary answers "
		    . 'an HTTP error (ORC-REVOKE-8)' );
	return;
}

# driver_case($t):
#	The lock of one record through the driver, at this
#	counterparty (TEST-HARNESS-3). One wrong attempt at the
#	revocation counter, then junk on every get_pin and an HTTP
#	error on every set_pin of that record.
#
#	The mutation: a lock at an ordinary counter burns one strike
#	and locks nothing, so the later enrollment gives ok.
sub driver_case ($t)
{
	my $vault = $t->vault('revoke-driver');
	is( $t->enroll($vault)->{state}, 'ok', 'the record enrolls' );
	is( $t->reveal($vault)->{state}, 'ok', 'the record reveals' );

	my $lock = $t->lock($vault);
	is( $lock->{state}, 'ok',
		'the lock got an answer at the revocation counter '
		    . '(ORC-REVOKE-8)' )
	    or diag( $lock->{error} );
	for my $attempt ( 1 .. 3 ) {
		is( $t->reveal($vault)->{state},
			'junk', "the get_pin $attempt after the lock answers "
			    . 'junk (TEST-HARNESS-3)' );
	}
	is( $t->enroll($vault)->{state},
		'status', 'the set_pin after the lock answers an HTTP error '
		    . '(TEST-HARNESS-3)' );
	is( $t->reveal($vault)->{state},
		'junk', 'the get_pin after the failed set_pin answers junk '
		    . '(TEST-HARNESS-3)' );
	return;
}

return sub ($t)
{
	my $secret = $t->answer('secret');

	#
	# The stolen machine: a creation and one entry. The surviving
	# machine: a copy of the shared set, and a provisioning.
	#
	my $stolen = $t->ceremony_vault( 'revoke', oracles => $ORACLES,
		threshold => $THRESHOLD, pool => $POOL );
	my $made = $t->create($stolen);
	is( $made->{exit}, 0, 'the creation of the stolen machine passes' )
	    or diag( $made->{error} );
	my ($add) = $t->console( $stolen,
		{ argv => [ 'add', '-T', 'password', 'a1' ],
			answers => [ 'right', 'secret' ] } );
	is( $add->{exit}, 0, 'add writes the stored entry' )
	    or diag( $add->{error} );

	my $plate = $t->ceremony_vault( 'revoke-plate', oracles => $ORACLES,
		threshold => $THRESHOLD );
	$t->copy_shared( $stolen->{dir}, $plate->{dir} );
	my $prov = $t->provision($plate);
	is( $prov->{exit}, 0, 'the provisioning of the surviving machine '
		    . 'passes' )
	    or diag( $prov->{error} );
	reveals( $t, $plate, $secret, 'the surviving machine' );

	my $name    = $stolen->{machine};
	my $before  = records_of($t);
	my @url     = map { $t->url($_) } 1 .. $ORACLES;

	#
	# The command line of the subcommand (PROG-ONESHOT-4). Each
	# case stops before the plate scan, so each one runs over ssh
	# with no terminal.
	#
	my $bare = $t->program( '-d', $plate->{dir}, 'revoke' );
	is( $bare->{exit}, 2, 'a run without the -m option exits 2' );
	like( $bare->{error}, qr/the -m option is mandatory/,
		'a run without the -m option gives the reason' );
	my $bad = $t->program( '-d', $plate->{dir}, 'revoke', '-m', 'Machine' );
	is( $bad->{exit}, 2, 'a rejected machine name exits 2' );
	my $zero = $t->program( '-d', $plate->{dir}, 'revoke', '-m', $name, 0 );
	is( $zero->{exit}, 2, 'the position 0 exits 2' );
	like( $zero->{error}, qr/the oracle position is too small/,
		'the position 0 gives the reason' );
	my $above = $t->program( '-d', $plate->{dir}, 'revoke', '-m', $name,
		$ORACLES + 1 );
	is( $above->{exit}, 1, 'a position above the oracle set exits 1' );
	like( $above->{error},
		qr/position 4 is above the oracle set of 3 positions/,
		'a position above the oracle set gives the reason before the '
		    . 'plate scan (ORC-REVOKE-3)' );

	#
	# The replacement (ORC-REVOKE-3, ORC-REVOKE-8). The surviving
	# machine replaces its own records at oracle 3, from its own
	# plate. The record then answers junk to the old wrap, and a
	# set_pin of it still passes: the replacement locks nothing,
	# and it retires no name.
	#
	# The mutations: a replacement that sends the lock leaves the
	# set_pin failing. A replacement that writes the retired mark
	# makes the probe below refuse the name.
	#
	my $rep = revoke( $t, $plate, '-r', '-m', $plate->{machine}, 3 );
	is( $rep->{exit}, 0, 'the replacement passes (ORC-REVOKE-8)' )
	    or diag( $rep->{error} );
	like( $rep->{error},
		qr/the replacement landed on $RECORDS records of the machine \Q$plate->{machine}\E at oracle 3 \(\Q$url[2]\E\)/,
		'the report names the replacement, the record count and the '
		    . 'oracle (ORC-REVOKE-12)' );
	unlike( $rep->{error}, qr/retired/,
		'the replacement retires no name (ORC-REVOKE-11)' );
	is_deeply( records_of($t), $before,
		'the replacement removed no record file and added none '
		    . '(ORC-REVOKE-8)' );
	my $pv = driver_vault( $plate, 0 );
	is( $t->reveal( $pv, oracle => 3 )->{state},
		'junk', 'the old wrap of a replaced record unmasks junk '
		    . '(ORC-REVOKE-8)' );
	is( $t->enroll( $pv, oracle => 3 )->{state},
		'ok', 'a set_pin of a replaced record passes: the replacement '
		    . 'locks nothing (ORC-REVOKE-8)' );

	my $probe = $t->ceremony_vault( 'revoke-probe', oracles => $ORACLES,
		threshold => $THRESHOLD );
	$t->copy_shared( $plate->{dir}, $probe->{dir} );
	my $kept = $t->provision( $probe, machine => $plate->{machine},
		answers => [ 'no', 'none' ] );
	is( $kept->{exit}, 1,
		'a provisioning under the replaced name stops at the '
		    . 'confirmation (CER-PROVISION-3)' );
	like( $kept->{error},
		qr/the registry of the index holds the machine \Q$plate->{machine}\E/,
		'the registry holds the replaced name without a mark '
		    . '(ORC-REVOKE-11)' );
	unlike( $kept->{error}, qr/retired/,
		'the replaced name is not retired (ORC-REVOKE-11)' );

	#
	# The lock at oracle 3 (ORC-REVOKE-8, ORC-REVOKE-11,
	# ORC-REVOKE-12).
	#
	# The mutations: a lock at an ordinary counter locks nothing,
	# and the driver then enrolls the record. A lock that writes
	# the counters file of this machine moves that file. A report
	# without the remaining oracles, the count or the passphrase
	# change fails the text assertions.
	#
	my $counters = $t->read_file( $t->counters($plate) );
	my $lock1    = revoke( $t, $plate, '-m', $name, 3 );
	is( $lock1->{exit}, 0, 'the lock at oracle 3 passes (ORC-REVOKE-8)' )
	    or diag( $lock1->{error} );
	like( $lock1->{error},
		qr/the lock landed on $RECORDS records of the machine \Q$name\E at oracle 3 \(\Q$url[2]\E\)/,
		'the report names the lock, the record count and the oracle '
		    . '(ORC-REVOKE-12)' );
	like( $lock1->{error},
		qr/the machine \Q$name\E is retired, and the registry of the index marks it/,
		'the report states the retirement (ORC-REVOKE-11)' );
	like( $lock1->{error}, qr/provisions under a new name/,
		'the report names a new machine name as the path '
		    . '(ORC-REVOKE-11)' );
	for my $oracle ( 1, 2 ) {
		my $url = $url[ $oracle - 1 ];
		like( $lock1->{error},
			qr/the records of the machine \Q$name\E remain at oracle $oracle \(\Q$url\E\)/,
			"the report names oracle $oracle, which got no lock "
			    . '(ORC-REVOKE-12)' );
	}
	unlike( $lock1->{error}, qr/remain at oracle 3 /,
		'the report names the locked oracle as no remaining one' );
	like( $lock1->{error}, qr/"fugupass kit -m \Q$name\E" names each record/,
		'the report names the kit for the remaining records '
		    . '(ORC-REVOKE-12)' );
	like( $lock1->{error},
		qr/a quorum takes $THRESHOLD of the $ORACLES live oracles, so the lock at 2 of them denies it/,
		'the report states the n - k + 1 count (ORC-REVOKE-10)' );
	like( $lock1->{error},
		qr/change the passphrase on every other machine when the passphrase may be known: "fugupass passwd"/,
		'the report directs the owner to the passphrase change '
		    . '(ORC-REVOKE-12)' );
	is_deeply( records_of($t), $before,
		'the lock removed no record file and added none: a locked '
		    . 'record keeps its file (ORC-REVOKE-8)' );
	is( $t->read_file( $t->counters($plate) ),
		$counters, 'the lock wrote no counter of another machine into '
		    . 'the counters file of this machine (ORC-COUNTER-2)' );

	locked_case( $t, $stolen, 3, 'after the lock at oracle 3' );
	is_deeply( records_of($t), $before,
		'three junk answers burned no strike: the record file stays '
		    . '(ORC-COUNTER-6)' );

	# One lock leaves a quorum: the masks of oracles 1 and 2 stay
	# obtainable, and the session reveals through them
	# (ORC-REVOKE-10). With oracle 1 stopped, the walk reaches the
	# locked oracle 3 after a pass at oracle 2, and the junk
	# answer of the canary stops the reveal: the lock answers junk
	# to the stolen machine as to every caller (ORC-REVOKE-8).
	my $sv = driver_vault( $stolen, 0 );
	is_deeply(
		[ map { $t->reveal( $sv, oracle => $_ )->{state} } 1 .. 3 ],
		[ 'ok', 'ok', 'junk' ],
		'one lock leaves the masks of two oracles obtainable: a quorum '
		    . 'of two (ORC-REVOKE-10)' );
	reveals( $t, $stolen, $secret,
		'one lock leaves a reveal through the other two oracles '
		    . '(ORC-REVOKE-10)' );
	$t->stop_oracle(1);
	my $through = refuses( $t, $stolen,
		'a reveal through the locked oracle 3' );
	$t->start_oracle(1);
	like( $through->{error},
		qr/the canary of oracle 3 \(\Q$url[2]\E\): the check fails/,
		'the stolen machine gets junk from its canary at oracle 3 '
		    . '(ORC-REVOKE-8)' );
	like( $through->{error},
		qr/the passphrase passed at oracle 2, so the cause sits at oracle 3/,
		'the report puts the cause at the locked oracle (ORC-CANARY-9)' );

	#
	# The lock at oracle 2: n - k + 1 locks deny a quorum
	# (ORC-REVOKE-10). One mask per entry stays obtainable, below
	# the threshold of two. The surviving machine keeps revealing
	# (CER-PROVISION-11).
	#
	# The mutation: a lock that reaches the slots and not the
	# canary leaves the canary of oracle 2 passing, and the reveal
	# then works through oracles 1 and 2.
	#
	my $lock2 = revoke( $t, $plate, '-m', $name, 2 );
	is( $lock2->{exit}, 0, 'the lock at oracle 2 passes' )
	    or diag( $lock2->{error} );
	like( $lock2->{error},
		qr/the lock landed on $RECORDS records of the machine \Q$name\E at oracle 2 \(\Q$url[1]\E\)/,
		'the report names the lock at oracle 2 (ORC-REVOKE-12)' );
	for my $oracle ( 1, 3 ) {
		my $url = $url[ $oracle - 1 ];
		like( $lock2->{error},
			qr/remain at oracle $oracle \(\Q$url\E\)/,
			"the report names oracle $oracle, which got no lock in "
			    . 'this run (ORC-REVOKE-12)' );
	}
	locked_case( $t, $stolen, 2, 'after the lock at oracle 2' );

	is_deeply(
		[ map { $t->reveal( $sv, oracle => $_ )->{state} } 1 .. 3 ],
		[ 'ok', 'junk', 'junk' ],
		"locks at $THRESHOLD oracles leave one obtainable mask per "
		    . 'entry, below the threshold (ORC-REVOKE-10)' );
	my $denied = refuses( $t, $stolen,
		"locks at $THRESHOLD oracles deny the stolen machine a quorum "
		    . '(ORC-REVOKE-10)' );
	like( $denied->{error},
		qr/the canary of oracle 2 \(\Q$url[1]\E\): the check fails/,
		'the walk of the session stops at the locked oracle 2 '
		    . '(ORC-REVOKE-8)' );
	like( $denied->{error},
		qr/the passphrase passed at oracle 1, so the cause sits at oracle 2/,
		'the report puts the cause at the locked oracle (ORC-CANARY-9)' );
	reveals( $t, $plate, $secret,
		'the surviving machine reveals after the locks '
		    . '(CER-PROVISION-11)' );

	#
	# The retired mark (ORC-REVOKE-11, VAULT-INDEX-7,
	# CER-PROVISION-3). A fresh directory takes a copy of the
	# shared set of the surviving machine, and a provisioning
	# under the stolen name refuses there. A run under the name
	# of the surviving machine reads the confirmation, so the mark
	# hits the stolen name alone. A later ceremony keeps the mark.
	#
	# The mutations: a lock that writes no mark, and a ceremony
	# that drops the retired refusal, each make the run read the
	# confirmation in place of the refusal. The two answers guard
	# the console: such a run reads them as the two passphrases,
	# and the empty second one fails the read.
	#
	my $probe2 = $t->ceremony_vault( 'revoke-probe2', oracles => $ORACLES,
		threshold => $THRESHOLD );
	$t->copy_shared( $plate->{dir}, $probe2->{dir} );
	my $retired = $t->provision( $probe2, machine => $name,
		answers => [ 'none', 'none' ] );
	is( $retired->{exit}, 1,
		'a provisioning under the retired name refuses '
		    . '(CER-PROVISION-3)' );
	like( $retired->{error},
		qr/the registry of the index marks the machine \Q$name\E retired/,
		'the refusal names the retired mark of the registry '
		    . '(ORC-REVOKE-11, VAULT-INDEX-7)' );
	like( $retired->{error}, qr/give a new machine name/,
		'the refusal names a new machine name as the path '
		    . '(CER-PROVISION-3)' );
	is( $t->file_exists("$probe2->{dir}/machine/config"),
		0, 'the refused run wrote no config (CER-PROVISION-3)' );
	is( $t->file_exists("$probe2->{dir}/machine/factor"),
		0, 'the refused run wrote no device factor (CER-PROVISION-3)' );

	my $other = $t->provision( $probe2, machine => $plate->{machine},
		answers => [ 'no', 'none' ] );
	is( $other->{exit}, 1,
		'a run under the surviving name stops at the confirmation' );
	like( $other->{error},
		qr/the registry of the index holds the machine \Q$plate->{machine}\E/,
		'the mark hits the stolen name alone (VAULT-INDEX-7)' );

	my $later = $t->provision($probe2);
	is( $later->{exit}, 0,
		'a provisioning under a new name passes after the lock '
		    . '(ORC-REVOKE-11)' )
	    or diag( $later->{error} );
	my $probe3 = $t->ceremony_vault( 'revoke-probe3', oracles => $ORACLES,
		threshold => $THRESHOLD );
	$t->copy_shared( $probe2->{dir}, $probe3->{dir} );
	my $still = $t->provision( $probe3, machine => $name,
		answers => [ 'none', 'none' ] );
	is( $still->{exit}, 1,
		'the mark survives a later ceremony (VAULT-INDEX-7)' );
	like( $still->{error},
		qr/marks the machine \Q$name\E retired/,
		'the later index still marks the name (VAULT-INDEX-7)' );

	#
	# The default oracle set, and a retired position
	# (ORC-REVOKE-3, ORC-PROVISION-9). A copy of the surviving
	# machine retires position 3 in its config. A run without a
	# position takes every live position, a retired position gets
	# no request, and a named retired position stops the run.
	#
	# The mutation: a default of the first position alone reports
	# no lock at oracle 2.
	#
	my $copy = "$plate->{dir}-retired";
	$t->copy_dir( $plate->{dir}, $copy );
	my @config = split /\n/, $t->read_file("$copy/machine/config");
	s/\Aoracle-3: .*\z/oracle-3: retired/ for @config;
	$t->write_file( "$copy/machine/config", @config );
	my $named = $t->program( '-d', $copy, 'revoke', '-m', $name, 3 );
	is( $named->{exit}, 1, 'a named retired position stops the run' );
	like( $named->{error},
		qr/position 3 is retired, and it takes no request/,
		'a named retired position gives the reason (ORC-PROVISION-9)' );

	my $every = revoke( $t, { dir => $copy, tag => 'revoke-retired' },
		'-m', $name );
	is( $every->{exit}, 0, 'the lock of every live position passes' )
	    or diag( $every->{error} );
	for my $oracle ( 1, 2 ) {
		my $url = $url[ $oracle - 1 ];
		like( $every->{error},
			qr/the lock landed on $RECORDS records of the machine \Q$name\E at oracle $oracle \(\Q$url\E\)/,
			"the default set locks the live oracle $oracle "
			    . '(ORC-REVOKE-3)' );
	}
	like( $every->{error},
		qr/position 3 is retired, and no request goes there/,
		'the report states that the retired position got no request '
		    . '(ORC-PROVISION-9)' );
	like( $every->{error},
		qr/the records of the machine \Q$name\E remain at the retired position 3/,
		'the report names the retired position as a remaining one '
		    . '(ORC-REVOKE-12)' );
	unlike( $every->{error}, qr/remain at oracle/,
		'the report names no live oracle as a remaining one' );
	like( $every->{error},
		qr/a quorum takes $THRESHOLD of the 2 live oracles, so the lock at 1 of them denies it/,
		'the count of the quorum denial counts the live positions '
		    . '(ORC-REVOKE-10)' );

	subtest 'the lock through the driver' => sub { driver_case($t) };
	return;
};
