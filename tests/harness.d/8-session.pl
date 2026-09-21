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

# The session leg (PROG-REPL, PROG-ONESHOT, ORC-QUORUM, ORC-CANARY,
# ENTRY-POOL, ENTRY-ROTATION, ENTRY-SHADOW, TEST-HARNESS-5).
#
# The leg runs the six commands and the canary subcommand against
# two topologies: one oracle with a threshold of one, and the
# example topology of three oracles with a threshold of two
# (TEST-HARNESS-5). The quorum part below runs against the second
# one alone, because a two-oracle quorum needs three oracles.
#
# Every command of the core process reads the passphrase from
# /dev/tty, so each one runs on the console of the guest
# (TEST-HARNESS-8, SEC-MEMORY-4). One console session carries the
# steps of one batch, and the counters file after each step states
# the requests of that step (ORC-COUNTER-2). A record of an entry
# that takes no request therefore keeps its counter, and that is the
# measure of "no entry request" below.
#
# A secret prints to the terminal, so the console text of a step
# carries it and the standard output of the step carries none
# (PROG-OUTPUT-1, PROG-OUTPUT-4). terminal() gives the lines of the
# terminal without the prompts.

use v5.36;

use Digest::SHA qw(hmac_sha1);
use POSIX       qw(strftime);

# The two topologies of this leg. The first one is the daily vault
# of one oracle, and the second one is the documented example
# (TEST-HARNESS-5, ORC-QUORUM-7).
my @TOPOLOGY = (
	{ tag => 'one', name => 'one oracle',   oracles => 1, threshold => 1 },
	{ tag => 'two', name => 'two of three', oracles => 3, threshold => 2 }
);

# The slots of the two vaults of one topology. The entry vault takes
# six entries, and the pool vault crosses the low watermark of 8 and
# then empties (ENTRY-POOL-6, ENTRY-POOL-7).
my $ENTRY_POOL = 8;
my $WATER_POOL = 12;

# The stale date of the shadow audit, and the age that the config of
# a creation holds (ENTRY-SHADOW-6).
my $STALE_DATE = '2020-01-01';

# The greatest counter of a record (ORC-COUNTER-5). The client sends
# the stored value plus one at least, so a record of this value in
# the counters file takes no later request.
my $MAX_COUNTER = 4_294_967_295;

# terminal($run):
#	The lines that one step wrote to the terminal, without the
#	prompts of it (PROG-OUTPUT-1). A secret takes one line, and a
#	step that writes no secret gives the empty list.
sub terminal ($run)
{
	return grep {
		length
		    && !/\A(?:Passphrase|Passphrase again|Secret): \z/
	}
	    map { s/\r//gr } split /\n/, $run->{console} // '';
}

# entry_counters($run):
#	The counters of the entry records after one step, by record
#	name (ORC-COUNTER-2). The canary records of the unlock stay
#	out, so two steps that reveal the same entries give the same
#	hash.
sub entry_counters ($run)
{
	my %counter = %{ $run->{counters} };
	delete $counter{$_} for grep { /\Acanary-/ } keys %counter;
	return \%counter;
}

# hotp($key, $step):
#	The six-digit code of the counter $step under the key $key
#	(RFC 4226, RFC 6238). This is an implementation of its own,
#	so it proves the code of the core process.
sub hotp ( $key, $step )
{
	my $mac    = hmac_sha1( pack( 'N2', $step >> 32, $step & 0xFFFFFFFF ),
		$key );
	my $offset = ord( substr $mac, -1 ) & 0x0F;
	my $value  = unpack( 'N', substr $mac, $offset, 4 ) & 0x7FFFFFFF;
	return sprintf '%06u', $value % 1_000_000;
}

# codes($run):
#	Every code that the clock of one step allows (RFC 6238). The
#	step of a code is the guest time divided by the period, and
#	the step holds two times: one before the command and one
#	after it.
sub codes ( $t, $run )
{
	my ( $from, $to ) = @{ $run->{clock} };
	return map { hotp( pack( 'H*', $t->answer('totp_key') ), $_ ) }
	    int( $from / 30 ) .. int( $to / 30 );
}

# entry_case($t, $topology):
#	The six commands and the canary subcommand of one topology.
sub entry_case ( $t, $topology )
{
	my $secret = $t->answer('secret');
	my $vault  = $t->ceremony_vault(
		"s-$topology->{tag}",
		oracles   => $topology->{oracles},
		threshold => $topology->{threshold},
		pool      => $ENTRY_POOL );

	my $made = $t->create($vault);
	is( $made->{exit}, 0, 'the creation of the session vault passes' )
	    or diag( $made->{error} );

	#
	# The unlock of a new vault (PROG-REPL-1).
	#
	my ($empty) = $t->console( $vault,
		{ argv => ['ls'], answers => ['right'] } );

	is( $empty->{exit}, 0, 'ls passes on a new vault' )
	    or diag( $empty->{error} );
	is( $empty->{out}, '', 'ls lists no entry of a new vault' );
	ok( $empty->{counters}{'canary-1'} > $made->{counters}{'canary-1'},
		'the unlock sends one canary request (ORC-CANARY-1)' );

	#
	# The consumption of gen and of add (ENTRY-POOL-3,
	# ENTRY-POOL-4, PROG-ONESHOT-8).
	#
	my ( $gen, $list, $add, $show, $derived ) = $t->console(
		$vault,
		{ argv => [ 'gen', '-T', 'password', 'g1' ],
			answers => ['right'] },
		{ argv    => ['ls'], answers => ['right'] },
		{
			argv => [
				'add', '-T', 'password', '-f',
				'username=u1', 'a1'
			],
			answers => [ 'right', 'secret' ] },
		{ argv => [ 'show', 'a1' ], answers => ['right'] },
		{ argv => [ 'show', 'g1' ], answers => ['right'] } );

	is( $gen->{exit}, 0, 'gen writes one derived entry' )
	    or diag( $gen->{error} );
	is( $add->{exit}, 0, 'add writes one stored entry' )
	    or diag( $add->{error} );
	is( $list->{out}, "g1\n", 'ls lists the entry of the open index' );
	is_deeply( entry_counters($list), entry_counters($gen),
		'ls sends no entry request (PROG-REPL-3)' );

	like( $derived->{out}, qr/^slots: 0$/m,
		'gen consumed the lowest free slot (ENTRY-POOL-3)' );
	like( $show->{out}, qr/^slots: 1$/m,
		'add consumed the next free slot (ENTRY-POOL-3)' );
	like( $show->{out}, qr/^username: u1$/m,
		'show prints the metadata of the entry (PROG-ONESHOT-9)' );
	like( $show->{out}, qr/^type: password$/m,
		'the entry file holds the type of the index (ENTRY-TYPES-1)' );
	unlike( $show->{out}, qr/\Q$secret\E/,
		'the standard output of show holds no secret '
		    . '(PROG-OUTPUT-4)' );
	is_deeply( [ terminal($show) ], [$secret],
		'show reveals the secret on the terminal (ORC-QUORUM-4, '
		    . 'PROG-OUTPUT-1)' );
	is( scalar( terminal($list) ),
		0, 'ls writes no secret to the terminal' );

	#
	# The rotation of a derived entry (ENTRY-ROTATION-1).
	#
	my ( $typo, $rotate, $after ) = $t->console(
		$vault,
		{ argv => [ 'show', 'a1' ], answers => ['wrong'] },
		{ argv => [ 'gen', '-T', 'password', 'g1' ],
			answers => ['right'] },
		{ argv => [ 'show', 'g1' ], answers => ['right'] } );

	isnt( $typo->{exit}, 0, 'a wrong passphrase opens no session' );
	like( $typo->{error}, qr/the canary of oracle 1 .* the check fails/,
		'the report names the canary of the first oracle' );
	like( $typo->{error}, qr/the cause is the passphrase/,
		'the report of the first canary holds the typo case '
		    . '(ORC-CANARY-4)' );
	like( $typo->{error},
		qr/the session sends no entry request to oracle 1/,
		'the report states that no entry record takes a request' );
	is_deeply( entry_counters($typo), entry_counters($derived),
		'a wrong passphrase sends no entry request (ORC-CANARY-1)' );
	is( scalar( terminal($typo) ),
		0, 'the stopped session writes no secret to the terminal' );
	if ( $topology->{oracles} > 1 ) {
		is( $typo->{counters}{'canary-2'},
			$derived->{counters}{'canary-2'},
			'the check stops at the first canary, and the second '
			    . 'oracle takes no request (ORC-CANARY-4)' );
	}

	is( $rotate->{exit}, 0, 'gen rotates the entry of that name' )
	    or diag( $rotate->{error} );
	like( $after->{out}, qr/^slots: 0,2$/m,
		'the rotation consumed a new slot, and it extends the slot '
		    . 'list (ENTRY-ROTATION-1, ENTRY-ROTATION-2)' );
	like( $after->{out}, qr/^version: 2$/m,
		'the rotation increments the version (ENTRY-ROTATION-1)' );
	isnt( ( terminal($after) )[0],
		( terminal($derived) )[0],
		'the new version holds the candidate of the new slot '
		    . '(KEY-BIP85-6)' );

	#
	# The rotation of a stored entry (ENTRY-ROTATION-4,
	# ENTRY-ROTATION-5). The index line of the entry holds the
	# slot list, the type and the entry file name, and each
	# write of the index seals it again (VAULT-INDEX-2). The
	# index file of this rotation therefore stays byte for byte.
	#
	my $second = $t->answer('secret2');
	my $index  = $t->digest("$vault->{dir}/index");
	my ( $reseal, $stored ) = $t->console(
		$vault,
		{ argv => [ 'add', 'a1' ], answers => [ 'right', 'secret2' ] },
		{ argv => [ 'show', 'a1' ], answers => ['right'] } );

	is( $reseal->{exit}, 0,
		'add rotates the stored entry of that name '
		    . '(ENTRY-ROTATION-5)' )
	    or diag( $reseal->{error} );
	is( $t->digest("$vault->{dir}/index"),
		$index, 'the rotation of add writes no index, so the file '
		    . 'name and the slot list of the entry stay '
		    . '(ENTRY-ROTATION-4)' );
	like( $stored->{out}, qr/^slots: 1$/m,
		'the rotation of add keeps the slot of the entry '
		    . '(ENTRY-ROTATION-4)' );
	like( $stored->{out}, qr/^version: 1$/m,
		'the rotation of add keeps the version (ENTRY-ROTATION-1)' );
	like( $stored->{out}, qr/^username: u1$/m,
		'the rotation of add carries the metadata of the old '
		    . 'version into the new file (ENTRY-ROTATION-5)' );
	is_deeply( [ terminal($stored) ], [$second],
		'the rotation of add seals the new secret in the slot of '
		    . 'the entry (ENTRY-ROTATION-4)' );

	#
	# A secret read that fails, on the same rotation. The read
	# comes before the reveal of the old entry, so the entry
	# records of that slot take no request (SEC-MEMORY-4,
	# SEC-MEMORY-6). An empty line is a failed read.
	#
	my ($void) = $t->console( $vault,
		{ argv => [ 'add', 'a1' ], answers => [ 'right', 'none' ] } );

	isnt( $void->{exit}, 0,
		'an empty secret stops the rotation of add' );
	like( $void->{error}, qr/the secret: the read fails/,
		'the report names the read of the secret' );
	is_deeply( entry_counters($void), entry_counters($stored),
		'the failed read of the secret leaves the records of the '
		    . 'slot untouched (SEC-MEMORY-6)' );

	#
	# The totp code and the shadow audit (ENTRY-TYPES-3,
	# ENTRY-SHADOW-4, ENTRY-SHADOW-5).
	#
	my $fresh = strftime( '%Y-%m-%d', gmtime $made->{clock}[0] );
	my ( $addtotp, $code, $stale, $recent, $audit ) = $t->console(
		$vault,
		{ argv => [ 'add', '-T', 'totp', 't1' ],
			answers => [ 'right', 'totp_key' ] },
		{ argv => [ 'totp', 't1' ], answers => ['right'] },
		{
			argv => [
				'add', '-T', 'shadow', '-c', 'shadow',
				'-f', 'location=a bank box',
				'-f', "verified=$STALE_DATE", 'old'
			],
			answers => ['right'] },
		{
			argv => [
				'add', '-T', 'shadow', '-c', 'shadow',
				'-f', "verified=$fresh", 'new'
			],
			answers => ['right'] },
		{ argv => ['audit'], answers => ['right'] } );

	is( $addtotp->{exit}, 0, 'add writes the totp entry' )
	    or diag( $addtotp->{error} );
	is( $stale->{exit},  0, 'add writes the stale shadow entry' );
	is( $recent->{exit}, 0, 'add writes the fresh shadow entry' );

	my @want = codes( $t, $code );
	my ($got) = terminal($code);
	ok( ( grep { $_ eq ( $got // '' ) } @want ),
		'totp prints the code of the RFC 6238 vector '
		    . '(ENTRY-TYPES-3)' )
	    or diag("the terminal gave $got, and the clock allows @want");

	is( $audit->{exit}, 0, 'audit passes' ) or diag( $audit->{error} );
	like( $audit->{out}, qr/^\Q$STALE_DATE\E old$/m,
		'audit lists the shadow entry of the old date '
		    . '(ENTRY-SHADOW-4)' );
	unlike( $audit->{out}, qr/^\S+ new$/m,
		'audit skips the shadow entry of the fresh date '
		    . '(ENTRY-SHADOW-4)' );
	ok( $audit->{counters}{'4-1'} > $recent->{counters}{'4-1'},
		'audit reveals the shadow entry of slot 4' );
	is( $audit->{counters}{'0-1'},
		$recent->{counters}{'0-1'},
		'audit sends no request for an entry of another type '
		    . '(ENTRY-SHADOW-5)' );

	#
	# The canary re-enrollment, and the heal of the index wrap
	# (ORC-CANARY-5, ORC-CANARY-8, ORC-CANARY-11).
	#
	my $wrap = $t->digest( $t->index_wrap($vault) );
	my $seal = $t->digest( $t->seal($vault) );
	my ( $canary, $healed ) = $t->console(
		$vault,
		{ argv => [ 'canary', 1 ], answers => [ 'right', 'right' ] },
		{ argv => ['ls'], answers => ['right'] } );

	is( $canary->{exit}, 0, 'the canary subcommand re-enrolls the '
		    . 'record (ORC-CANARY-5)' )
	    or diag( $canary->{error} );
	isnt( $t->digest( $t->seal($vault) ),
		$seal, 'the re-enrollment seals the fresh check value '
		    . '(ORC-CANARY-11)' );
	isnt( $t->digest( $t->index_wrap($vault) ),
		$wrap, 'the session re-wrapped the index share under the '
		    . 'fresh canary mask (ORC-CANARY-8)' );
	is( $healed->{exit}, 0,
		'the next session opens the index through the fresh wrap '
		    . '(ORC-CANARY-8)' )
	    or diag( $healed->{error} );
	like( $healed->{out}, qr/^g1$/m,
		'the healed index still resolves the entry names' );

	#
	# Fewer than k reachable oracles (ORC-QUORUM-6).
	#
	my $down = $topology->{oracles} - $topology->{threshold} + 1;
	$t->stop_oracle($_) for 1 .. $down;
	my ($few) = $t->console( $vault,
		{ argv => [ 'show', 'a1' ], answers => ['right'] } );
	$t->start_oracle($_) for 1 .. $down;

	isnt( $few->{exit}, 0, "$down stopped oracles refuse the reveal "
		    . '(ORC-QUORUM-6)' );
	like( $few->{error},
		qr/the quorum takes $topology->{threshold} reachable oracles/,
		'the refusal names the threshold' );
	like( $few->{error}, qr/the session performs no reveal/,
		'the refusal states that no reveal ran (ORC-QUORUM-6)' );
	for my $oracle ( 1 .. $topology->{oracles} ) {
		my $url = $t->url($oracle);
		like( $few->{error}, qr/^\S+ oracle $oracle \(\Q$url\E\): \S/m,
			"the refusal names the state of oracle $oracle "
			    . '(ORC-QUORUM-6)' );
	}
	is( scalar( terminal($few) ),
		0, 'the refusal writes no secret to the terminal' );

	#
	# The canary re-enrollment of a session without K_idx
	# (ORC-CANARY-8).
	#
	$t->remove_file( $t->index_wrap( $vault, oracle => $_ ) )
	    for 1 .. $down;
	my ( $dead, $closed ) = $t->console(
		$vault,
		{ argv => [ 'canary', 1 ], answers => [ 'right', 'right' ] },
		{ argv => ['ls'], answers => ['right'] } );

	is( $dead->{exit}, 0, 'the canary subcommand passes without the '
		    . 'index key' )
	    or diag( $dead->{error} );
	unlike( $dead->{error}, qr/the index wrap of oracle 1 is gone/,
		'the enrollment of an absent index wrap reports no removal '
		    . '(ORC-CANARY-8)' );
	is( $t->file_exists( $t->index_wrap($vault) ),
		0, 'the dead index wrap of that oracle stays absent '
		    . '(ORC-CANARY-8)' );
	isnt( $closed->{exit}, 0,
		'the session resolves no entry name without the index' );
	like( $closed->{error}, qr/stays closed/,
		'the report names the closed index (ORC-CANARY-8)' );

	#
	# An oracle outside that set keeps a live index wrap. The
	# enrollment of it kills that wrap, and the session holds no
	# index key, so the wrap file goes (ORC-CANARY-8).
	#
	if ( $topology->{oracles} > $down ) {
		my $last = $topology->{oracles};
		my $wrap = $t->index_wrap( $vault, oracle => $last );
		my ($kill) = $t->console( $vault,
			{ argv => [ 'canary', $last ],
				answers => [ 'right', 'right' ] } );

		is( $kill->{exit}, 0,
			'the canary subcommand of that oracle passes '
			    . '(ORC-CANARY-5)' )
		    or diag( $kill->{error} );
		like( $kill->{error},
			qr/the index wrap of oracle $last is gone/,
			'the report names the index wrap that the '
			    . 'enrollment killed (ORC-CANARY-8)' );
		is( $t->file_exists($wrap),
			0, 'the enrollment removed the live index wrap '
			    . '(ORC-CANARY-8)' );
	}

	return;
}

# pool_case($t, $topology):
#	The low watermark and the exhaustion of the pool
#	(ENTRY-POOL-6, ENTRY-POOL-7).
sub pool_case ( $t, $topology )
{
	my $vault = $t->ceremony_vault(
		"p-$topology->{tag}",
		oracles   => $topology->{oracles},
		threshold => $topology->{threshold},
		pool      => $WATER_POOL );

	my $made = $t->create($vault);
	is( $made->{exit}, 0, 'the creation of the pool vault passes' )
	    or diag( $made->{error} );

	# One entry of each slot of the pool, and one more. The names
	# differ, so each command consumes a slot and rotates nothing.
	my @run = $t->console(
		$vault,
		map { {
			argv    => [ 'gen', '-T', 'password', "e$_" ],
			answers => ['right'] } } 1 .. $WATER_POOL + 1 );

	is( scalar( grep { $_->{exit} == 0 } @run[ 0 .. $WATER_POOL - 1 ] ),
		$WATER_POOL,
		"the pool of $WATER_POOL slots takes $WATER_POOL entries" )
	    or diag( join '', map { $_->{error} } @run );

	# The watermark is 8, so the first three consumptions leave 11,
	# 10 and 9 free slots, and they warn about none of them.
	for my $i ( 0 .. 2 ) {
		unlike( $run[$i]{error}, qr/watermark/,
			'the consumption above the watermark gives no '
			    . 'warning (ENTRY-POOL-6)' );
	}
	like( $run[3]{error},
		qr/the pool holds 8 free slots, at the low watermark of 8/,
		'the pool warns at the low watermark (ENTRY-POOL-6)' );
	like( $run[3]{error}, qr/the refill ceremony adds slots to the pool/,
		'the warning names the refill ceremony (ENTRY-POOL-6)' );

	isnt( $run[$WATER_POOL]{exit}, 0,
		'the empty pool refuses a new entry (ENTRY-POOL-7)' );
	like( $run[$WATER_POOL]{error}, qr/holds no free slot/,
		'the refusal names the empty pool (ENTRY-POOL-7)' );
	like( $run[$WATER_POOL]{error},
		qr/the refill ceremony adds slots to the pool/,
		'the refusal names the refill ceremony (ENTRY-POOL-7)' );

	return;
}

# quorum_case($t):
#	The reveal on every two-oracle quorum of the example
#	topology, the decrypt failure with one mask, the
#	substitution after a decrypt failure and after a failed
#	request, and the two reveals of one session (TEST-HARNESS-5,
#	ORC-QUORUM-4, ORC-QUORUM-5).
sub quorum_case ($t)
{
	my $secret = $t->answer('secret2');
	my $vault  = $t->ceremony_vault( 'q', oracles => 3, threshold => 2,
		pool => 4 );

	my $made = $t->create($vault);
	is( $made->{exit}, 0, 'the creation of the quorum vault passes' )
	    or diag( $made->{error} );

	my ( $add, $derived ) = $t->console(
		$vault,
		{ argv => [ 'add', '-T', 'password', 'q1' ],
			answers => [ 'right', 'secret2' ] },
		{ argv => [ 'gen', '-T', 'password', 'g1' ],
			answers => ['right'] } );
	is( $add->{exit}, 0, 'add writes the entry of the quorum vault' )
	    or diag( $add->{error} );
	is( $derived->{exit}, 0,
		'gen writes the derived entry of the quorum vault' )
	    or diag( $derived->{error} );

	# Every two-oracle quorum of the three (TEST-HARNESS-5). One
	# stopped oracle leaves one quorum, so the session selects it
	# from the reachable oracles (ORC-QUORUM-2).
	for my $stopped ( 1 .. 3 ) {
		$t->stop_oracle($stopped);
		my ($show) = $t->console( $vault,
			{ argv => [ 'show', 'q1' ], answers => ['right'] } );
		$t->start_oracle($stopped);

		my @quorum = grep { $_ != $stopped } 1 .. 3;
		is( $show->{exit}, 0,
			"the quorum of oracle $quorum[0] and oracle "
			    . "$quorum[1] reveals the entry" )
		    or diag( $show->{error} );
		is_deeply( [ terminal($show) ], [$secret],
			"the quorum of oracle $quorum[0] and oracle "
			    . "$quorum[1] gives the secret (ORC-QUORUM-3)" );
	}

	# The wrap of an other slot at oracle 1. The share of that
	# oracle is then wrong, and the decrypt of two shares fails
	# (ORC-QUORUM-4).
	my $stale  = $t->wrap( $vault, slot => 0, oracle => 1 );
	my $backup = "$vault->{dir}-wrap.good";
	$t->copy_file( $stale, $backup );
	$t->copy_file( $t->wrap( $vault, slot => 1, oracle => 1 ), $stale );

	$t->stop_oracle(3);
	my ($alone) = $t->console( $vault,
		{ argv => [ 'show', 'q1' ], answers => ['right'] } );
	$t->start_oracle(3);

	isnt( $alone->{exit}, 0,
		'one good mask of two fails the decrypt (ORC-QUORUM-4)' );
	is( scalar( terminal($alone) ),
		0, 'the failed decrypt writes no secret to the terminal' );
	for my $oracle ( 1, 2 ) {
		my $url = $t->url($oracle);
		like( $alone->{error},
			qr/the attempt holds oracle $oracle \(\Q$url\E\)/,
			"the report names oracle $oracle of the attempt "
			    . '(ORC-QUORUM-5)' );
	}

	# The third oracle answers again, so the session substitutes
	# it after the decrypt failure (ORC-QUORUM-5).
	my ($substitute) = $t->console( $vault,
		{ argv => [ 'show', 'q1' ], answers => ['right'] } );
	is( $substitute->{exit}, 0,
		'the session substitutes the third oracle after the decrypt '
		    . 'failure (ORC-QUORUM-5)' )
	    or diag( $substitute->{error} );
	is_deeply( [ terminal($substitute) ], [$secret],
		'the substituted quorum reveals the entry (ORC-QUORUM-5)' );
	like( $substitute->{error}, qr/the attempt holds oracle 1 /,
		'the report of the failed attempt names its quorum '
		    . '(ORC-QUORUM-5)' );

	$t->copy_file( $backup, $stale );

	# The counters file gives the record of slot 0 at oracle 1
	# the greatest counter, so the client holds no greater value
	# of that record, and the request of it fails (ORC-COUNTER-5).
	# The canary record of that oracle keeps its counter, so the
	# failure comes at the reveal, and the session substitutes
	# the third oracle after it (ORC-QUORUM-5).
	my $record  = $t->record( $vault, slot => 0, oracle => 1 );
	my $file    = $t->counters($vault);
	my @counter = grep { !/\A\Q$record\E: / }
	    split /\n/, $t->read_file($file) // '';
	$t->write_file( $file, @counter, "$record: $MAX_COUNTER" );

	my $url = $t->url(1);
	my ($moved) = $t->console( $vault,
		{ argv => [ 'show', 'q1' ], answers => ['right'] } );

	like( $moved->{error},
		qr/slot 0 at oracle 1 \(\Q$url\E\): the request fails/,
		'the report names the failed request of the quorum oracle '
		    . '(ORC-QUORUM-5)' );
	is( $moved->{exit}, 0,
		'the session substitutes an oracle after a request that '
		    . 'fails at this machine (ORC-QUORUM-5, ORC-COUNTER-5)' )
	    or diag( $moved->{error} );
	is_deeply( [ terminal($moved) ], [$secret],
		'the quorum of the substitution reveals the entry '
		    . '(ORC-QUORUM-5)' );

	#
	# Two reveals of one session. The rotation of gen reveals
	# the slot of the old version, and it then consumes a new
	# slot. The wrap of slot 1 at oracle 1 is stale, so the
	# first reveal substitutes the third oracle and walks the
	# candidates to the end. The wrap of slot 2 at oracle 3 is
	# stale as well, so the second reveal needs a substitution
	# of its own (ORC-QUORUM-5).
	#
	my $old  = $t->wrap( $vault, slot => 1, oracle => 1 );
	my $new  = $t->wrap( $vault, slot => 2, oracle => 3 );
	my $keep = "$vault->{dir}-wrap.old";
	my $back = "$vault->{dir}-wrap.new";

	$t->copy_file( $old, $keep );
	$t->copy_file( $new, $back );
	$t->copy_file( $t->wrap( $vault, slot => 0, oracle => 1 ), $old );
	$t->copy_file( $t->wrap( $vault, slot => 0, oracle => 3 ), $new );

	my ( $twice, $rotated ) = $t->console(
		$vault,
		{ argv => [ 'gen', 'g1' ], answers => ['right'] },
		{ argv => [ 'show', 'g1' ], answers => ['right'] } );

	$t->copy_file( $keep, $old );
	$t->copy_file( $back, $new );

	is( $twice->{exit}, 0,
		'the second reveal of one session substitutes an oracle of '
		    . 'its own (ORC-QUORUM-5)' )
	    or diag( $twice->{error} );
	like( $twice->{error},
		qr/slot 1: the entry of this quorum does not open/,
		'the reveal of the old version fails the decrypt first '
		    . '(ORC-QUORUM-4)' );
	like( $twice->{error},
		qr/slot 2: the entry of this quorum does not open/,
		'the consumption of the new slot fails the decrypt too '
		    . '(ORC-QUORUM-4)' );
	like( $rotated->{out}, qr/^slots: 1,2$/m,
		'the rotation of the two reveals consumed the new slot '
		    . '(ENTRY-ROTATION-1)' );
	return;
}

return sub ($t)
{
	for my $topology (@TOPOLOGY) {
		subtest "the session of $topology->{name}" => sub {
			entry_case( $t, $topology );
		};
		subtest "the pool of $topology->{name}" => sub {
			pool_case( $t, $topology );
		};
	}
	subtest 'the quorum of three oracles' => sub { quorum_case($t) };
	return;
};
