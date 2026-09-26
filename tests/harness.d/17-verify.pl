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

# The plate verification leg (CER-VERIFY, PROG-REPL-6,
# REC-PRINCIPLE-4).
#
# A creation writes the plate check value of the fixed test master
# into the config file of the machine (KEY-MASTER-5). The
# verification then reads the plate and the config alone, so the
# harness stops every counterparty for the match and for the
# rejection (CER-VERIFY-2, PROG-REPL-6). The audit opens a session,
# so the two audits of this leg run against a live counterparty
# (CER-VERIFY-3).
#
# The scan double prints one fixed test master, so the harness holds
# no second plate (TEST-KAT-4). The rejection therefore gives the
# config file a plate check value that the test master does not
# derive: the leg replaces the first digit of the plate-check line.
# A verification that skips the compare accepts that config, so the
# mutation of the compare proves the way.
#
# A verification reads no passphrase and prints no secret, and the
# harness drives it over the console all the same (TEST-HARNESS-8).
# A run over the ssh channel of fuguvm would stop at the first read
# of the terminal, and a mutation that reads the passphrase would
# then fail for the wrong reason.
#
# Each assertion names the mutation that it catches. The index is a
# sealed file, so a change of it shows in the digest of the file,
# and the date of it shows in the audit alone.

use v5.36;

# The example topology of TEST-HARNESS-5. The leg takes one
# instance for each position, and the harness reads that count at
# the load.
my $ORACLES   = 3;
my $THRESHOLD = 2;
our $INSTANCES = $ORACLES;

# The slots of the creation. A small pool keeps the leg short.
my $POOL = 2;

# date_of($seconds):
#	The date of the line format of one guest clock read, in UTC
#	(VAULT-FORMAT-7). The verification records the day of the
#	guest, and the clock of a console step gives it.
sub date_of ($seconds)
{
	my @tm = gmtime( int $seconds );
	return sprintf '%04d-%02d-%02d', $tm[5] + 1900, $tm[4] + 1, $tm[3];
}

return sub ($t)
{
	my $vault = $t->ceremony_vault( 'verify', oracles => $ORACLES,
		threshold => $THRESHOLD, pool => $POOL );
	my $made = $t->create($vault);
	is( $made->{exit}, 0, 'the creation passes' ) or diag( $made->{error} );
	my @config = split /\n/, $t->read_file("$vault->{dir}/machine/config");
	my $index = "$vault->{dir}/index";

	#
	# A new vault holds no verification date (CER-VERIFY-3). The
	# audit prints no verified line, and it reports the absent
	# date.
	#
	# The mutation: a creation that writes a date line into the
	# index prints a verified line here.
	#
	my ($before) = $t->console( $vault,
		{ argv => ['audit'], answers => ['right'] } );
	is( $before->{exit}, 0, 'the audit of a new vault passes' )
	    or diag( $before->{error} );
	unlike( $before->{out}, qr/^verified: /m,
		'the audit of a new vault prints no verification date '
		    . '(CER-VERIFY-3)' );
	like( $before->{error}, qr/no date of a plate verification/,
		'the audit of a new vault reports the absent date '
		    . '(CER-VERIFY-3)' );
	my $counters = $t->read_file( $t->counters($vault) );
	my $digest   = $t->digest($index);

	#
	# The match, with every counterparty stopped (CER-VERIFY-1,
	# CER-VERIFY-2, CER-VERIFY-5, PROG-REPL-6). The verification
	# reads the plate and the config, it prints no secret, and it
	# records the date in the index.
	#
	# The mutations: a verification that opens a session reads the
	# answer as the passphrase, reaches the stopped oracle, fails,
	# and moves the counters file. A verification that prints root
	# on the terminal leaves a terminal line. A verification that
	# writes no date leaves the digest of the index as it was.
	#
	$t->stop;
	my ($match) = $t->console( $vault,
		{ argv => ['verify'], answers => ['right'] } );
	is( $match->{exit}, 0,
		'verify matches the plate of the vault with every counterparty '
		    . 'stopped (CER-VERIFY-1, PROG-REPL-6)' )
	    or diag( $match->{error} );
	is( scalar( $t->terminal($match) ), 0,
		'verify prints no secret on the terminal (CER-VERIFY-2)' );
	is( $t->read_file( $t->counters($vault) ), $counters,
		'verify sent no request: the counters file stays '
		    . '(CER-VERIFY-2, REC-PRINCIPLE-4)' );
	my $recorded = $t->digest($index);
	isnt( $recorded, $digest,
		'the match rewrote the index with the date (CER-VERIFY-5)' );

	#
	# The rejection (CER-VERIFY-1). The config file takes a plate
	# check value that the test master does not derive, and the
	# verification refuses the plate of the double. The refusal
	# names a wrong plate or a damaged plate, and it writes no
	# date.
	#
	# The mutations: a verification that skips the compare exits 0
	# here, and one with another report names no plate. A
	# verification that records the date before the compare
	# changes the digest of the index.
	#
	my @other = map {
		s/\A(plate-check: )([0-9a-f])/$1 . ( $2 eq '0' ? '1' : '0' )/er
	} @config;
	$t->write_file( "$vault->{dir}/machine/config", @other );
	my ($reject) = $t->console( $vault, { argv => ['verify'] } );
	is( $reject->{exit}, 1,
		'verify rejects the plate of another check value (CER-VERIFY-1)' );
	like( $reject->{error}, qr/a wrong plate, or a damaged plate/,
		'the rejection names a wrong plate or a damaged plate '
		    . '(CER-VERIFY-1)' );
	is( $t->digest($index), $recorded,
		'the rejection wrote no date: the index stays (CER-VERIFY-5)' );
	$t->write_file( "$vault->{dir}/machine/config", @config );

	#
	# The audit reports the recorded date (CER-VERIFY-3). The date
	# is the day of the guest at the match, and the clock of that
	# step gives it. A step can cross midnight, so the two reads of
	# the clock bound the day.
	#
	# The mutations: an audit that prints no verified line, and a
	# verification that records another day, each fail here.
	#
	$t->start;
	my ($after) = $t->console( $vault,
		{ argv => ['audit'], answers => ['right'] } );
	is( $after->{exit}, 0, 'the audit after the verification passes' )
	    or diag( $after->{error} );
	my @day = map { date_of($_) } @{ $match->{clock} };
	my $day = join '|', map { quotemeta } @day;
	like( $after->{out}, qr/^verified: (?:$day)$/m,
		'the audit reports the date of the verification (CER-VERIFY-3)' )
	    or diag("the day of the match: @day. The output:\n$after->{out}");
	return;
};
