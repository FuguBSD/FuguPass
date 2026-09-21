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

# The creation leg (CER-CREATE-2 to CER-CREATE-9, PROG-ONESHOT-4).
#
# The ceremony reads the master from the scan double, and it reads
# the passphrase twice from the console of the guest. The leg drives
# three vaults: one whole ceremony, one mistyped passphrase, and one
# refused enrollment with the re-run after it.
#
# The leg reads the command line of the frame and of the subcommand
# first (PROG-ONESHOT-4, PROG-ONESHOT-6). A wrong command line stops
# before the plate scan and before the passphrase read, so a fourth
# vault takes those runs, and no ceremony runs in it.
#
# Each ceremony vault takes a machine name of its own. The device
# factor comes from the master and the machine name, so two vaults
# of one name address one record of a slot (KEY-DEVICE-1). A
# distinct name therefore keeps the records of this leg apart from
# the records of every other leg.
#
# The refused enrollment comes from the counter policy. A get_pin of
# a high counter raises the stored counter of the record at the
# oracle, and a later set_pin of a lower counter takes an HTTP error
# (FuguOracle OPS-SET-2). The ceremony reads the counters file of
# the vault, so the leg holds the counter of one slot alone, and the
# slot loop stops there.

use v5.36;

return sub ($t)
{
	# The frame, before the first ceremony (PROG-ONESHOT-4).
	my $bad = $t->program('bogus');
	is( $bad->{exit}, 2, 'an unknown subcommand exits 2' );
	like( $bad->{error}, qr/^usage: /m,
		'an unknown subcommand gives a usage line' );

	# The command line of the subcommand (PROG-ONESHOT-6). Each
	# case below stops before the plate scan and before the
	# passphrase read, so each one runs over ssh with no
	# terminal. The -d option belongs to the program, so it
	# comes before the subcommand name.
	#
	# The oracle argument of a case is well formed, so the one
	# wrong field of the case is the field that the gate reads.
	my $empty  = $t->ceremony_vault('usage');
	my $oracle = $t->foreign_key . q{ } . $t->url;
	my @wrong  = (
		{
			what   => 'a malformed threshold',
			argv   => [ '-k', '0' ],
			reason => qr/the threshold is too small/
		},
		{
			what   => 'a malformed round count',
			argv   => [ '-r', 'often' ],
			reason => qr/the round count is invalid/
		},
		{
			what   => 'an absent mandatory option',
			argv   => [],
			reason => qr/the -k, -m and -r options/
		},
		{
			what => 'a rejected machine name',
			argv =>
			    [ '-k', 1, '-m', 'Machine', '-r', 1, $oracle ],
			reason => qr/the machine name takes lowercase letters/
		},
		{
			what => 'a threshold above the oracle count',
			argv => [
				'-k', 2, '-m', $empty->{machine},
				'-r', 1, $oracle
			],
			reason =>
			    qr/the threshold is above the count of the oracle/
		} );

	for my $case (@wrong) {
		my $run = $t->program( '-d', $empty->{dir}, 'create',
			@{ $case->{argv} } );
		is( $run->{exit}, 2, "$case->{what} exits 2" );
		like( $run->{error}, $case->{reason},
			"$case->{what} gives the reason" );
		like( $run->{error}, qr/^usage: /m,
			"$case->{what} gives a usage line" );
	}

	# The bound of the oracle set, the one gate of the ceremony
	# that a command line reaches (VAULT-CONFIG-6). It stops the
	# ceremony, so it gives the status 1 and no usage line.
	my $many = $t->program(
		'-d', $empty->{dir}, 'create', '-k', 1,
		'-m', $empty->{machine}, '-r', 1, ('x') x 256 );
	is( $many->{exit}, 1, 'an oracle set above the bound exits 1' );
	like( $many->{error}, qr/the oracle set takes [0-9]+ positions/,
		'an oracle set above the bound gives the reason' );

	#
	# The whole ceremony.
	#
	my $vault  = $t->ceremony_vault('main');
	my @before = $t->records;
	my $run    = $t->create($vault);
	is( $run->{exit}, 0, 'the creation ceremony passes' )
	    or diag( $run->{error} );

	my $dir = $vault->{dir};
	is( $t->file_exists("$dir/machine/factor"),
		1, 'the ceremony wrote the device factor (CER-CREATE-2)' );
	is( $t->file_exists("$dir/machine/config"),
		1, 'the ceremony wrote the config (CER-CREATE-3)' );
	is( $t->file_exists( $t->seal($vault) ),
		1, 'the ceremony wrote the canary seal (CER-CREATE-5)' );
	is( $t->file_exists("$dir/machine/wrap.index.1"),
		1, 'the ceremony wrote the index wrap (CER-CREATE-5)' );
	is( $t->file_exists("$dir/index"),
		1, 'the ceremony wrote the index (CER-CREATE-7)' );

	my @entry = grep { /\A[0-9a-f]{64}\z/ } $t->names($dir);
	is( scalar @entry, 64,
		'the ceremony wrote one slot file of each slot '
		    . '(CER-CREATE-6, ENTRY-POOL-2)' );

	my @wrap = grep { /\Awrap\.[0-9]+\.1\z/ } $t->names("$dir/machine");
	is( scalar @wrap, 64,
		'the ceremony wrote one wrap of each slot at the oracle '
		    . '(CER-CREATE-6)' );

	# The plate check value of the fixed test master. The double
	# prints that master, so the config of a ceremony holds the
	# check value of it (KEY-MASTER-5, VAULT-CONFIG-1).
	my $check = $t->plate_check;
	like( $t->read_file("$dir/machine/config"),
		qr/^plate-check: \Q$check\E$/m,
		'the config holds the plate check value of the test master' );

	# The search of the two values below must find nothing, so
	# this search of a value that one file holds proves the
	# search itself.
	is( scalar $t->search( $dir, $check ),
		1, 'the search finds the plate check value in one file' );
	is( scalar $t->search( $dir, $t->master ),
		0, 'no file of the vault holds the master (CER-CREATE-8)' );
	is( scalar $t->search( $dir, 'candidate-mnemonic' ),
		0, 'no file of the vault holds a slot plaintext '
		    . '(VAULT-SEAL-1)' );

	# The revocation kit (CER-CREATE-9, ORC-REVOKE-6).
	my $kit = $t->read_file("$dir/machine/revocation-kit");
	like( $run->{out}, qr{\Q$dir/machine/revocation-kit\E},
		'the report names the kit file (PROG-ONESHOT-7)' );
	like( $kit, qr/^machine \Q$vault->{machine}\E$/m,
		'the kit names this machine (ORC-REVOKE-6)' );

	my @record = $kit =~ /^record 1 ([0-9a-f]{64}\.pin)$/mg;
	is( scalar @record, 65,
		'the kit names 65 record files of the oracle: the 64 slots '
		    . 'and the canary (ORC-REVOKE-6)' );
	my %once = map { $_ => 1 } @record;
	is( scalar keys %once, 65,
		'each record file name of the kit is a name of its own' );

	# The names must be the record files that the oracle now
	# holds. The two sets before and after the ceremony give the
	# records of it, and a wrong hash input in the kit names 65
	# unique files that no store holds.
	my %before = map { $_ => 1 } @before;
	my @fresh  = sort grep { !$before{$_} } $t->records;
	is_deeply( \@fresh, [ sort @record ],
		'the kit names the record files that the ceremony stored '
		    . 'at the oracle (ORC-REVOKE-6)' );

	#
	# The mistyped second passphrase (CER-CREATE-4).
	#
	my $typo = $t->ceremony_vault('typo');
	my $stop = $t->create( $typo, pass => [ 'right', 'other' ] );
	isnt( $stop->{exit}, 0,
		'a mistyped second passphrase stops the ceremony' );
	like( $stop->{error}, qr/the two reads differ/,
		'the report names the two reads' );
	is( $t->file_exists("$typo->{dir}/machine/config"),
		1, 'the stopped ceremony wrote the config before the read' );
	is( $t->file_exists( $t->counters($typo) ),
		0, 'the stopped ceremony sent no request' );
	is( $t->file_exists( $t->seal($typo) ),
		0, 'the stopped ceremony wrote no canary seal' );

	#
	# The refused enrollment, and the re-run after it
	# (CER-CREATE-6).
	#
	my $slow = $t->ceremony_vault( 'refuse', slot => 3 );
	my $name = $t->record($slow);
	$t->config($slow);

	is( $t->enroll($slow)->{state}, 'ok',
		'the record of the slot enrolls before the ceremony' );
	$t->write_file( $t->counters($slow),
		"$name: " . $t->high_counter );
	is( $t->reveal($slow)->{state},
		'ok', 'the reveal raises the stored counter of that record' );
	$t->remove_file( $t->counters($slow) );

	my $url    = $t->url;
	my $refuse = $t->create($slow);
	isnt( $refuse->{exit}, 0, 'a refused set_pin stops the ceremony' );
	like( $refuse->{error}, qr/slot 3 at oracle 1 \(\Q$url\E\)/,
		'the report names the slot and the oracle of the refusal' );

	my @partial = grep { /\A[0-9a-f]{64}\z/ } $t->names( $slow->{dir} );
	is( scalar @partial, 3,
		'the stopped slot loop wrote the file of each slot before '
		    . 'the refused one, and no file of it' );
	is( $t->file_exists("$slow->{dir}/index"),
		0, 'the stopped ceremony wrote no index' );
	is( $t->file_exists("$slow->{dir}/machine/revocation-kit"),
		0, 'the stopped ceremony wrote no kit' );

	# The counter of that one record, above the stored counter of
	# the oracle. Every other line of the file stays, so each
	# other record keeps the counter of the stopped run.
	my @line = grep { !/\A\Q$name\E: / }
	    split /\n/, $t->read_file( $t->counters($slow) ) // '';
	push @line, "$name: " . ( $t->high_counter + 1 );
	$t->write_file( $t->counters($slow), @line );

	my $again = $t->create($slow);
	is( $again->{exit}, 0, 'the re-run of the ceremony passes' )
	    or diag( $again->{error} );
	my @full = grep { /\A[0-9a-f]{64}\z/ } $t->names( $slow->{dir} );
	is( scalar @full, 64, 'the re-run completes the pool' );
	is( $t->file_exists("$slow->{dir}/index"),
		1, 'the re-run wrote the index' );

	return;
};
