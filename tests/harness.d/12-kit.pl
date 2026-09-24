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

# The kit leg (ORC-REVOKE-6, PROG-ONESHOT-7, VAULT-LAYOUT-6).
#
# The kit subcommand derives the revocation kit of a machine and
# prints it, and no file of the vault holds one. The leg drives one
# creation and one refill of a vault against the example topology
# of three oracles, and it reads the kit after each ceremony. The
# record set of an instance before a ceremony and after it gives
# the records of that ceremony at that oracle, and the kit must
# name each one of them under that oracle, and no other one.
#
# A copy of the vault with one retired position, and no wrap of it,
# gives the kit after a retirement. The kit must name the records
# of that position too, under the word retired.
#
# A second vault of another machine name takes the same plate and a
# copy of the index, so the kit of the first machine derives there
# from the plate and the index alone. That kit must match the kit
# of the first machine byte for byte.
#
# Each assertion names the mutation that it catches. A state
# assertion compares the kit with a set that this file read from
# the counterparty, and never with a value that the kit itself
# holds.

use v5.36;

# The example topology of TEST-HARNESS-5.
my $ORACLES   = 3;
my $THRESHOLD = 2;

# The slots of a creation with no -p option, and of one refill of
# the config that the creation wrote (ENTRY-POOL-2).
my $POOL = 64;

# records_of($t):
#	The record file names of each instance, by oracle index.
sub records_of ($t)
{
	return { map { $_ => [ $t->records($_) ] } 1 .. $ORACLES };
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

# kit_records($text):
#	The record file names of the kit text $text, by oracle
#	index, each list sorted. A record line holds the word
#	record, the oracle index, and the name.
sub kit_records ($text)
{
	my %record;
	for my $line ( split /\n/, $text ) {
		push @{ $record{$1} }, $2
		    if $line =~ /\Arecord ([0-9]+) ([0-9a-f]{64}\.pin)\z/;
	}
	$_ = [ sort @$_ ] for values %record;
	return \%record;
}

# count_of($records):
#	The count of the record file names of every oracle.
sub count_of ($records)
{
	my $count = 0;
	$count += @$_ for values %$records;
	return $count;
}

# check_kit($t, $what, $run, $vault, $want):
#	The kit of one run against the records $want of the
#	counterparty, by oracle index. Each oracle takes one URL
#	line, and the record lines of it name the records of that
#	oracle and no other one.
#
#	The mutations: a kit without the canary line names 64
#	records of an oracle in place of 65. A kit that hashes the
#	client private key names 65 files that no store holds. A kit
#	that takes the oracle index 1 for every oracle names the
#	records of the first instance under the two others.
sub check_kit ( $t, $what, $run, $vault, $want )
{
	is( $run->{exit}, 0, "$what: the kit subcommand passes" )
	    or diag( $run->{error} );
	unlike( $run->{error}, qr/^fugupass: /m,
		"$what: the kit gives no report" );
	like( $run->{out}, qr/\Amachine \Q$vault->{machine}\E\n/,
		"$what: the first line names the machine (ORC-REVOKE-6)" );

	my $got = kit_records( $run->{out} );
	for my $oracle ( 1 .. $ORACLES ) {
		my $url = $t->url($oracle);
		like( $run->{out}, qr/^oracle $oracle \Q$url\E$/m,
			"$what: the kit names oracle $oracle and its URL" );
		is_deeply( $got->{$oracle}, $want->{$oracle},
			"$what: the record lines of oracle $oracle name the "
			    . 'records of this machine at that oracle, and '
			    . 'no other one (ORC-REVOKE-6)' );
	}
	return;
}

return sub ($t)
{
	my $vault = $t->ceremony_vault( 'kit', oracles => $ORACLES,
		threshold => $THRESHOLD );
	my $dir = $vault->{dir};

	#
	# The creation, and the kit of this machine after it.
	#
	my $start = records_of($t);
	my $made  = $t->create($vault);
	is( $made->{exit}, 0, 'the creation ceremony passes' )
	    or diag( $made->{error} );
	my $created = records_of($t);
	my $want    = fresh( $start, $created );
	is( scalar @{ $want->{1} }, $POOL + 1,
		'the creation stored 65 records at the first oracle: the '
		    . '64 slots and the canary (CER-CREATE-5, CER-CREATE-6)' );

	# The kit of this machine takes no terminal: it reads no
	# passphrase, and it scans no plate (PROG-ONESHOT-7).
	my $kit = $t->program( '-d', $dir, 'kit' );
	check_kit( $t, 'after the creation', $kit, $vault, $want );

	# No file of the vault holds a kit (VAULT-LAYOUT-6). The
	# mutation: a ceremony that writes the kit file of the old
	# layout leaves that file.
	is( $t->file_exists("$dir/machine/revocation-kit"),
		0, 'the ceremony wrote no kit file (VAULT-LAYOUT-6)' );
	my ($name) = @{ $want->{1} };
	is( scalar $t->search( $dir, $name ),
		0, 'no file of the vault holds a record file name of the '
		    . 'kit (ORC-REVOKE-6)' );

	#
	# The refill, and the kit of this machine after it.
	#
	my ($refill) = $t->console( $vault,
		{ argv => ['refill'], answers => ['right'] } );
	is( $refill->{exit}, 0, 'the refill ceremony passes (CER-REFILL-2)' )
	    or diag( $refill->{error} );
	my $refilled = records_of($t);
	my $new      = fresh( $created, $refilled );
	is( scalar @{ $new->{1} }, $POOL,
		'the refill stored one record of each new slot at the '
		    . 'first oracle (CER-REFILL-2)' );

	# The kit must name each record of the refill, and it must
	# grow by the slot count of the refill at each oracle. The
	# mutation: a kit that takes the slot set from the pool size
	# of the config names the 64 slots of the creation alone.
	my $full  = fresh( $start, $refilled );
	my $again = $t->program( '-d', $dir, 'kit' );
	check_kit( $t, 'after the refill', $again, $vault, $full );

	my $listed = kit_records( $again->{out} );
	for my $oracle ( 1 .. $ORACLES ) {
		my %has = map { $_ => 1 } @{ $listed->{$oracle} };
		my @missing = grep { !$has{$_} } @{ $new->{$oracle} };
		is_deeply( \@missing, [],
			"the kit names each record of the refill at oracle "
			    . "$oracle (ORC-REVOKE-6, CER-REFILL-2)" );
	}
	is( count_of($listed) - count_of( kit_records( $kit->{out} ) ),
		$POOL * $ORACLES,
		'the kit grew by the slot count of the refill times the '
		    . 'oracle count (ORC-REVOKE-6)' );

	#
	# The kit after a retirement (ORC-PROVISION-6,
	# CER-PROVISION-16).
	#
	# A retirement writes the word retired at the position, and
	# it deletes the wrap files, the canary seal and the index
	# wrap of that position. The records of this machine stay at
	# the departing oracle, and the owner destroys them with the
	# kit, so the kit names each one of them under that position.
	# The leg builds that state in a copy of the vault. The copy
	# holds the factor of this machine, so the record names of
	# the copy are the record names of this machine.
	#
	# The mutations: a kit that steps over a retired position
	# names no record of position 3. A kit that takes the slot
	# set of a position from the wraps of that position alone
	# names no record of it either, because the copy holds no
	# wrap of position 3.
	my $copy = "$dir-retired";
	$t->copy_dir( $dir, $copy );
	my @config = split /\n/, $t->read_file("$copy/machine/config");
	s/\Aoracle-3: .*\z/oracle-3: retired/ for @config;
	$t->write_file( "$copy/machine/config", @config );
	$t->remove_file( map { "$copy/machine/$_" }
		grep { /\.3\z/ } $t->names("$copy/machine") );

	my $gone = $t->program( '-d', $copy, 'kit' );
	is( $gone->{exit}, 0,
		'the kit of a vault with a retired position passes' )
	    or diag( $gone->{error} );
	like( $gone->{out}, qr/^oracle 3 retired$/m,
		'the kit names the retired position 3 with the word retired '
		    . 'in place of its URL (ORC-REVOKE-6)' );
	my $rest = kit_records( $gone->{out} );
	is_deeply( $rest->{3}, $full->{3},
		'the record lines of the retired position 3 name the records '
		    . 'of this machine at the departing oracle, and no other '
		    . 'one (ORC-REVOKE-6, CER-PROVISION-16)' );
	for my $oracle ( 1 .. 2 ) {
		my $url = $t->url($oracle);
		like( $gone->{out}, qr/^oracle $oracle \Q$url\E$/m,
			"the kit names the live oracle $oracle and its URL "
			    . 'after the retirement' );
		is_deeply( $rest->{$oracle}, $full->{$oracle},
			"the record lines of oracle $oracle are unchanged "
			    . 'after the retirement (ORC-REVOKE-6)' );
	}

	#
	# The kit of a named machine, from the plate of a second
	# machine (KEY-DEVICE-4, ORC-REVOKE-4).
	#
	my $other = $t->ceremony_vault( 'kit-other', oracles => $ORACLES,
		threshold => $THRESHOLD );
	my $second = $t->create($other);
	is( $second->{exit}, 0, 'the creation of the second machine passes' )
	    or diag( $second->{error} );

	# A second machine of the vault holds the shared set, and the
	# index of that set bounds the kit of a named machine
	# (VAULT-LAYOUT-3, VAULT-INDEX-2). The provisioning ceremony
	# copies the set by any transport (CER-PROVISION-2), and the
	# leg copies the index in its place.
	$t->copy_file( "$dir/index", "$other->{dir}/index" );

	# The plate scan takes the double, so the run goes over the
	# console (TEST-HARNESS-8). The subcommand reads no
	# passphrase, so the step takes no answer, and it takes no
	# slot count: the index gives the bound.
	#
	# The mutations: a kit that takes the device factor of this
	# machine in place of the factor of the named machine is the
	# kit of the second machine, and the two differ. A kit that
	# takes a constant bound of 64 in place of the pool-next line
	# of the index names the slots of the creation alone, and it
	# misses each slot of the refill.
	my ($named) = $t->console( $other,
		{ argv => [ 'kit', '-m', $vault->{machine} ] } );
	is( $named->{exit}, 0, 'the kit of a named machine passes' )
	    or diag( $named->{error} );
	is( $named->{out}, $again->{out},
		'the kit of the first machine, from the plate on the '
		    . 'second machine, is the kit of the first machine '
		    . 'byte for byte (KEY-DEVICE-4, ORC-REVOKE-4)' );
	my $own = $t->program( '-d', $other->{dir}, 'kit' );
	isnt( $own->{out}, $named->{out},
		'the kit of the second machine differs from the kit of the '
		    . 'first one (KEY-DEVICE-1)' );
	is( $t->file_exists("$other->{dir}/machine/revocation-kit"),
		0, 'the kit of a named machine wrote no file' );

	# An index that the plate does not open names another vault,
	# and the kit stops with a report (VAULT-INDEX-4). The canary
	# seal of the first machine is a sealed file under another
	# key. The mutation: a kit that takes a constant bound reads
	# no index, and it passes over any file there.
	$t->copy_file( $t->seal($vault), "$other->{dir}/index" );
	my ($wrong) = $t->console( $other,
		{ argv => [ 'kit', '-m', $vault->{machine} ] } );
	is( $wrong->{exit}, 1, 'a kit under an index of another key fails' );
	like( $wrong->{error}, qr/the plate does not open the index/,
		'a kit under an index of another key names the plate' );

	#
	# The command line of the subcommand (PROG-ONESHOT-4). Each
	# case stops before the plate scan, so each one runs over ssh
	# with no terminal.
	#
	my $bad = $t->program( '-d', $other->{dir}, 'kit', '-m', 'Machine' );
	is( $bad->{exit}, 2, 'a rejected machine name exits 2' );
	like( $bad->{error}, qr/the machine name takes lowercase letters/,
		'a rejected machine name gives the reason' );
	my $alone = $t->program( '-d', $other->{dir}, 'kit', '-p', 3 );
	is( $alone->{exit}, 2, 'the removed -p option exits 2' );
	like( $alone->{error}, qr/^usage: /m,
		'the removed -p option gives a usage line' );
	my $extra = $t->program( '-d', $other->{dir}, 'kit', 'name' );
	is( $extra->{exit}, 2, 'an argument of the subcommand exits 2' );
	like( $extra->{error}, qr/^usage: /m,
		'an argument of the subcommand gives a usage line' );
	return;
};
