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

# The interface leg (PROG-IFACE, PROG-REPL-7, PROG-SPLIT-7,
# PROG-SPLIT-8, PROG-SPLIT-9).
#
# A run of the core process with no subcommand starts one
# interactive session: the core unlocks the vault and spawns
# bin/fugupass-repl on two pipes (PROG-IFACE-1, PROG-IFACE-10). The
# leg drives that session, and it drives the lock of it.
#
# The standard input of a step is a named pipe, so the interface
# reads plain lines with no editing and no escape output
# (PROG-IFACE-7). The passphrase and the secret of an add still
# reach the core through /dev/tty, so each step runs on the console
# of the guest (TEST-HARNESS-8, SEC-MEMORY-4, PROG-IFACE-3).
#
# The core process gives the exit status 0 only when the interface
# process exited 0 and the session reaped it, so the status of a
# step states that the lock ended the interface as well
# (PROG-IFACE-6, PROG-REPL-7).

use v5.36;

# The slots of the vault of this leg. One add consumes one slot, and
# a ceremony of few slots costs few oracle rounds.
my $POOL = 2;

# The seconds of the idle timeout that the leg writes into the
# config, and the seconds that the standard input of the idle step
# stays open (PROG-REPL-7). The second value is far above the first
# one, so a session that never locks takes the whole hold.
my $IDLE = 3;
my $HOLD = 40;

# The bytes of the entry name at the line bound, and the bytes one
# byte above it. The line of the vault format takes 4096 bytes, and
# that count holds the line feed, so the text of a request line takes
# 4095 bytes (PROG-IFACE-12, VAULT-FORMAT-5). The command word 'show'
# and the space after it take five of those bytes.
my $AT_BOUND   = 4095 - length 'show ';
my $OVER_BOUND = $AT_BOUND + 1;

# session_case($t, $vault):
#	One session of the six commands (PROG-IFACE-2, PROG-REPL-3).
#
#	The session writes one stored entry, lists the index, reveals
#	the entry, and then ends on quit. The line after the quit is a
#	second ls, and the core must never see it: quit lives in the
#	interface (PROG-REPL-3). One listing therefore reaches the
#	standard output, and not two.
#
#	The listing is the measure, and no second reveal is: a second
#	reveal of one entry reaches the request bound of the record
#	and prints nothing either way (ORC-QUORUM-8). The interface
#	also asks for one listing of its own before the first prompt,
#	and it shows none of it (PROG-REPL-10).
sub session_case ( $t, $vault )
{
	my $secret = $t->answer('secret');

	my ($run) = $t->console(
		$vault,
		{
			argv    => [],
			answers => [ 'right', 'secret' ],
			input   => [
				'add -T password -f username=u1 a1',
				'ls', 'show a1', 'quit', 'ls'
			] } );

	is( $run->{exit}, 0,
		'the session ends on quit, and the interface process exited '
		    . '0 (PROG-REPL-7, PROG-IFACE-6)' )
	    or diag( $run->{error} );

	like( $run->{out}, qr/^username: u1$/m,
		'show shows the metadata of the entry (PROG-IFACE-2)' );
	like( $run->{out}, qr/^type: password$/m,
		'the entry carries the type of the add (PROG-IFACE-2)' );
	unlike( $run->{out}, qr/\Q$secret\E/,
		'the standard output of the session holds no secret '
		    . '(PROG-IFACE-3, PROG-OUTPUT-4)' );

	is_deeply( [ $t->terminal($run) ], [$secret],
		'the secret reaches the terminal from the core, and the add '
		    . 'read its secret there (PROG-IFACE-3, PROG-OUTPUT-1)' );

	my @listed = $run->{out} =~ /^a1$/mg;
	is( scalar @listed, 1,
		'ls shows the entry of the open index once, so the line '
		    . 'after the quit reached no core path (PROG-REPL-3)' );

	is_deeply( [ $t->search( $vault->{dir}, $secret ) ],
		[], 'no file of the vault holds the secret of the session '
		    . '(SEC-MEMORY-1)' );
	return;
}

# idle_case($t, $vault):
#	The idle lock of one session (PROG-REPL-7). The timeout is a
#	tunable of the config file, and the config file is plaintext
#	with no seal, so the leg writes the short value of one vault
#	into it (VAULT-CONFIG-1, VAULT-CONFIG-2).
#
#	The standard input of the step stays open and silent for
#	$HOLD seconds, and it sends no command line. The core must
#	lock after $IDLE seconds of it, and the report must name the
#	value of the config file: a core that took the default of
#	IFACE_LOCK_TIMEOUT_DEFAULT would name 300 seconds and would
#	run for the whole hold.
#
#	The clock of a step holds the start-up of the session as well:
#	the spawn of the interpreter, the passphrase read and the
#	canary rounds. The baseline step below runs that start-up and
#	ends at once, so the difference of the two steps holds the
#	wait alone.
sub idle_case ( $t, $vault )
{
	my $path = "$vault->{dir}/machine/config";
	my $text = $t->read_file($path);

	like( $text, qr/^lock-timeout: [0-9]+$/m,
		'the creation wrote the lock timeout of the config '
		    . '(VAULT-CONFIG-1)' );

	$t->write_file( $path,
		map { s/\Alock-timeout: .*\z/lock-timeout: $IDLE/r }
		    split /\n/, $text );

	my ( $base, $run ) = $t->console(
		$vault,
		{ argv => [], answers => ['right'], input => ['quit'] },
		{ argv => [], answers => ['right'], hold  => $HOLD } );

	is( $base->{exit}, 0, 'the baseline session ends on quit' )
	    or diag( $base->{error} );
	is( $run->{exit}, 0, 'the idle lock ends the session with no failure '
		    . '(PROG-REPL-7)' )
	    or diag( $run->{error} );
	like(
		$run->{error},
		qr/the session locks: $IDLE seconds with no request/,
		"the core locks after the $IDLE seconds of the config, and "
		    . 'not after the default (PROG-REPL-7)' );
	is( $run->{out}, '', 'the idle session runs no command' );
	cmp_ok( $t->elapsed($run), '<', $HOLD,
		'the lock ends the step before the standard input closes '
		    . '(PROG-IFACE-6)' );

	# The bound below is the measure of the wait. A deadline that
	# is wrong returns at once, and it prints the same lock line.
	# Each clock reads whole seconds and loses up to one of them,
	# so the bound takes the half of the timeout.
	cmp_ok( $t->elapsed($run) - $t->elapsed($base), '>=', $IDLE / 2,
		"the idle session ran the $IDLE seconds of the timeout "
		    . 'longer than the baseline session (PROG-REPL-7)' );
	return;
}

# long_case($t, $vault):
#	The line bound of a request line (PROG-IFACE-12,
#	VAULT-FORMAT-5). The core must read the line at the bound, and
#	it must refuse the line one byte above it with a fail end
#	line. The session must go on after that refusal.
#
#	The step types the two lines, a third command, and quit. The
#	index holds no entry of the three names, so the report of the
#	core names the name that it read. That report is the measure
#	of each line.
#
#	The third command proves the end line of the refusal: the
#	interface waits for the reply of one request, and it sends the
#	next request after that reply alone.
#
#	The case reads no entry of another case, so the order of the
#	cases of this leg does not reach it.
sub long_case ( $t, $vault )
{
	my ($run) = $t->console(
		$vault,
		{
			argv    => [],
			answers => ['right'],
			input   => [
				'show ' . ( 'a' x $AT_BOUND ),
				'show ' . ( 'b' x $OVER_BOUND ),
				'show zz', 'quit'
			] } );

	is( $run->{exit}, 0,
		'the long request line ends no session (PROG-IFACE-12)' )
	    or diag( $run->{error} );

	like( $run->{error}, qr/holds no entry of the name a{$AT_BOUND}$/m,
		'the core reads the request line at the line bound whole '
		    . '(PROG-IFACE-12, VAULT-FORMAT-5)' );
	like(
		$run->{error},
		qr/the request line holds more than 4096 bytes/,
		'the core refuses the request line one byte above that '
		    . 'bound (PROG-IFACE-12, VAULT-FORMAT-5)' );
	unlike( $run->{error}, qr/holds no entry of the name b/,
		'and the refused line reaches no command (PROG-IFACE-12)' );
	like( $run->{error}, qr/holds no entry of the name zz$/m,
		'the command after the refused line reaches the core, so '
		    . 'that line took an end line (PROG-IFACE-12)' );
	return;
}

# pledge_case($t):
#	The pledge of the interface process (PROG-SPLIT-7,
#	PROG-SPLIT-8, PROG-SPLIT-9).
#
#	tests/stubs/repl-pledge.pl loads the shipped interface
#	program and calls main() of it, so the pledge under test is
#	the pledge of that program. main() then reports the absent
#	request pipe through Fugu::Log, and the probe opens a file.
#
#	The promises are 'stdio tty', and they hold no rpath, so the
#	kernel kills the process on that open. The shell reports the
#	signal as the status 134, and the 'open:' line of the probe
#	never prints.
sub pledge_case ($t)
{
	my $run = $t->perl( 'tests/stubs/repl-pledge.pl',
		$t->helper('fugupass-repl'), '/etc/passwd' );

	like( $run->{out}, qr/^supported: 1$/m,
		'Fugu::Sandbox->is_supported reports enforcement in the '
		    . 'guest (PROG-SPLIT-8)' );
	like( $run->{out}, qr/^before: 1$/m,
		'the file of the probe is there before the pledge' );
	like( $run->{out}, qr/^main: 1$/m,
		'main() of the interface program pledged and reported the '
		    . 'absent request pipe (PROG-IFACE-10)' );
	like( $run->{error}, qr/no request pipe on file descriptor 3/,
		'the report reaches the standard error, and no syslog '
		    . 'socket (PROG-SPLIT-9)' );
	unlike( $run->{out}, qr/^open:/m,
		'the interface process opens no file after the pledge '
		    . '(PROG-SPLIT-7)' );
	is( $run->{exit}, 134,
		'the open after the pledge kills the process with SIGABRT '
		    . '(PROG-SPLIT-7)' );
	return;
}

return sub ($t)
{
	# One ceremony serves the three session cases. Each case names
	# its own entries, so no case reads an entry of another one.
	# The idle case runs last, because it rewrites the config of
	# the vault.
	my $vault = $t->ceremony_vault( 'repl', pool => $POOL );
	my $made  = $t->create($vault);
	is( $made->{exit}, 0, 'the creation of the interface vault passes' )
	    or diag( $made->{error} );

	subtest 'the session of the interface process' =>
	    sub { session_case( $t, $vault ) };
	subtest 'a request line above the line bound' =>
	    sub { long_case( $t, $vault ) };
	subtest 'the idle lock of a session' =>
	    sub { idle_case( $t, $vault ) };
	subtest 'the pledge of the interface process' =>
	    sub { pledge_case($t) };
	return;
};
