#!/usr/bin/env perl
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

# Host tests of bin/fugupass-repl, the interface process.
#
# The tests run a fake core: the test process spawns the program with
# the two pipes of PROG-IFACE-10 and answers each request itself. The
# operator input is a pipe, so the program reads plain lines with no
# editing and no escape output (PROG-IFACE-7).

use v5.34;
use warnings;
use experimental 'signatures';
no feature qw(indirect multidimensional bareword_filehandles);

use File::Temp qw(tempdir);
use FindBin    qw($RealBin);
use IO::Select;
use POSIX qw(dup2 WNOHANG);
use Test::More;

my $PROGRAM = "$RealBin/../../bin/fugupass-repl";

# The build step of the unveil list, and the file of the core
# process that carries that list (PROG-SPLIT-10).
my $GENERATOR = "$RealBin/../../src/unveil-paths";
my $SANDBOX   = "$RealBin/../../src/sandbox.c";

eval { require Fugu::REPL; require Fugu::Sandbox; 1 }
    or plan skip_all => 'the Fugu library is absent';

# The bound of every wait. A program that stalls fails the test
# instead of the run.
use constant DEADLINE => 15;

# The descriptors of the two pipes (PROG-IFACE-10). The child moves
# its ends there, over two spare numbers, because dup2 clears the
# close-on-exec flag only when the source differs from the target.
use constant {
	CHILD_REQUEST_FD => 3,
	CHILD_REPLY_FD   => 4,
	SPARE_REQUEST_FD => 20,
	SPARE_REPLY_FD   => 21,
};

# _spawn(%args):
#	Start the interface program and return the fake core: the
#	process id, the operator input, the terminal output, the
#	error output, and the two pipes. With dir the child runs in
#	that directory and takes it as its home. With no_pipes the
#	child gets no request pipe and no reply pipe.
sub _spawn (%args)
{
	my %pipe;
	for my $name (qw(in out err req rep)) {
		pipe my $read, my $write or die "pipe: $!\n";
		$pipe{$name} = [ $read, $write ];
	}

	my $pid = fork;
	defined $pid or die "fork: $!\n";

	if ( $pid == 0 ) {
		if ( $args{dir} ) {
			chdir $args{dir} or exit 127;
			$ENV{HOME} = $args{dir};
		}

		open STDIN,  '<&', $pipe{in}[0]  or exit 127;
		open STDOUT, '>&', $pipe{out}[1] or exit 127;
		open STDERR, '>&', $pipe{err}[1] or exit 127;

		if ( !$args{no_pipes} ) {
			dup2( fileno $pipe{req}[1], SPARE_REQUEST_FD )
			    or exit 127;
			dup2( fileno $pipe{rep}[0], SPARE_REPLY_FD )
			    or exit 127;
			dup2( SPARE_REQUEST_FD, CHILD_REQUEST_FD ) or exit 127;
			dup2( SPARE_REPLY_FD,   CHILD_REPLY_FD )   or exit 127;
			POSIX::close(SPARE_REQUEST_FD);
			POSIX::close(SPARE_REPLY_FD);
		}

		exec $^X, $PROGRAM;
		exit 127;
	}

	close $pipe{in}[0]  or die "close: $!\n";
	close $pipe{out}[1] or die "close: $!\n";
	close $pipe{err}[1] or die "close: $!\n";
	close $pipe{req}[1] or die "close: $!\n";
	close $pipe{rep}[0] or die "close: $!\n";

	return {
		pid     => $pid,
		in      => $pipe{in}[1],
		out     => $pipe{out}[0],
		err     => $pipe{err}[0],
		req     => $pipe{req}[0],
		rep     => $pipe{rep}[1],
		pending => q{},
		stalled => 0,
	};
}

# _request($core):
#	The next request line of the interface, without the
#	terminator. Return nothing at the end of the request pipe,
#	and record a stall when the wait runs out.
sub _request ($core)
{
	while (1) {
		if ( $core->{pending} =~ s/\A([^\n]*)\n// ) {
			return $1;
		}

		my $select = IO::Select->new( $core->{req} );
		if ( !$select->can_read(DEADLINE) ) {
			$core->{stalled} = 1;
			return;
		}

		my $count = sysread $core->{req}, my $chunk, 4096;
		return unless $count;
		$core->{pending} .= $chunk;
	}
}

# _reply($core, @lines):
#	Write the reply lines of one request, the end line included.
sub _reply ( $core, @lines )
{
	my $bytes = join q{}, map { "$_\n" } @lines;
	syswrite $core->{rep}, $bytes or die "reply: $!\n";
	return;
}

# _type($core, @lines):
#	Give the operator input of the session.
sub _type ( $core, @lines )
{
	my $bytes = join q{}, map { "$_\n" } @lines;
	syswrite $core->{in}, $bytes or die "type: $!\n";
	return;
}

# _reap($core):
#	The exit status of the interface. Return nothing when a signal
#	ended it, and nothing when it ran past the deadline.
sub _reap ($core)
{
	my $deadline = time + DEADLINE;

	while ( time <= $deadline ) {
		my $done = waitpid $core->{pid}, WNOHANG;
		if ( $done == $core->{pid} ) {
			return unless POSIX::WIFEXITED($?);
			return POSIX::WEXITSTATUS($?);
		}
		select undef, undef, undef, 0.02;
	}

	kill 'KILL', $core->{pid};
	waitpid $core->{pid}, 0;
	return;
}

# _slurp($fh):
#	Every byte that the handle still holds.
sub _slurp ($fh)
{
	local $/ = undef;
	my $text = <$fh>;
	close $fh or die "close: $!\n";
	return $text // q{};
}

# Each of the six commands reaches the core as one request line, and
# help and quit reach no core path (PROG-REPL-3). The line loses its
# leading and its trailing space, and an empty line sends nothing
# (PROG-IFACE-11).
subtest 'each command maps to one request line' => sub {
	my $core = _spawn();

	is( _request($core), 'ls', 'the interface asks for the listing' );
	_reply( $core, '>alpha', '>beta', '=ok' );

	_type(
		$core, 'ls', 'show alpha',
		'add -T stored beta',
		'gen -T derived gamma',
		'totp delta', '  audit  ', q{}, 'help', 'quit'
	);

	my @seen;
	while ( defined( my $request = _request($core) ) ) {
		push @seen, $request;

		# The failed command must not end the session: the
		# request after it proves that the prompt came back.
		if    ( $request eq 'ls' )         { _reply( $core, '=ok' ) }
		elsif ( $request eq 'totp delta' ) { _reply( $core, '=fail' ) }
		else                               { _reply( $core, '=ok' ) }
	}

	ok( !$core->{stalled}, 'the interface never stalls' );
	is_deeply(
		\@seen,
		[
			'ls',
			'show alpha',
			'add -T stored beta',
			'gen -T derived gamma',
			'totp delta',
			'audit'
		],
		'the six commands reach the core, and help and quit do not'
	);
	is( _reap($core), 0, 'quit ends the interface' );
};

# The display filter guards the terminal (PROG-IFACE-5). The expected
# bytes are literal here: a filter that the test computes would pass
# against itself.
subtest 'the display filter guards the terminal' => sub {
	my $core = _spawn();

	is( _request($core), 'ls', 'the interface asks for the listing' );
	_reply( $core, '=ok' );

	_type( $core, 'show alpha', 'quit' );
	is( _request($core), 'show alpha', 'the command reaches the core' );

	# BEL, DEL, a raw C1 byte, a C1 byte as UTF-8, the two bytes
	# of one UTF-8 sequence, and an escape sequence.
	_reply(
		$core,
		">alpha\x07beta\x7Fgamma\x9Bdelta\xC2\x9B"
		    . "epsilon\xC3\xA5\x1B[31m",
		'=ok'
	);

	is( _reap($core), 0, 'the interface ends' );
	is(
		_slurp( $core->{out} ),
		"alpha?betagammadeltaepsilon\xC3\xA5?[31m\n",
		'the filter replaces BEL, removes DEL and C1, and keeps UTF-8'
	);
};

# A reply line with another tag is a protocol failure, and the
# interface must stop (PROG-IFACE-11). The core and the interface
# disagree there, and a guess is worse than a stop.
subtest 'an unknown reply tag stops the interface' => sub {
	my $core = _spawn();

	is( _request($core), 'ls', 'the interface asks for the listing' );
	_reply( $core, '!alpha', '=ok' );

	is( _reap($core), 1, 'the unknown tag stops the interface' );
	like(
		_slurp( $core->{err} ),
		qr/reply tag '!'/,
		'and the report names the tag'
	);
};

# The core locks and closes the reply pipe, and that ends the
# interface even with the operator input still open (PROG-IFACE-6,
# PROG-REPL-7).
subtest 'a closed reply pipe ends the interface' => sub {
	my $core = _spawn();

	is( _request($core), 'ls', 'the interface asks for the listing' );
	_reply( $core, '=ok' );

	close $core->{rep} or die "close: $!\n";

	is( _reap($core), 0, 'the closed reply pipe ends the interface' );
	unlike( _slurp( $core->{out} ),
		qr/\e/, 'the plain mode writes no escape' );
};

# One Fugu::Signal manager installs the interrupt handler, and that
# handler keeps the process alive (PROG-IFACE-9). Without it the
# default action of SIGINT kills the process, and _reap then reports
# nothing. This case proves the handler alone, and the case 'the
# prompt loop reads the interrupt flag' below proves the read of the
# flag.
subtest 'a signal ends the session' => sub {
	my $core = _spawn();

	is( _request($core), 'ls', 'the interface asks for the listing' );
	_reply( $core, '=ok' );

	# The request above proves that the handler is in place: the
	# program installs it before it opens the pipes.
	select undef, undef, undef, 0.2;
	kill 'INT', $core->{pid} or die "kill: $!\n";

	is( _reap($core), 0, 'the interrupt ends the interface' );
};

# The interface writes no history file, and no other file
# (PROG-REPL-8).
subtest 'the interface writes no file' => sub {
	my $dir  = tempdir( CLEANUP => 1 );
	my $core = _spawn( dir => $dir );

	is( _request($core), 'ls', 'the interface asks for the listing' );
	_reply( $core, '>alpha', '>beta', '=ok' );

	_type( $core, 'show alpha', 'quit' );
	is( _request($core), 'show alpha', 'the command reaches the core' );
	_reply( $core, '>name alpha', '=ok' );

	is( _reap($core), 0, 'the interface ends' );

	opendir my $dh, $dir or die "opendir: $!\n";
	my @left = sort grep { $_ ne q{.} && $_ ne q{..} } readdir $dh;
	closedir $dh or die "closedir: $!\n";

	is( "@left", q{}, 'the working directory and the home stay empty' );
};

# The interface refuses to run without the core (PROG-IFACE-10).
subtest 'the interface needs the core' => sub {
	my $core = _spawn( no_pipes => 1 );

	is( _reap($core), 1, 'the interface refuses to run alone' );
	like(
		_slurp( $core->{err} ),
		qr/request pipe/,
		'and it names the pipe that is absent'
	);
};

# The completion offers the command names, and the entry names of the
# listing that PROG-REPL-12 allows (PROG-REPL-9, PROG-REPL-10). The
# test loads the program as a module and drives the listing path with
# a real reply.
subtest 'the completion offers the commands and the entry names' => sub {
	require $PROGRAM;

	pipe my $req_read, my $req_write or die "pipe: $!\n";
	pipe my $rep_read, my $rep_write or die "pipe: $!\n";

	my $session = main::new_session( $req_write, $rep_read );
	my $editor  = main::build_editor($session);

	is_deeply( $editor->watch, [$rep_read],
		'the editor watches the reply pipe' );
	is_deeply(
		[ sort keys %{ $editor->commands } ],
		[qw(add audit gen help ls quit show totp)],
		'the command table holds the six commands, help and quit'
	);

	# The middle entry carries the text of an end line. The tag of
	# each line keeps the frame apart from the text, so that name
	# cannot end the reply (PROG-IFACE-11).
	#
	# The last entry carries a BEL and an escape sequence. The
	# editor writes a candidate to the terminal on a Tab press, and
	# it filters nothing there (PROG-IFACE-5). The display filter
	# changes that name, so the set leaves it out (PROG-REPL-12).
	# The three other names pass the filter whole, and the set
	# holds each one.
	syswrite $rep_write, ">alpha\n>=ok\n>beta\n>ga\x07mma\x1B[31m\n=ok\n"
	    or die "write: $!\n";
	ok( main::request_listing( $editor, $session ),
		'the listing reply arrives' );

	my $asked = readline $req_read;
	is( $asked, "ls\n", 'the interface asks the core for the listing' );

	my $callback = main::completion_callback($session);
	my @offered  = $callback->( 'a', 'show a' );
	is_deeply(
		[ sort @offered ],
		[ '=ok', 'alpha', 'beta' ],
		'the callback offers each entry name that the display '
		    . 'filter keeps whole (PROG-REPL-12)'
	);

	# Fugu::REPL keeps the callback under the constructor key, and
	# it has no reader for it. The test reads the key, because the
	# wiring of the callback is what PROG-REPL-9 demands.
	my @wired = $editor->{complete}->( 'a', 'show a' );
	is_deeply(
		[ sort @wired ],
		[ '=ok', 'alpha', 'beta' ],
		'the editor holds that callback'
	);
};

# Each ls of the operator refreshes the completion set, and that set
# takes the same bound (PROG-REPL-10, PROG-REPL-12). The fake editor
# types one ls, so the second filter site of the program runs.
subtest 'the operator listing refreshes the completion set' => sub {
	require $PROGRAM;

	pipe my $req_read, my $req_write or die "pipe: $!\n";
	pipe my $rep_read, my $rep_write or die "pipe: $!\n";

	# The reply of the start-up listing, and then the reply of the
	# listing of the operator. The second reply holds one name that
	# the display filter changes.
	syswrite $rep_write, ">alpha\n=ok\n>beta\n>ga\x07mma\n=ok\n"
	    or die "write: $!\n";

	my $session = main::new_session( $req_write, $rep_read );
	my $editor  = FakeEditor->new( lines => ['ls'] );
	my $signals = FakeSignals->new( flags => [ 0, 0 ] );

	is( _run_session( $editor, $session, $signals ),
		0, 'the prompt loop ends at the end of the operator input' );
	is_deeply( $session->{entries}, ['beta'],
		'the listing of the operator replaced the completion set, '
		    . 'and it left the filtered name out' );

	my @asked = ( scalar readline $req_read, scalar readline $req_read );
	is_deeply(
		\@asked,
		[ "ls\n", "ls\n" ],
		'the start-up listing and the listing of the operator are '
		    . 'the two requests of the loop'
	);
};

# The prompt loop must read the interrupt flag of the manager
# (PROG-IFACE-9). The fake manager reports the interrupt of every
# read, so a loop that acts on the flag reads no command line. The
# fake editor counts each read, so a loop that ignores the flag
# reads one line and leaves the count at 1. The count is the
# measure of this case. That editor holds no line, so such a loop
# then ends on the end of the input, and no case here needs the
# deadline of _run_session.
subtest 'the prompt loop reads the interrupt flag' => sub {
	require $PROGRAM;

	pipe my $req_read, my $req_write or die "pipe: $!\n";
	pipe my $rep_read, my $rep_write or die "pipe: $!\n";

	# The one listing of the loop comes first, and the flag stands
	# at the prompt after it (PROG-REPL-10).
	syswrite $rep_write, "=ok\n" or die "write: $!\n";

	my $session = main::new_session( $req_write, $rep_read );
	my $editor  = FakeEditor->new;
	my $signals = FakeSignals->new;

	is( _run_session( $editor, $session, $signals ),
		0, 'the interrupt ends the prompt loop with no failure' );
	is( $signals->{asked}, 1, 'the loop asked the manager for the flag' );
	is( $editor->{reads},  0, 'and it read no command line after it' );

	my $asked = readline $req_read;
	is( $asked, "ls\n", 'the listing is the one request of the loop' );
};

# The build derives the unveil list of the interface process, and the
# core process carries it (PROG-SPLIT-10). Neither Fugu::Sandbox
# method calls a syscall, so this host test proves the list.
#
# The test runs the build step with the perl of this test, and the
# expected list comes from the two methods. The generated header is
# no file of the repository, so the run here is the one way to read
# it off OpenBSD.
subtest 'the build derives the unveil list of the interface' => sub {
	my $header = _generate();

	like(
		$header,
		qr/^\#define UNVEIL_PATHS_DERIVED\b/m,
		'the header defines the macro of the list'
	);

	my @got;
	push @got, [ $1, $2 ]
	    while $header =~ /\{ "([^"]*)",\s*"([a-z]+)" \}/g;

	my ( @want, %seen );
	for my $path ( Fugu::Sandbox->perl_lib_dirs ) {
		push @want, [ $path, 'r' ] if !$seen{$path}++;
	}
	for my $entry ( Fugu::Sandbox->system_paths ) {
		push @want, [ $entry->[0], $entry->[1] ]
		    if !$seen{ $entry->[0] }++;
	}

	is_deeply( \@got, \@want,
		      'perl_lib_dirs and system_paths give the list that the '
		    . 'header holds' );

	# The core process no longer names the resolver files and the
	# service tables itself: system_paths carries them
	# (PROG-SPLIT-3).
	my %perm = map { $_->[0] => $_->[1] } @got;
	for my $path (qw(/etc/resolv.conf /etc/hosts /etc/services)) {
		is( $perm{$path}, 'r',
			      "the list holds $path with the r permission "
			    . '(PROG-SPLIT-3)' );
	}

	# The core process carries the list, so the one file of the
	# unveil calls reads the header and expands the macro
	# (PROG-SPLIT-10).
	my $sandbox = _read($SANDBOX);
	like(
		$sandbox,
		qr/^\#include "unveil_paths\.h"$/m,
		'the sandbox of the core process reads the header'
	);
	like( $sandbox, qr/unveil_list\[\]\s*=\s*\{.*\bUNVEIL_PATHS_DERIVED\b/s,
		'the unveil list of the core process holds the derived list '
		    . '(PROG-SPLIT-10)' );

	# The build runs the step through the shebang of it, and the
	# core process runs the interface program through the shebang
	# of that program. The two lines must name one perl: the list
	# of the header then names the perl of the interface process
	# (PROG-SPLIT-10).
	my ($step)      = split /\n/, _read($GENERATOR);
	my ($interface) = split /\n/, _read($PROGRAM);
	is( $step, $interface,
		'the build step and the interface program name one perl' );
};

# _generate():
#	The header that the build step writes. The test runs the step
#	with its own perl, because the shebang of the step names the
#	perl of the target machine.
sub _generate ()
{
	open my $fh, '-|', $^X, $GENERATOR
	    or die "the test runs no $GENERATOR: $!\n";
	my $text = do { local $/ = undef; <$fh> };
	close $fh or die "$GENERATOR failed\n";
	return $text;
}

# The fake editor of the prompt loop. run_session calls read_line at
# the prompt, and event, restore and show after it. The lines of the
# constructor are the operator input, and read_line gives the end of
# that input after the last line.
package FakeEditor;

sub new ( $class, %args )
{
	return bless { reads => 0, lines => $args{lines} // [] }, $class;
}

sub read_line ($self)
{
	$self->{reads}++;
	return shift @{ $self->{lines} };
}

sub event ($)
{
	return;
}

sub restore ($self)
{
	return $self;
}

sub show ( $self, $ )
{
	return $self;
}

# The fake signal manager of the prompt loop. It counts each read of
# the flag. The flags of the constructor answer the first reads, and
# each read after them reports an interrupt.
package FakeSignals;

sub new ( $class, %args )
{
	return bless { asked => 0, flags => $args{flags} // [] }, $class;
}

sub interrupted ($self)
{
	$self->{asked}++;
	return @{ $self->{flags} } ? shift @{ $self->{flags} } : 1;
}

package main;

# _run_session($editor, $session, $signals):
#	run_session of the program, inside the deadline of this test.
#	A prompt loop that never ends fails one assertion here, and it
#	stalls no gate.
sub _run_session ( $editor, $session, $signals )
{
	my $status = eval {
		local $SIG{ALRM} =
		    sub { die "the prompt loop ran past the deadline\n" };
		alarm DEADLINE;
		my $rv = main::run_session( $editor, $session, $signals );
		alarm 0;
		return $rv;
	};
	my $error = $@;
	alarm 0;

	is( $error, q{}, 'the prompt loop ends inside the deadline' );
	return $status;
}

# _read($path):
#	Every byte of the file at $path.
sub _read ($path)
{
	open my $fh, '<', $path or die "the test reads no $path: $!\n";
	my $text = do { local $/ = undef; <$fh> };
	close $fh;
	return $text;
}

done_testing();
