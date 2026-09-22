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

eval { require Fugu::REPL; 1 }
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

# One Fugu::Signal manager holds the interrupt flag, and the prompt
# loop reads it (PROG-IFACE-9). Without the handler the default
# action of SIGINT kills the process, and _reap then reports nothing.
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

# The completion offers the command names and the entry names of the
# listing (PROG-REPL-9, PROG-REPL-10). The test loads the program as
# a module and drives the listing path with a real reply.
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
	syswrite $rep_write, ">alpha\n>=ok\n>beta\n=ok\n"
	    or die "write: $!\n";
	ok( main::request_listing( $editor, $session ),
		'the listing reply arrives' );

	my $asked = readline $req_read;
	is( $asked, "ls\n", 'the interface asks the core for the listing' );

	my $callback = main::completion_callback($session);
	my @offered  = $callback->( 'a', 'show a' );
	is_deeply( [ sort @offered ],
		[qw(=ok alpha beta)],
		'the callback offers the entry names of the listing' );

	# Fugu::REPL keeps the callback under the constructor key, and
	# it has no reader for it. The test reads the key, because the
	# wiring of the callback is what PROG-REPL-9 demands.
	my @wired = $editor->{complete}->( 'a', 'show a' );
	is_deeply( [ sort @wired ],
		[qw(=ok alpha beta)], 'the editor holds that callback' );
};

done_testing();
