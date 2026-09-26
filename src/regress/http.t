#!/usr/bin/perl
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

# http.t: the tests of the transport (ORC-CONFORM-4).
#
# usage: http.t <driver>
#
# src/regress/Makefile runs this script, and the driver is the
# regress program http. A transport needs a peer, so this file
# starts a fixture server on the loopback and it drives the program
# against that server. The three states of src/http.h are the
# subject: the bytes of an answer, an HTTP error with its status,
# and a transport failure.
#
# The fixture answers one connection in a child process. It reads
# the whole request first, so the client never writes to a closed
# socket, and the first case writes the request to a file for the
# assertions of the head.
#
# The script reads the base Perl of OpenBSD only. It opens no file
# on the standard input, so a run under </dev/null passes. The
# alarm of each process stops a run that waits on a peer that never
# answers.

use v5.34;
use warnings;
use experimental 'signatures';
no feature qw(indirect multidimensional bareword_filehandles);
use Test::More;
use IO::Socket::INET ();
use POSIX ();

$| = 1;

my $driver = shift @ARGV;
BAIL_OUT('usage: http.t <driver>')
    unless defined $driver && -x $driver;

# The bytes of one request and of one answer, and the base64 of
# them. The transport moves bytes, so the value needs no envelope.
my $HEX = '000102030405';
my $B64 = 'AAECAwQF';

# The file that the fixture writes, with the request that it read.
my $REQFILE = 'http.request';

$SIG{ALRM} = sub { BAIL_OUT('the test did not finish') };
alarm 120;

# _listen():
#	A listening socket on the loopback, on a free port.
sub _listen ()
{
	my $sock = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => 0,
		Listen    => 5,
		Proto     => 'tcp',
		ReuseAddr => 1,
	);
	BAIL_OUT("listen: $!") unless defined $sock;
	return $sock;
}

# _request($conn):
#	The whole request of one connection: the head, and the bytes
#	that Content-Length names.
sub _request ($conn)
{
	my $text = q{};
	my $end  = -1;
	while ( ( $end = index $text, "\r\n\r\n" ) < 0 ) {
		my $n = sysread $conn, my $chunk, 4096;
		return $text unless $n;
		$text .= $chunk;
	}
	my ($want) = $text =~ /\r\nContent-Length:[ ]*(\d+)\r\n/;
	return $text unless defined $want;
	my $got = length($text) - $end - 4;
	while ( $got < $want ) {
		my $n = sysread $conn, my $chunk, $want - $got;
		return $text unless $n;
		$text .= $chunk;
		$got += $n;
	}
	return $text;
}

# _serve($sock, $answer, $save):
#	Fork one fixture. The child accepts one connection, reads the
#	request, and writes $answer. An undef $answer closes the
#	connection with no answer. A true $save writes the request to
#	$REQFILE. The answer is the pid of the child.
sub _serve ( $sock, $answer, $save )
{
	my $pid = fork;
	BAIL_OUT("fork: $!") unless defined $pid;
	return $pid if $pid;

	# The child. POSIX::_exit leaves the test plan of the parent
	# alone, because it runs no END block and it flushes nothing.
	$SIG{PIPE} = 'IGNORE';
	alarm 60;
	my $conn = $sock->accept;
	if ( defined $conn ) {
		$conn->autoflush(1);
		my $text = _request($conn);
		if ($save) {
			my $fh;
			if ( open $fh, '>', $REQFILE ) {
				print {$fh} $text;
				close $fh;
			}
		}
		print {$conn} $answer if defined $answer;
		$conn->close;
	}
	$sock->close;
	POSIX::_exit(0);
}

# _answer($status, $phrase, $body):
#	One HTTP answer, with the head of a conforming oracle.
sub _answer ( $status, $phrase, $body )
{
	return
	      "HTTP/1.1 $status $phrase\r\n"
	    . "Content-Type: application/json\r\n"
	    . 'Content-Length: '
	    . length($body)
	    . "\r\n"
	    . "Connection: close\r\n"
	    . "\r\n"
	    . $body;
}

# _run(@args):
#	The first line of the standard output of one run.
sub _run (@args)
{
	open my $fh, '-|', @args or BAIL_OUT("run: $!");
	my $line = <$fh>;
	1 while <$fh>;
	close $fh;
	chomp $line if defined $line;
	return $line // q{};
}

# _post($answer, $save):
#	One run of the post mode against one fixture that gives
#	$answer.
sub _post ( $answer, $save )
{
	my $sock = _listen();
	my $port = $sock->sockport;
	my $pid  = _serve( $sock, $answer, $save );
	my $line = _run( $driver, 'post', "http://127.0.0.1:$port/get_pin",
		$HEX );
	waitpid $pid, 0;
	$sock->close;
	return $line;
}

# _data($body):
#	One run of the data mode over one body.
sub _data ($body)
{
	my $path = 'http.body';
	open my $fh, '>', $path or BAIL_OUT("$path: $!");
	print {$fh} $body;
	close $fh;
	my $line = _run( $driver, 'data', $path );
	unlink $path;
	return $line;
}

# A 200 with a data member gives the decoded bytes, and the request
# that reaches the oracle is one POST of one JSON body.
unlink $REQFILE;
is( _post( _answer( 200, 'OK', qq({"data": "$B64"}) ), 1 ),
	"ok $HEX", 'a 200 with a data member gives the bytes' );

my $sent = q{};
if ( open my $fh, '<', $REQFILE ) {
	local $/ = undef;
	$sent = <$fh>;
	close $fh;
	unlink $REQFILE;
}
like( $sent, qr{\A\QPOST /get_pin HTTP/1.1\E\r\n}, 'the request is one POST' );
like(
	$sent,
	qr{\r\nHost:[ ]127[.]0[.]0[.]1:\d+\r\n},
	'the request names the host'
);
like(
	$sent,
	qr{\r\nContent-Type:[ ]application/json\r\n},
	'the request names the media type'
);
like( $sent, qr{\r\nContent-Length:[ ]20\r\n}, 'the request names the length' );
like(
	$sent,
	qr{\r\nConnection:[ ]close\r\n},
	'the request closes the stream'
);
like(
	$sent,
	qr{\r\n\r\n\Q{"data": "$B64"}\E\z},
	'the body carries the base64'
);

# A status other than 200 is the HTTP error state, with the status.
for my $case ( [ 500, 'Internal Server Error' ], [ 413, 'Payload Too Large' ],
	[ 400, 'Bad Request' ] )
{
	my ( $status, $phrase ) = @$case;
	is( _post( _answer( $status, $phrase, q{} ), 0 ),
		"http $status", "a $status gives the status" );
}

# A refused connection and a closed socket are transport failures.
my $dead = _listen();
my $port = $dead->sockport;
$dead->close;
is( _run( $driver, 'post', "http://127.0.0.1:$port/get_pin", $HEX ),
	'transport', 'a refused connection is a transport failure' );

is( _post( undef, 0 ), 'transport', 'a closed socket is a transport failure' );

# A body that the reader refuses is a transport failure as well.
for my $case (
	[ 'a duplicate data member', qq({"data": "$B64", "data": "$B64"}) ],
	[ 'a body with no data member', qq({"other": "$B64"}) ],
	[ 'a body over the cap',        '{"data": "' . 'A' x 5000 . '"}' ],
	)
{
	my ( $name, $body ) = @$case;
	is( _post( _answer( 200, 'OK', $body ), 0 ),
		'transport', "$name is a transport failure" );
}

# _chunked($status, $phrase, @chunks):
#	One HTTP answer in the chunked transfer coding, as httpd(8)
#	sends a FastCGI answer with no length. Each element of
#	@chunks is one chunk, and the last chunk of the coding
#	follows them.
sub _chunked ( $status, $phrase, @chunks )
{
	return
	      "HTTP/1.1 $status $phrase\r\n"
	    . "Content-Type: application/json\r\n"
	    . "Transfer-Encoding: chunked\r\n"
	    . "Connection: close\r\n"
	    . "\r\n"
	    . join( q{}, map { sprintf "%x\r\n%s\r\n", length $_, $_ } @chunks )
	    . "0\r\n\r\n";
}

# A chunked answer gives the bytes, as one chunk and as two. The
# mutation: a reader without the decoder takes the size line as the
# body, and it refuses it.
my $json = qq({"data": "$B64"});
is( _post( _chunked( 200, 'OK', $json ), 0 ),
	"ok $HEX", 'a chunked answer of one chunk gives the bytes' );
is( _post( _chunked( 200, 'OK', substr( $json, 0, 7 ), substr( $json, 7 ) ),
		0 ),
	"ok $HEX", 'a chunked answer of two chunks gives the bytes' );

# A malformed coding is a transport failure. The mutations: a
# decoder that stops at the bytes it has takes the size beyond the
# body, one that needs no last chunk takes the body without it, one
# that reads the size to the first space takes the size with no line
# end, one that steps over a trailer takes it, and one that ignores
# the coding name takes gzip.
my $head = "HTTP/1.1 200 OK\r\n"
    . "Content-Type: application/json\r\n"
    . "Transfer-Encoding: chunked\r\n"
    . "Connection: close\r\n\r\n";
for my $case (
	[ 'a chunk size beyond the body',
		$head . sprintf( "%x\r\n%s\r\n0\r\n\r\n", length($json) + 100,
			$json ) ],
	[ 'a body with no last chunk',
		$head . sprintf( "%x\r\n%s\r\n", length $json, $json ) ],
	[ 'a size with no line end',
		$head . sprintf( "%x %s\r\n0\r\n\r\n", length $json, $json ) ],
	[ 'a trailer field',
		$head . sprintf( "%x\r\n%s\r\n0\r\nX: y\r\n\r\n", length $json,
			$json ) ],
	[ 'a coding that the reader does not take',
		( $head =~ s/chunked/gzip/r ) . $json ],
	)
{
	my ( $name, $answer ) = @$case;
	is( _post( $answer, 0 ), 'transport', "$name is a transport failure" );
}

# The reader itself takes one shape only. Each body below reaches
# http_data() with no socket, so the reader is the one subject.
my @bodies = (
	[ 'the one shape',      qq({"data": "$B64"}),           "ok $HEX" ],
	[ 'insignificant space',
		qq( {\n\t"data"\r\n\t: "$B64"\n} ), "ok $HEX" ],
	[ 'an unknown member',
		qq({"a": {"b": [1, "}"], "c": null}, "data": "$B64", "d": [{}]}),
		"ok $HEX"
	],
	[ 'a duplicate data member',
		qq({"data": "$B64", "data": "$B64"}), 'reader' ],
	[ 'no data member',      qq({"other": "$B64"}),     'reader' ],
	[ 'an escape sequence',  '{"data": "AAEC\\u0041wQF"}', 'reader' ],
	[ 'a value of a number', '{"data": 5}',              'reader' ],
	[ 'bad base64',          '{"data": "!!!!"}',         'reader' ],
	[ 'a byte after the object', qq({"data": "$B64"} x), 'reader' ],
	[ 'a body over the cap', '{"data": "' . 'A' x 5000 . '"}', 'reader' ],
);
for my $case (@bodies) {
	my ( $name, $body, $want ) = @$case;
	is( _data($body), $want, "the reader answers $name" );
}

done_testing();
