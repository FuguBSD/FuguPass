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

# The helper leg (PROG-SCAN-7, PROG-SPLIT-4, PROG-OUTPUT-2).
#
# Every other leg runs the scan double, and the first part of this
# leg runs the scan helper of the guest build. The guest holds a
# video device and no camera behind it, so the ceremony stops at the
# open of that device, and the report names it.
#
# That one report line proves two parts of the path. The helper
# unveils no path, so the unveil list of the core process carries the
# device: a list without the device answers the open with "No such
# file or directory". The execpromises of the core hold no proc
# promise, so the helper reads the two inherited core limits and
# writes none: a setrlimit(2) call of such a child is a pledge
# violation, and the kernel kills the helper before the report
# (SEC-MEMORY-3).
#
# The report proves no promise of the pledge call: the helper opens
# the device before that call, and a machine with no camera stops at
# the open. src/regress/sandbox holds the probe of the video promise
# (PROG-SPLIT-4).
#
# The second part reveals one mnemonic entry twice. The default
# output of a mnemonic is the QR code of fugupass-qr, and the -w
# option prints the words (PROG-OUTPUT-2). The helper directory holds
# the render helper of the guest build, so this part reads the code
# that the program renders.
#
# A secret prints to the terminal, so the console text of a step
# carries the code and the words, and the standard output of the step
# carries neither (PROG-OUTPUT-1, PROG-OUTPUT-4).

use v5.36;

# The slots of the vault of the mnemonic part. The leg consumes one
# slot, and a small pool keeps the ceremony short.
my $POOL = 4;

# The three half blocks of a render, in UTF-8 (PROG-QR-9). U+2588 is
# two light modules, U+2580 is a light module above a dark one, and
# U+2584 is a dark module above a light one. The space is two dark
# modules, and the console carries the bytes of the terminal.
my $LIGHT = qr/\xe2\x96\x88/;
my $HALF  = qr/(?:\xe2\x96[\x80\x84\x88]|[ ])/;

# The code of a mnemonic: 25 modules on each side, a quiet zone of 4
# light modules on each side of that, and two module rows in one
# character row (PROG-QR-6, PROG-QR-9).
my $QUIET = 4;
my $SIDE  = 25 + 2 * $QUIET;
my $ROWS  = int( ( $SIDE + 1 ) / 2 );

return sub ($t)
{
	#
	# The real scan helper, with no camera behind the device
	# (PROG-SCAN-7).
	#
	my $vault = $t->ceremony_vault('scan');
	my $run   = $t->real_program(
		'-d', $vault->{dir}, 'create', '-k', 1,
		'-m', $vault->{machine}, '-r', 1,
		$t->pubkey . q{ } . $t->url );

	isnt( $run->{exit}, 0,
		'a ceremony of a machine with no camera stops (PROG-SCAN-7)' );
	like( $run->{error},
		qr{fugupass-scan: /dev/video: Device not configured},
		'the helper opens the video device of the unveil list, and '
		    . 'no camera stands behind it (PROG-SCAN-7, '
		    . 'PROG-SCAN-13, PROG-SPLIT-4)' )
	    or diag( $run->{error} );
	like( $run->{error}, qr/the plate scan fails/,
		'the core process reports the failed scan (CER-CREATE-1)' );
	is( $t->file_exists( $t->counters($vault) ),
		0, 'the stopped ceremony sent no request' );

	#
	# The two shapes of one mnemonic entry (PROG-OUTPUT-2).
	#
	my $code_vault = $t->ceremony_vault( 'code', pool => $POOL );
	my $made       = $t->create($code_vault);
	is( $made->{exit}, 0, 'the creation of the mnemonic vault passes' )
	    or diag( $made->{error} );

	my ( $gen, $code, $words ) = $t->console(
		$code_vault,
		{ argv => [ 'gen', '-T', 'mnemonic', 'm1' ],
			answers => ['right'] },
		{ argv => [ 'show',        'm1' ], answers => ['right'] },
		{ argv => [ 'show', '-w', 'm1' ], answers => ['right'] } );

	is( $gen->{exit}, 0, 'gen writes one mnemonic entry' )
	    or diag( $gen->{error} );
	is( $words->{exit}, 0, 'show -w passes on a mnemonic entry' )
	    or diag( $words->{error} );
	is( $code->{exit}, 0, 'show passes on a mnemonic entry' )
	    or diag( $code->{error} );

	# The words, on the -w option.
	my @line = $t->terminal($words);
	is( scalar @line, 1, 'show -w writes one line to the terminal' );
	my $text = $line[0] // '';
	like( $text, qr/\A(?:[a-z]+ ){11}[a-z]+\z/,
		'the -w option prints the 12 words of the mnemonic '
		    . '(PROG-OUTPUT-2, PROG-ONESHOT-9)' );
	unlike( $words->{out}, qr/\Q$text\E/,
		'the standard output of show -w holds no word '
		    . '(PROG-OUTPUT-4)' );

	# The code, on no option. The words stand behind the code, so
	# the terminal of this step holds no word of them.
	my @render = $t->terminal($code);
	is( scalar @render, $ROWS,
		"the default output of a mnemonic is $ROWS lines of half "
		    . 'blocks (PROG-OUTPUT-2, PROG-QR-9)' )
	    or diag( join "\n", @render );
	is( scalar( grep {
			/\A(?:$LIGHT){$QUIET}(?:$HALF){25}(?:$LIGHT){$QUIET}\z/
		} @render ),
		$ROWS,
		'each line holds 25 modules, and a quiet zone of 4 light '
		    . 'modules stands on each side of them (PROG-QR-9)' )
	    or diag( join "\n", map { unpack 'H*', $_ } @render );
	my @edge = @render == $ROWS ? @render[ 0, 1, -2, -1 ] : ();
	is( scalar( grep { /\A(?:$LIGHT){$SIDE}\z/ } @edge ),
		4,
		'the quiet zone takes two lines of light modules above the '
		    . 'code, and two lines below it (PROG-QR-9)' );
	unlike( join( "\n", @render ), qr/\Q$text\E/,
		'the default output holds no word of the mnemonic '
		    . '(PROG-OUTPUT-2)' );
	like( $code->{out}, qr/^type: mnemonic$/m,
		'show prints the metadata of the entry (PROG-ONESHOT-9)' );
	unlike( $code->{out}, qr/\xe2\x96/,
		'the standard output of show holds no half block '
		    . '(PROG-OUTPUT-4)' );

	return;
};
