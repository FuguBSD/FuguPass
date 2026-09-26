#!/usr/bin/env perl
# ex:ts=8 sw=4:
# The prohibited claims (SEC-CLAIMS). No manual page and no document
# under docs/ claims coercion resistance, a delayed reveal, a
# velocity alarm, an oracle-side freeze, or an oracle-side rate
# limit (SEC-CLAIMS-1 to SEC-CLAIMS-3). The scan mirrors
# vocabulary.t: a code block and a code span hold names, and a
# record under docs/research/ stays outside the rule, as
# OVW-VOCABULARY-3 states it for that test.
#
# The one sentence that can name a claim is the sentence that
# prohibits it. That sentence leads with the words "No oracle
# operation", as ORC-REVOKE-1 does. A page writes one sentence per
# line, so the scan exempts the line that holds those words, and a
# prohibition sentence that wraps fails here until the author joins
# it.

use v5.34;
use warnings;
use experimental 'signatures';
no feature qw(indirect multidimensional bareword_filehandles);
use Test::More;
use FindBin    qw($RealBin $RealScript);
use File::Spec ();

my $root = "$RealBin/../..";
chdir $root or BAIL_OUT("chdir $root: $!");
my $self = File::Spec->abs2rel( "$RealBin/$RealScript", $root );

# _slurp($path):
#	The whole file as text, or undef when it does not open.
sub _slurp ($path)
{
	open my $fh, '<', $path or return;
	local $/ = undef;
	my $text = <$fh>;
	close $fh;
	return $text;
}

# _blank($text):
#	The line feeds of $text and nothing else, so a removal keeps
#	every line number true.
sub _blank ($text)
{
	return "\n" x ( () = $text =~ /\n/g );
}

# Each claim matches whole, in any letter case, as itself, as a
# plural, and as a verb form.
my @claims = (
	'coercions?', 'freez(?:e|es|ing)',
	'frozen?',    'delayed[ \t]+reveals?',
	'velocity',   'velocities',
	'alarms?',    'rate[ \t-]+limit(?:s|ed|er|ers|ing)?',
);
my $alt         = join '|', @claims;
my $claim       = qr/\b(?:$alt)\b/i;
my $prohibition = qr/\bno oracle operation\b/i;

my @tracked = `git ls-files --cached --others --exclude-standard`;
chomp @tracked;

# A manual page is a file with a section number as its suffix. A
# document is a file under docs/, outside the research records.
my @files =
    grep { $_ ne $self && ( /\.[1-9]\z/ || m{^docs/} ) && !m{^docs/research/} }
    @tracked;
ok(
	scalar( grep { /\.[1-9]\z/ } @files ),
	'the tree holds at least one manual page'
);

my @hits;
for my $path (@files) {
	my $text = _slurp($path) // next;

	# A fenced code block and an inline code span of a document
	# hold names, not words.
	my @lines = split /\n/, $text, -1;
	if ( $path =~ /\.md\z/ ) {
		$text =~ s/^```.*?^```[^\n]*/_blank($&)/msge;
		$text =~ s/`[^`]*`/_blank($&)/ge;
	}
	my $number = 0;
	for my $line ( split /\n/, $text, -1 ) {
		$number++;
		next if $lines[ $number - 1 ] =~ $prohibition;
		push @hits, "$path:$number" if $line =~ $claim;
	}
}
is( "@hits", q{},
	'no manual page and no document claims a prohibited capability' );

done_testing();
