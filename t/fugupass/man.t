#!/usr/bin/env perl
# ex:ts=8 sw=4:
# The manual pages (PROG-BUILD-2). mandoc -Tlint must report no
# warning and no error on each page under src, and it must exit 0.
# The pages are hand-written mdoc, so a defect of a macro shows
# here and not in a terminal of a person.
#
# The pages cross-reference pages of the OpenBSD base system, such
# as pledge(2), and a host that is not OpenBSD holds no such page.
# mandoc reports such a reference at the style level, so the lint
# takes the warning level: a macro defect fails, and a cross
# reference does not.

use v5.34;
use warnings;
use experimental 'signatures';
no feature qw(indirect multidimensional bareword_filehandles);
use Test::More;
use File::Find ();
use IPC::Open3 qw(open3);
use Symbol     qw(gensym);
use FindBin    qw($RealBin);

my $root = "$RealBin/../..";
chdir $root or BAIL_OUT("chdir $root: $!");

# mandoc is a test dependency of the Linux runner, and the base
# system of macOS holds it. Without it, no page can be linted here.
my ($mandoc) = grep { -x } map { "$_/mandoc" } split /:/, $ENV{PATH} // q{};
plan skip_all => 'mandoc is absent' unless defined $mandoc;

my @pages;
File::Find::find(
	sub {
		push @pages, $File::Find::name if -f && /\.[1-9]\z/;
		return;
	},
	'src'
);
@pages = sort @pages;

ok( scalar @pages, 'the tree holds at least one manual page' );

for my $page (@pages) {
	my $fault = gensym;
	my $pid   = open3(
		my $in,   my $out, $fault,    $mandoc,
		'-Tlint', '-W',    'warning', $page
	);
	close $in;

	local $/ = undef;
	my $output = <$out>;
	my $report = <$fault>;
	waitpid $pid, 0;
	my $status = $? >> 8;
	close $out;
	close $fault;

	is( ( $output // q{} ) . ( $report // q{} ),
		q{}, "mandoc -Tlint reports nothing on $page" );
	is( $status, 0, "mandoc -Tlint exits 0 on $page" );
}

done_testing();
