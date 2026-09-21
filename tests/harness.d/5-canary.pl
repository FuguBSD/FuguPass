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

# The canary leg (ORC-CANARY-6, ORC-CANARY-7, ORC-CANARY-8).
#
# A canary enrollment reads the passphrase twice, enrolls the canary
# record, and proves it with one immediate get_pin. It then seals
# the canary check value under the canary check seal key, and it
# writes the seal. The state ok therefore proves the enrollment, the
# round trip and the seal together.
#
# A mistyped second read stops the enrollment before the first
# request. The driver reports that with the word error, because one
# value of the record client reports every local failure. The leg
# therefore also proves that the vault holds no seal.
#
# The third case is a failure after the set_pin. A directory at the
# path of the canary seal stops the seal write, and every step
# before that write passes: another step gives the state of the
# oracle, and the word error names a local failure alone. The
# set_pin therefore replaced the canary mask, and that mask killed
# this machine's index wrap of the oracle. The wrap file must go,
# because the absent file is the one detectable dead state
# (ORC-CANARY-8).

use v5.36;

return sub ($t)
{
	my $vault = $t->vault('canary');

	is( $t->file_exists( $t->seal($vault) ),
		0, 'a new vault holds no canary seal' );

	my $enroll = $t->canary($vault);
	is( $enroll->{state}, 'ok',
		'the canary enrollment and its round trip pass '
		    . '(ORC-CANARY-6)' );
	is( $t->file_exists( $t->seal($vault) ),
		1, 'the enrollment wrote the canary seal (ORC-CANARY-11)' );

	my $name = $t->canary_record($vault);
	like( $t->read_file( $t->counters($vault) ),
		qr/^\Q$name\E: [0-9]+$/m,
		'the counters file names the canary record (ORC-COUNTER-2)' );

	is( $t->canary($vault)->{state},
		'ok', 'the client re-enrolls the canary (ORC-CANARY-5)' );

	my $typo = $t->vault('canary-typo');
	my $stop = $t->canary( $typo, pass => [ 'right', 'other' ] );
	is( $stop->{state}, 'error',
		'a mistyped second read stops the enrollment '
		    . '(ORC-CANARY-6)' );
	is( $t->file_exists( $t->seal($typo) ),
		0, 'the stopped enrollment wrote no canary seal' );

	# The vault of the first case holds the counters of the
	# canary record, so this case takes that vault again.
	my $dead = $t->index_wrap($vault);
	$t->write_file( $dead, 'dead' );
	$t->remove_file( $t->seal($vault) );
	$t->make_dir( $t->seal($vault) );

	my $after = $t->canary($vault);
	is( $after->{state}, 'error',
		'a canary seal write that fails stops the enrollment' );
	is( $t->file_exists($dead),
		0, 'the failure after the set_pin took the dead index '
		    . 'wrap away (ORC-CANARY-8)' );

	return;
};
