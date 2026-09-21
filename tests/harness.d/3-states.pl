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

# The states leg (ORC-REVEAL-6, ORC-REVEAL-8).
#
# The client holds the transport failure, the HTTP error and the
# junk answer apart, and each one takes a report of its own. This
# leg drives the three against the counterparty, and it proves that
# no two of them share a report.
#
# A stopped counterparty gives the transport failure. A set_pin
# below the stored counter gives the HTTP error: the oracle rejects
# a counter that is not strictly greater, and a set_pin carries no
# junk path (FuguOracle OPS-SET-2, FuguOracle OPS-SET-7). A wrong
# passphrase gives the junk answer.
#
# A wrong static key gives the HTTP error as well, and not the
# oracle-authentication failure of ORC-REVEAL-8. The request travels
# under a key that the client derives from the static key, so a
# counterparty with another static key cannot read the request, and
# it answers a status other than 200. A 200 answer with a broken MAC
# needs a counterparty that breaks it, and no conforming
# counterparty does. This leg therefore proves that a provisioning
# fault reaches no junk report and no success, and the
# oracle-authentication state stays without coverage here.

use v5.36;

return sub ($t)
{
	my $vault = $t->vault('states');
	is( $t->enroll($vault)->{state}, 'ok', 'the record enrolls' );

	# The transport failure (ORC-REVEAL-6).
	$t->stop;
	my $down = $t->reveal($vault);
	$t->start;
	is( $down->{state}, 'transport',
		'a stopped counterparty gives the transport failure' );
	is( $t->reveal($vault)->{state},
		'ok', 'the record answers again after the restart' );

	# The HTTP error. An enrollment persists the stored counter
	# 0 (FuguOracle OPS-SET-4), and a reveal advances it, so the
	# forged high counter goes on a reveal. The reset file then
	# sends a lower one on the next set_pin.
	my $http = $t->vault('states-http');
	is( $t->enroll($http)->{state}, 'ok', 'the second record enrolls' );
	$t->write_file( $t->counters($http),
		$t->record($http) . ': ' . $t->high_counter );
	is( $t->reveal($http)->{state},
		'ok', 'the second record reveals with a high counter' );
	$t->write_file( $t->counters($http), $t->record($http) . ': 1' );
	my $status = $t->enroll($http);
	is( $status->{state}, 'status',
		'an enrollment below the stored counter gives the HTTP error' );

	# The junk answer, from a wrong passphrase.
	my $bad = $t->vault('states-junk');
	is( $t->enroll($bad)->{state}, 'ok', 'the third record enrolls' );
	my $junk = $t->reveal( $bad, pass => ['wrong'] );
	is( $junk->{state}, 'junk', 'a wrong passphrase gives the junk answer' );

	my $foreign =
	    $t->vault( 'states-key', pubkey => $t->foreign_key );
	my $fault = $t->reveal($foreign);
	is( $fault->{state}, 'status',
		'a wrong static key gives the HTTP error, and no junk answer' );

	# Each state takes its own report (ORC-REVEAL-6).
	isnt( $down->{state}, $status->{state},
		'the transport failure and the HTTP error differ' );
	isnt( $down->{state}, $junk->{state},
		'the transport failure and the junk answer differ' );
	isnt( $status->{state}, $junk->{state},
		'the HTTP error and the junk answer differ' );
	for my $case ( $down, $status, $junk, $fault ) {
		isnt( $case->{state}, 'ok',
			"the report $case->{state} is no success" );
	}

	return;
};
