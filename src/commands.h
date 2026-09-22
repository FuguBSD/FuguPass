/*
 * Copyright (c) 2026 Dick Olsson <hi@senzilla.io>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * The six commands of the session: ls, show, add, gen, totp and
 * audit (PROG-REPL-3). One table holds them, and each row holds one
 * command line and one function.
 *
 * commands_run() is the one path of a command. The subcommand frame
 * reaches it through commands_oneshot(), and the interface process
 * reaches it with the session of that session (PROG-ONESHOT-1,
 * PROG-ONESHOT-2). A command takes the open session of session.h,
 * and it sends no oracle request of its own.
 *
 * Each command writes its records to one sink, one record per line,
 * with no decoration (PROG-ONESHOT-3, PROG-ONESHOT-9). The sink is
 * the standard output, and commands_sink() gives the reply pipe of
 * a session in place of it (PROG-IFACE-13). A secret goes to the
 * terminal, and no record holds one (PROG-OUTPUT-1, PROG-OUTPUT-4).
 * Every report of a failure goes to the standard error.
 *
 * ls reads the open index alone, and it sends no request. show and
 * totp each take one quorum reveal, and audit takes one reveal per
 * entry (PROG-REPL-4). add and gen each consume one pool slot, and
 * the consumption is one quorum event (ENTRY-POOL-4).
 */

#ifndef COMMANDS_H
#define COMMANDS_H

#include "session.h"

/*
 * One command (PROG-REPL-3). name is the command name, and args is
 * the options and the arguments of it, for a usage line. run takes
 * the open session, and the argument list of the command, with the
 * command name at argv[0].
 *
 * The last row of the table holds a NULL name.
 */
struct commands_cmd {
	const char	*name;
	const char	*args;
	int		 (*run)(struct session *, int, char *[]);
};

extern const struct commands_cmd	commands_table[];

/*
 * commands_sink(fn):
 *	Send each output record of a command to fn, one call per
 *	record, and with no line feed in a record (PROG-IFACE-13).
 *	iface.c gives the sink of a session, and that sink writes one
 *	reply line of the interface protocol (PROG-IFACE-11).
 *
 *	A NULL argument gives the records back to the standard
 *	output, and a one-shot subcommand takes them there
 *	(PROG-ONESHOT-3).
 *
 *	A secret takes no sink: it goes to the terminal
 *	(PROG-OUTPUT-1).
 */
void	commands_sink(void (*)(const char *));

/*
 * commands_run(s, argc, argv):
 *	Run the command of argv[0] on the open session s. The call
 *	gives 0 for a command that passes, and -1 for a command that
 *	fails and for a name that the table does not hold.
 *
 *	This call is the one path of a command, and a one-shot
 *	subcommand and a command of the interactive session both
 *	take it (PROG-ONESHOT-2).
 */
int	commands_run(struct session *, int, char *[]);

/*
 * commands_oneshot(vault, argc, argv):
 *	Open the vault directory vault, run the command of argv[0]
 *	on that session, and close the session (PROG-ONESHOT-1).
 *
 *	The call gives the exit status of the subcommand: 0 for a
 *	command that passes, and 1 for every failure. The unlock
 *	reports its own failure (PROG-REPL-1).
 */
int	commands_oneshot(const char *, int, char *[]);

#endif /* COMMANDS_H */
