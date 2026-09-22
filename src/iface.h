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
 * The interactive session of the core process: the spawn of the
 * interface process, the two pipes, the request loop, and the lock.
 * iface.c holds the implementation.
 *
 * A run of fugupass with no subcommand starts the session, and
 * main() of fugupass.c makes the one call of this file
 * (PROG-IFACE-1).
 *
 * The session runs each command through commands_run() of
 * commands.h, so a one-shot subcommand and a command of the session
 * run the same core paths (PROG-ONESHOT-2).
 */

#ifndef IFACE_H
#define IFACE_H

/*
 * The seconds of the idle timeout of a session (PROG-REPL-11). A
 * config file that holds no lock-timeout field takes this value, and
 * ceremony.c writes it into the config file of a creation
 * (VAULT-CONFIG-1).
 */
#define IFACE_LOCK_TIMEOUT_DEFAULT	300

/*
 * iface_session(vault):
 *	Run one interactive session of the vault directory vault
 *	(PROG-IFACE-1). The call unlocks the vault, it spawns the
 *	interface process, and it runs one command of each request
 *	line (PROG-REPL-1, PROG-IFACE-10, PROG-IFACE-11).
 *
 *	The session locks at the end of the request pipe, and after
 *	the idle timeout of the config file (PROG-REPL-7). The lock
 *	clears every session secret, and the closed reply pipe ends
 *	the interface process (SEC-MEMORY-1, PROG-IFACE-6).
 *
 *	The call gives the exit status of the program: 0 for a
 *	session that ends with a lock, and 1 for a failed unlock, a
 *	failed spawn, and an interface process that exits with
 *	another status.
 */
int	iface_session(const char *);

#endif /* IFACE_H */
