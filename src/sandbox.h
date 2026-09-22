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
 * The sandbox of the core process: the unveil(2) list, and the
 * pledge(2) call after it (PROG-SPLIT-3).
 *
 * main() of fugupass.c makes one call of sandbox_enter(), and
 * src/regress/sandbox.c makes the same call. The list therefore has
 * one implementation, and the test reads the list that the program
 * runs under.
 */

#ifndef SANDBOX_H
#define SANDBOX_H

/* The promises of the core process (PROG-SPLIT-3). */
#define SANDBOX_PROMISES \
	"stdio rpath wpath cpath flock proc exec inet dns tty"

/*
 * The promises of a child process of the core (PROG-SPLIT-3).
 * sandbox_enter() gives this value to pledge(2) as the
 * execpromises argument, and the unveil list of this process
 * reaches a child of execve(2) through that argument alone. The
 * child of a NULL argument holds the whole file system and no
 * pledge, so the list of a NULL argument restricts no child.
 *
 * A child reduces a promise set and never widens one, so this value
 * holds every promise that a child pledges: tty of fugupass-repl
 * (PROG-SPLIT-7). rpath carries the runtime files of each child,
 * and the program text of the interface process.
 *
 * The value holds no video, and no row of the unveil list carries
 * /dev/video*. PROG-SPLIT-4 adds the promise and the rows together
 * with fugupass-scan. A promise with no path behind it grants
 * nothing, and it widens the set of every other child.
 *
 * prot_exec carries the XS modules of the interpreter of the
 * interface process: the loader of such a module maps it with
 * PROT_EXEC, and a child without that promise dies on the first
 * one.
 *
 * The value holds no wpath and no cpath, so a child reads a file of
 * the list and writes none. It holds no proc and no exec, so a
 * child starts no process. The lock of sandbox_enter() reaches a
 * child as well: an unveil(2) call of a child gives EPERM, and no
 * child widens the list of this process (PROG-SPLIT-4).
 */
#define SANDBOX_EXEC_PROMISES \
	"stdio rpath prot_exec tty"

/*
 * sandbox_enter(vault):
 *	The unveil list of the vault directory vault, and the pledge
 *	of the core process (PROG-SPLIT-3). The call makes the vault
 *	directory, because unveil(2) refuses a path that no file
 *	holds.
 *
 *	The list holds the vault directory with the rwc permission,
 *	/dev/tty with rw, the interface program with rx, the two
 *	other helper programs with x, and the runtime files, the
 *	resolver files and the trust anchors of libtls with r
 *	(PROG-SPLIT-12).
 *
 *	The pledge call names SANDBOX_PROMISES and
 *	SANDBOX_EXEC_PROMISES, so the list holds for each child of
 *	this process as well.
 *
 *	A path of the list that no file holds leaves ENOENT, and the
 *	list then holds one path less. The process stays inside the
 *	list, so an absent helper program and an absent resolver file
 *	each restrict this process more.
 *
 *	The call gives 0, and -1 on every other failure. errno then
 *	names the failed call, and the caller stops the program.
 */
int	sandbox_enter(const char *);

#endif /* SANDBOX_H */
