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
 * The sandbox of the core process. sandbox.h states the interface.
 *
 * The order is the order of PROG-SPLIT-3: every unveil call, then
 * the pledge call. main() of fugupass.c calls sandbox_nocore() of
 * this file before sandbox_enter(), so the core limit is the first
 * act of the program (SEC-MEMORY-3).
 *
 * The pledge call names SANDBOX_EXEC_PROMISES as its execpromises
 * argument, and that argument carries the list below to each child
 * of this process. A child of a NULL argument holds the whole file
 * system, and the list below then restricts no child. sandbox.h
 * states the promises of a child.
 *
 * The path of the vault comes from the command line, and the path
 * of a helper comes from helper.h, so those paths stand outside the
 * table below. helper.h gives the path of each helper program, so
 * the list of the sandbox and the list of the child runs agree.
 *
 * unveil_paths.h holds the paths of the Perl runtime of the
 * interface process, and the build step of src/lib/Makefile writes
 * that header (PROG-SPLIT-10). The resolver files and the service
 * tables of PROG-SPLIT-3 come from that list as well, because
 * Fugu::Sandbox->system_paths names them.
 *
 * The video devices of the plate scan stand outside the table as
 * well. unveil(2) takes no glob, so unveil_video() composes the
 * path of each device (PROG-SPLIT-13).
 */

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include "helper.h"
#include "http.h"
#include "sandbox.h"
#include "unveil_paths.h"

/*
 * The video devices of the plate scan (PROG-SPLIT-4,
 * PROG-SPLIT-13). VIDEO_PATH is the path of the first device, and
 * the numbered devices take one unit each, below VIDEO_UNITS. The
 * scan helper opens one device for a read, so each device takes the
 * r permission (PROG-SCAN-9).
 */
#define VIDEO_PATH	"/dev/video"
#define VIDEO_PERM	"r"
#define VIDEO_UNITS	10

/* One path of the unveil list, with the permissions of that path. */
struct unveil_path {
	const char	*path;
	const char	*perm;
};

/*
 * The unveil list, without the vault directory and without the
 * three helper programs (PROG-SPLIT-3).
 */
static const struct unveil_path unveil_list[] = {
	/* The terminal of the passphrase read (SEC-MEMORY-4). */
	{ "/dev/tty",			"rw" },

	/* The runtime files of a child program. */
	{ "/usr/libexec/ld.so",		"r" },
	{ "/var/run/ld.so.hints",	"r" },
	{ "/usr/lib",			"r" },
	{ "/usr/local/lib",		"r" },

	/* The trust anchors of a https oracle (PROG-SPLIT-12). */
	{ HTTP_CA_FILE,			"r" },

	/*
	 * The library tree of the perl of the interface process, and
	 * the read-only system paths that the resolver files and the
	 * service tables of PROG-SPLIT-3 belong to (PROG-SPLIT-10).
	 */
	UNVEIL_PATHS_DERIVED
};

int
sandbox_nocore(void)
{
	struct rlimit	 limit, nocore = { 0, 0 };

	/*
	 * The core limit comes first, before every other act of the
	 * program: no crash of it writes a secret to a core file
	 * (SEC-MEMORY-3).
	 *
	 * A child of the core process inherits the two zero limits of
	 * that process, and the execpromises of it hold no proc
	 * promise (PROG-SPLIT-3). setrlimit(2) needs that promise, and
	 * the kernel kills a child that calls it. The call below
	 * therefore reads the two limits first, and it calls
	 * setrlimit(2) only when one of them is not zero. getrlimit(2)
	 * needs the stdio promise alone (SEC-MEMORY-3).
	 *
	 * The zero of the soft limit stops every core file, and the
	 * zero of the hard limit stops a raise of the soft one.
	 */
	if (getrlimit(RLIMIT_CORE, &limit) == -1)
		return -1;
	if (limit.rlim_cur == 0 && limit.rlim_max == 0)
		return 0;
	if (setrlimit(RLIMIT_CORE, &nocore) == -1)
		return -1;
	return 0;
}

/*
 * unveil_video():
 *	Unveil each video device of PROG-SPLIT-13. unveil(2) takes
 *	no glob, so this call names VIDEO_PATH and one path of each
 *	unit below VIDEO_UNITS.
 *
 *	A device that the machine does not hold gives ENOENT, and the
 *	list then holds one path less. The call gives 0, and -1 on
 *	every other failure of unveil(2).
 */
static int
unveil_video(void)
{
	char	 path[PATH_MAX];
	int	 n, unit;

	if (unveil(VIDEO_PATH, VIDEO_PERM) == -1 && errno != ENOENT)
		return -1;
	for (unit = 0; unit < VIDEO_UNITS; unit++) {
		n = snprintf(path, sizeof(path), "%s%d", VIDEO_PATH, unit);
		if (n < 0 || (size_t)n >= sizeof(path)) {
			errno = ENAMETOOLONG;
			return -1;
		}
		if (unveil(path, VIDEO_PERM) == -1 && errno != ENOENT)
			return -1;
	}
	return 0;
}

int
sandbox_enter(const char *vault)
{
	const char	*path, *perm;
	size_t		 i;
	int		 which;

	if (vault == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (mkdir(vault, S_IRWXU) == -1 && errno != EEXIST)
		return -1;
	if (unveil(vault, "rwc") == -1)
		return -1;
	for (i = 0; i < nitems(unveil_list); i++) {
		if (unveil(unveil_list[i].path, unveil_list[i].perm) == -1 &&
		    errno != ENOENT)
			return -1;
	}
	if (unveil_video() != 0)
		return -1;
	for (which = 0; which < HELPER_MAX; which++) {
		if ((path = helper_path((enum helper)which)) == NULL) {
			errno = EINVAL;
			return -1;
		}
		/*
		 * The interface process is Perl, and the kernel gives
		 * the path of the program to the interpreter. The
		 * interpreter reads the program text, so that one path
		 * takes the r permission as well (PROG-SPLIT-7). A
		 * compiled helper runs with the x permission alone.
		 */
		perm = (enum helper)which == HELPER_REPL ? "rx" : "x";
		if (unveil(path, perm) == -1 && errno != ENOENT)
			return -1;
	}
	if (unveil(NULL, NULL) == -1)
		return -1;
	if (pledge(SANDBOX_PROMISES, SANDBOX_EXEC_PROMISES) == -1)
		return -1;
	return 0;
}
