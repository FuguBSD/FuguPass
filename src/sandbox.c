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
 * the pledge call. main() of fugupass.c sets RLIMIT_CORE to zero
 * before it calls this file (SEC-MEMORY-3).
 *
 * The path of the vault comes from the command line, and the path
 * of a helper comes from helper.h, so those paths stand outside the
 * table below. helper.h gives the path of each helper program, so
 * the list of the sandbox and the list of the child runs agree.
 *
 * PROG-SPLIT-10 derives the paths of the Perl runtime of the
 * interface process, and this file carries no derived path yet.
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <stddef.h>
#include <unistd.h>

#include "helper.h"
#include "http.h"
#include "sandbox.h"

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

	/* The resolver files of a name lookup. */
	{ "/etc/resolv.conf",		"r" },
	{ "/etc/hosts",			"r" },
	{ "/etc/services",		"r" },

	/* The trust anchors of a https oracle (PROG-SPLIT-12). */
	{ HTTP_CA_FILE,			"r" }
};

int
sandbox_enter(const char *vault)
{
	const char	*path;
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
	for (which = 0; which < HELPER_MAX; which++) {
		if ((path = helper_path((enum helper)which)) == NULL) {
			errno = EINVAL;
			return -1;
		}
		if (unveil(path, "x") == -1 && errno != ENOENT)
			return -1;
	}
	if (unveil(NULL, NULL) == -1)
		return -1;
	if (pledge(SANDBOX_PROMISES, NULL) == -1)
		return -1;
	return 0;
}
