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
 * fugupass, the core process: the sandbox, the subcommand frame,
 * and the passphrase read (PROG-SPLIT-1). fugupass.h states the two
 * functions that a subcommand takes from this file.
 *
 * main() holds the order of the sandbox. It sets RLIMIT_CORE to
 * zero first, so no crash of this program writes a secret to a core
 * file (SEC-MEMORY-3). It makes every unveil call next, and it
 * pledges last (PROG-SPLIT-3).
 *
 * The unveil list holds the vault directory, the terminal, the
 * three helper programs, the runtime files of a child, the resolver
 * files, and the trust anchors of libtls (PROG-SPLIT-3,
 * PROG-SPLIT-12). helper.h gives the path of each program, so the
 * list of the sandbox and the list of the child runs agree.
 * PROG-SPLIT-10 derives the paths of the Perl runtime of the
 * interface process, and this file carries no derived path yet.
 *
 * unveil(2) refuses a path that no file holds. main() therefore
 * makes the vault directory before the list, and a machine without
 * one of the other paths gets a list that is one path shorter. The
 * ceremony makes the machine subdirectory inside the vault
 * directory (VAULT-LAYOUT-4).
 *
 * The frame dispatches on the first argument after the options, and
 * the table below holds one row of each subcommand (PROG-ONESHOT-4).
 * An unknown subcommand gives the usage line and the status 2.
 * PROG-IFACE-1 gives the interactive session to a run with no
 * subcommand, and that session is not in this program yet. Such a
 * run gives the usage line as well.
 *
 * The passphrase enters here, through readpassphrase(3) of the
 * terminal (SEC-MEMORY-4, PROG-IFACE-3). No argument and no
 * environment variable carries it.
 */

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <readpassphrase.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fugupass.h"
#include "helper.h"
#include "http.h"

/* The vault directory of a run without the -d option, under HOME. */
#define VAULT_DIR	".fugupass"

/* The promises of the core process (PROG-SPLIT-3). */
#define PROMISES	"stdio rpath wpath cpath flock proc exec inet dns tty"

/* One subcommand of the frame (PROG-ONESHOT-4). */
struct subcommand {
	const char	*name;
	int		 (*run)(int, char *[], const char *);
};

/* One path of the unveil list, with the permissions of that path. */
struct unveil_path {
	const char	*path;
	const char	*perm;
};

static int	 cmd_create(int, char *[], const char *);
static int	 sandbox(const char *);
static void	 usage(void);
static int	 vault_dir(const char *, char *, size_t);

/*
 * The subcommands of this program. usage() names each one, and
 * main() takes the first argument that matches a name here.
 */
static const struct subcommand commands[] = {
	{ "create",	cmd_create }
};

/*
 * The unveil list, without the vault directory and without the
 * three helper programs (PROG-SPLIT-3). sandbox() adds those paths,
 * because a path of the vault comes from the command line, and a
 * path of a helper comes from helper.h.
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

/*
 * usage():
 *	The usage line, to the standard error, and the status 2. The
 *	line names each subcommand of the table above.
 */
static void
usage(void)
{
	size_t	 i;

	fprintf(stderr, "usage: %s [-d directory] ", getprogname());
	for (i = 0; i < nitems(commands); i++)
		fprintf(stderr, "%s%s", i == 0 ? "" : " | ", commands[i].name);
	fprintf(stderr, "\n");
	exit(2);
}

/*
 * vault_dir(opt, buf, bufsize):
 *	The path of the vault directory, to the bufsize bytes at buf.
 *	opt is the value of the -d option, or NULL. A run without
 *	that option takes the directory VAULT_DIR of the home
 *	directory.
 *
 *	The call gives -1 for a home directory that no environment
 *	names, for a relative home directory, and for a path that
 *	bufsize does not take.
 */
static int
vault_dir(const char *opt, char *buf, size_t bufsize)
{
	const char	*home;
	int		 len;

	if (opt != NULL)
		len = snprintf(buf, bufsize, "%s", opt);
	else {
		if ((home = getenv("HOME")) == NULL || home[0] != '/')
			return -1;
		len = snprintf(buf, bufsize, "%s/%s", home, VAULT_DIR);
	}
	if (len < 0 || (size_t)len >= bufsize)
		return -1;
	return 0;
}

/*
 * sandbox(vault):
 *	The unveil list of the vault directory vault, and the pledge
 *	of the core process (PROG-SPLIT-3). The call makes the vault
 *	directory, because unveil(2) refuses a path that no file
 *	holds.
 *
 *	A path of the list that no file holds leaves ENOENT, and the
 *	list then holds one path less. The process stays inside the
 *	list, so an absent helper program and an absent resolver file
 *	each restrict this process more.
 *
 *	The call gives -1 on every other failure, and the caller
 *	stops the program then.
 */
static int
sandbox(const char *vault)
{
	const char	*path;
	size_t		 i;
	int		 which;

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
		if ((path = helper_path((enum helper)which)) == NULL)
			return -1;
		if (unveil(path, "x") == -1 && errno != ENOENT)
			return -1;
	}
	if (unveil(NULL, NULL) == -1)
		return -1;
	if (pledge(PROMISES, NULL) == -1)
		return -1;
	return 0;
}

/*
 * cmd_create(argc, argv, vault):
 *	The vault creation ceremony of the vault directory vault
 *	(CER-CREATE). The ceremony is not in this program yet, and
 *	this function reports that. The next change gives the steps
 *	to ceremony.c, and this function calls that file.
 */
static int
cmd_create(int argc, char *argv[], const char *vault)
{
	(void)argc;
	(void)argv;
	(void)vault;

	warnx("create: the ceremony is not in this program yet");
	return 1;
}

int
fugupass_passphrase(const char *prompt, char *buf, size_t bufsize)
{
	size_t	 len;

	if (buf == NULL || bufsize == 0)
		return -1;

	/*
	 * RPP_REQUIRE_TTY takes the passphrase from /dev/tty, and it
	 * gives NULL for a process with no terminal. A pipe and a
	 * file therefore carry no passphrase (SEC-MEMORY-4).
	 */
	if (readpassphrase(prompt, buf, bufsize, RPP_REQUIRE_TTY) == NULL) {
		explicit_bzero(buf, bufsize);
		return -1;
	}

	/*
	 * readpassphrase(3) drops the bytes after the room of the
	 * buffer, so a full buffer can hold a part of a passphrase.
	 */
	len = strlen(buf);
	if (len == 0 || len + 1 == bufsize) {
		explicit_bzero(buf, bufsize);
		return -1;
	}
	return 0;
}

int
fugupass_passphrase_new(char *buf, size_t bufsize)
{
	char	 again[FUGUPASS_PASS_MAX];
	size_t	 len;
	int	 rv;

	if (bufsize == 0 || bufsize > sizeof(again))
		return -1;
	if ((rv = fugupass_passphrase("Passphrase: ", buf, bufsize)) != 0)
		return rv;
	if ((rv = fugupass_passphrase("Passphrase again: ", again,
	    bufsize)) != 0) {
		explicit_bzero(buf, bufsize);
		return rv;
	}

	len = strlen(buf);
	if (len != strlen(again) || timingsafe_bcmp(buf, again, len) != 0) {
		explicit_bzero(buf, bufsize);
		rv = FUGUPASS_EMISMATCH;
	}
	explicit_bzero(again, sizeof(again));
	return rv;
}

int
main(int argc, char *argv[])
{
	struct rlimit	 nocore = { 0, 0 };
	char		 vault[PATH_MAX];
	const char	*dir = NULL;
	size_t		 i;
	int		 ch;

	/*
	 * The first call of main(), before every other one: no crash
	 * of this program writes a secret to a core file
	 * (SEC-MEMORY-3).
	 */
	if (setrlimit(RLIMIT_CORE, &nocore) == -1)
		err(1, "setrlimit");

	/*
	 * A helper that exits early closes the pipe of its standard
	 * input, and a write to that pipe raises SIGPIPE (helper.h).
	 */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		err(1, "signal");

	while ((ch = getopt(argc, argv, "d:")) != -1) {
		switch (ch) {
		case 'd':
			dir = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage();

	/*
	 * The frame reads the table before the sandbox, so a wrong
	 * subcommand makes no vault directory.
	 */
	for (i = 0; i < nitems(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			break;
	}
	if (i == nitems(commands))
		usage();

	if (vault_dir(dir, vault, sizeof(vault)) != 0)
		errx(1, "no vault directory");
	if (sandbox(vault) != 0)
		err(1, "sandbox");

	return commands[i].run(argc, argv, vault);
}
