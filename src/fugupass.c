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
 * main() sets RLIMIT_CORE to zero first, so no crash of this
 * program writes a secret to a core file (SEC-MEMORY-3). It enters
 * the sandbox next, before the subcommand runs (PROG-SPLIT-3).
 *
 * sandbox.c holds the unveil list and the pledge call, and
 * src/regress/sandbox.c makes the same call as main(). The call
 * makes the vault directory, because unveil(2) refuses a path that
 * no file holds. The ceremony makes the machine subdirectory inside
 * the vault directory (VAULT-LAYOUT-4).
 *
 * The frame dispatches on the first argument after the options, and
 * the table below holds one row of each subcommand (PROG-ONESHOT-4).
 * An unknown subcommand gives the usage and the status 2.
 * PROG-IFACE-1 gives the interactive session to a run with no
 * subcommand, and that session is not in this program yet. Such a
 * run gives the usage as well.
 *
 * A subcommand reads the options and the arguments of its own
 * command line, and ceremony.c holds the steps of a ceremony
 * (PROG-ONESHOT-5, PROG-ONESHOT-6, CER-CREATE). A wrong command
 * line of a subcommand gives the reason, the usage and the status
 * 2.
 *
 * The passphrase enters here, through readpassphrase(3) of the
 * terminal (SEC-MEMORY-4, PROG-IFACE-3). No argument and no
 * environment variable carries it.
 */

#include <sys/param.h>
#include <sys/resource.h>

#include <err.h>
#include <limits.h>
#include <readpassphrase.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ceremony.h"
#include "derive.h"
#include "fugupass.h"
#include "sandbox.h"

/* The vault directory of a run without the -d option, under HOME. */
#define VAULT_DIR	".fugupass"

/* One subcommand of the frame (PROG-ONESHOT-4). */
struct subcommand {
	const char	*name;
	const char	*args;	/* the options and the arguments of it */
	int		 (*run)(int, char *[], const char *);
};

static int	 cmd_create(int, char *[], const char *);
static void	 usage(void);
static int	 vault_dir(const char *, char *, size_t);

/*
 * The subcommands of this program. usage() names each one, and
 * main() takes the first argument that matches a name here.
 */
static const struct subcommand commands[] = {
	{ "create",	"-k threshold -m machine -r rounds oracle ...",
	    cmd_create }
};

/*
 * usage():
 *	The usage lines, to the standard error, and the status 2.
 *	The table above gives one line of each subcommand.
 */
static void
usage(void)
{
	size_t	 i;

	for (i = 0; i < nitems(commands); i++)
		fprintf(stderr, "%s %s [-d directory] %s %s\n",
		    i == 0 ? "usage:" : "      ", getprogname(),
		    commands[i].name, commands[i].args);
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
 * cmd_create(argc, argv, vault):
 *	The vault creation ceremony of the vault directory vault
 *	(CER-CREATE). This function reads the command line of the
 *	subcommand, and ceremony.c runs the nine steps
 *	(PROG-ONESHOT-5, PROG-ONESHOT-6).
 *
 *	The threshold comes from -k, the machine name from -m, and
 *	the round count of bcrypt_pbkdf(3) from -r. Each argument
 *	after the options holds one position of the ordered oracle
 *	set: the static public key hex, one space, then the URL. The
 *	first argument is position 1 (ORC-PROVISION-1,
 *	ORC-PROVISION-5).
 *
 *	The config reader holds the full bounds of the threshold and
 *	of the oracle set (VAULT-CONFIG-6). This function holds the
 *	form of each number, and the two gates below.
 *
 *	getopt(3) already ran over the options of the program, so
 *	this second pass resets it.
 */
static int
cmd_create(int argc, char *argv[], const char *vault)
{
	struct ceremony_create	 arg;
	const char		*errstr;
	int			 ch;

	memset(&arg, 0, sizeof(arg));
	arg.vault = vault;

	optreset = 1;
	optind = 1;
	while ((ch = getopt(argc, argv, "k:m:r:")) != -1) {
		switch (ch) {
		case 'k':
			arg.threshold = (unsigned int)strtonum(optarg, 1,
			    DERIVE_ORACLE_MAX, &errstr);
			if (errstr != NULL) {
				warnx("the threshold is %s", errstr);
				usage();
			}
			break;
		case 'm':
			arg.machine = optarg;
			break;
		case 'r':
			arg.rounds = (unsigned int)strtonum(optarg, 1,
			    INT_MAX, &errstr);
			if (errstr != NULL) {
				warnx("the round count is %s", errstr);
				usage();
			}
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1 || arg.threshold == 0 || arg.machine == NULL ||
	    arg.rounds == 0) {
		warnx("the -k, -m and -r options and the oracle set are "
		    "mandatory");
		usage();
	}

	/*
	 * These two gates run before the plate scan, so a wrong
	 * command line costs no scan. The config reader holds the
	 * full rule of each one, because a retired position counts
	 * against the threshold there (VAULT-CONFIG-6).
	 */
	if (derive_machine_check(arg.machine, strlen(arg.machine)) != 0) {
		warnx("the machine name takes lowercase letters, digits "
		    "and hyphens, 1 to %d bytes", DERIVE_MACHINE_MAX);
		usage();
	}
	if (arg.threshold > (unsigned int)argc) {
		warnx("the threshold is above the count of the oracle set");
		usage();
	}

	arg.oracle = (const char *const *)argv;
	arg.count = (unsigned int)argc;

	return ceremony_create(&arg) == 0 ? 0 : 1;
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
	 * subcommand makes no vault directory. The sandbox comes
	 * before the command line of the subcommand, so a rejected
	 * option of a subcommand makes that directory.
	 */
	for (i = 0; i < nitems(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			break;
	}
	if (i == nitems(commands))
		usage();

	if (vault_dir(dir, vault, sizeof(vault)) != 0)
		errx(1, "no vault directory");
	if (sandbox_enter(vault) != 0)
		err(1, "sandbox");

	return commands[i].run(argc, argv, vault);
}
