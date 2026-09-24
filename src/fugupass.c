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
 * main() calls sandbox_nocore() of sandbox.h first, so no crash of
 * this program writes a secret to a core file (SEC-MEMORY-3). It
 * enters the sandbox next, before the subcommand runs
 * (PROG-SPLIT-3).
 *
 * sandbox.c holds the core limit, the unveil list and the pledge
 * call, and src/regress/sandbox.c makes the same two calls as
 * main(). The sandbox call makes the vault directory, because
 * unveil(2) refuses a path that no file holds. The ceremony makes
 * the machine subdirectory inside the vault directory
 * (VAULT-LAYOUT-4).
 *
 * The frame dispatches on the first argument after the options,
 * over two tables (PROG-ONESHOT-4). The table below holds the
 * subcommands of this file: the vault creation, the canary
 * re-enrollment, the passphrase change, the resume of an incomplete
 * change, and the pool refill. commands_table of commands.h holds
 * the six commands of the session, and commands_oneshot() runs one
 * of them (PROG-ONESHOT-1, PROG-ONESHOT-2). A name that neither
 * table holds gives the usage and the status 2. A run with no
 * subcommand starts the interactive session of iface.h, and that
 * session runs each command of the interface process
 * (PROG-IFACE-1).
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

#include <err.h>
#include <limits.h>
#include <readpassphrase.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ceremony.h"
#include "change.h"
#include "commands.h"
#include "derive.h"
#include "fugupass.h"
#include "iface.h"
#include "sandbox.h"
#include "session.h"

/* The vault directory of a run without the -d option, under HOME. */
#define VAULT_DIR	".fugupass"

/* One subcommand of the frame (PROG-ONESHOT-4). */
struct subcommand {
	const char	*name;
	const char	*args;	/* the options and the arguments of it */
	int		 (*run)(int, char *[], const char *);
};

static int	 cmd_create(int, char *[], const char *);
static int	 cmd_canary(int, char *[], const char *);
static int	 cmd_passwd(int, char *[], const char *);
static int	 cmd_resume(int, char *[], const char *);
static int	 cmd_refill(int, char *[], const char *);
static void	 usage(void);
static int	 vault_dir(const char *, char *, size_t);

/*
 * The subcommands of this file. usage() names each one, and main()
 * takes the first argument that matches a name here. Neither table
 * of the frame holds a name of the other one.
 */
static const struct subcommand commands[] = {
	{ "create",	"-k threshold -m machine -r rounds [-p slots] "
	    "oracle ...", cmd_create },
	{ "canary",	"oracle", cmd_canary },
	{ "passwd",	"", cmd_passwd },
	{ "resume",	"", cmd_resume },
	{ "refill",	"", cmd_refill }
};

/*
 * usage():
 *	The usage lines, to the standard error, and the status 2.
 *	The two tables of the frame give one line of each subcommand.
 */
static void
usage(void)
{
	const struct commands_cmd	*c;
	const char			*lead = "usage:";
	size_t				 i;

	for (i = 0; i < nitems(commands); i++) {
		fprintf(stderr, "%s %s [-d directory] %s%s%s\n", lead,
		    getprogname(), commands[i].name,
		    commands[i].args[0] == '\0' ? "" : " ",
		    commands[i].args);
		lead = "      ";
	}
	for (c = commands_table; c->name != NULL; c++) {
		fprintf(stderr, "%s %s [-d directory] %s%s%s\n", lead,
		    getprogname(), c->name, c->args[0] == '\0' ? "" : " ",
		    c->args);
		lead = "      ";
	}

	/* The line of the interactive session (PROG-IFACE-1). */
	fprintf(stderr, "%s %s [-d directory]\n", lead, getprogname());
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
 *	The slots of the pool come from -p, and a run without that
 *	option takes CEREMONY_POOL_SIZE slots (ENTRY-POOL-2).
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
	arg.pool = CEREMONY_POOL_SIZE;

	optreset = 1;
	optind = 1;
	while ((ch = getopt(argc, argv, "k:m:p:r:")) != -1) {
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
		case 'p':
			arg.pool = (unsigned int)strtonum(optarg, 1,
			    CEREMONY_POOL_MAX, &errstr);
			if (errstr != NULL) {
				warnx("the pool size is %s", errstr);
				usage();
			}
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

/*
 * cmd_canary(argc, argv, vault):
 *	The canary re-enrollment of one oracle of the vault directory
 *	vault (ORC-CANARY-5, PROG-ONESHOT-4). The one argument is the
 *	position of that oracle in the ordered set (ORC-PROVISION-5).
 *
 *	The call opens the session, so the passphrase of the unlock
 *	verifies at the canary record of each quorum oracle first
 *	(ORC-CANARY-1). session.c then reads the passphrase a second
 *	time, and it re-enrolls the record (ORC-CANARY-6).
 *
 *	A session that holds the index key re-wraps this machine's
 *	index share of the oracle, and a session without it deletes
 *	the dead wrap file (ORC-CANARY-8).
 */
static int
cmd_canary(int argc, char *argv[], const char *vault)
{
	struct session	*s = NULL;
	const char	*errstr;
	unsigned int	 oracle;
	int		 rv;

	if (argc != 2)
		usage();
	oracle = (unsigned int)strtonum(argv[1], 1, DERIVE_ORACLE_MAX,
	    &errstr);
	if (errstr != NULL)
		errx(1, "the oracle position is %s", errstr);

	if (session_open(vault, &s) != 0)
		return 1;
	rv = session_canary(s, oracle);
	session_close(s);
	return rv == 0 ? 0 : 1;
}

/*
 * cmd_passwd(argc, argv, vault):
 *	The passphrase change of the vault directory vault
 *	(ORC-ENROLL-4, PROG-ONESHOT-4). The subcommand takes no
 *	option and no argument, and change.c runs each step.
 *
 *	The change takes no master, so it reads no plate. It reads
 *	each passphrase twice, because a canary enrollment of the
 *	change can take either one (ORC-ENROLL-8, ORC-CANARY-6). An
 *	incomplete change leaves the marker, and cmd_resume()
 *	completes it (ORC-ENROLL-10).
 */
static int
cmd_passwd(int argc, char *argv[], const char *vault)
{
	(void)argv;
	if (argc != 1)
		usage();
	return change_passphrase(vault) == 0 ? 0 : 1;
}

/*
 * cmd_resume(argc, argv, vault):
 *	The rest of an incomplete passphrase change of the vault
 *	directory vault (ORC-ENROLL-10, PROG-ONESHOT-4). The
 *	subcommand takes no option and no argument.
 *
 *	The marker of the change splits the records of this machine,
 *	and change.c holds that rule. A vault that holds no marker
 *	gives the status 1.
 */
static int
cmd_resume(int argc, char *argv[], const char *vault)
{
	(void)argv;
	if (argc != 1)
		usage();
	return change_resume(vault) == 0 ? 0 : 1;
}

/*
 * cmd_refill(argc, argv, vault):
 *	The pool refill ceremony of the vault directory vault
 *	(CER-REFILL, PROG-ONESHOT-4). The subcommand takes no option
 *	and no argument: the config file of the vault holds the pool
 *	size, and ceremony.c reads it (ENTRY-POOL-2).
 *
 *	The ceremony takes the master from a plate scan, and it
 *	refuses to start while the change marker exists
 *	(CER-REFILL-1, CER-REFILL-8).
 */
static int
cmd_refill(int argc, char *argv[], const char *vault)
{
	(void)argv;
	if (argc != 1)
		usage();
	return ceremony_refill(vault) == 0 ? 0 : 1;
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
	const struct commands_cmd	*c;
	char				 vault[PATH_MAX];
	const char			*dir = NULL;
	size_t				 i;
	int				 ch;

	/*
	 * The first call of main(), before every other one: no crash
	 * of this program writes a secret to a core file
	 * (SEC-MEMORY-3). sandbox.c holds the call, and
	 * src/regress/sandbox.c probes the two limits that it leaves.
	 */
	if (sandbox_nocore() != 0)
		err(1, "the core limit of fugupass");

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

	/*
	 * The frame reads the two tables before the sandbox, so a
	 * wrong subcommand makes no vault directory. The sandbox
	 * comes before the command line of the subcommand, so a
	 * rejected option of a subcommand makes that directory.
	 *
	 * A run with no subcommand reads neither table: it starts
	 * the interactive session (PROG-IFACE-1).
	 */
	i = nitems(commands);
	if (argc >= 1) {
		for (i = 0; i < nitems(commands); i++) {
			if (strcmp(argv[0], commands[i].name) == 0)
				break;
		}
		if (i == nitems(commands)) {
			for (c = commands_table; c->name != NULL; c++) {
				if (strcmp(argv[0], c->name) == 0)
					break;
			}
			if (c->name == NULL)
				usage();
		}
	}

	if (vault_dir(dir, vault, sizeof(vault)) != 0)
		errx(1, "no vault directory");
	if (sandbox_enter(vault) != 0)
		err(1, "sandbox");

	if (argc < 1)
		return iface_session(vault);
	if (i < nitems(commands))
		return commands[i].run(argc, argv, vault);
	return commands_oneshot(vault, argc, argv);
}
