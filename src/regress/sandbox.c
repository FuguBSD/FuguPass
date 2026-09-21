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
 * The test of the sandbox of the core process (PROG-SPLIT-3,
 * PROG-SPLIT-12). sandbox_enter() of src/sandbox.c makes the unveil
 * list and the pledge call, and main() of fugupass.c makes the same
 * one call. This test therefore reads the list that the program
 * runs under.
 *
 * unveil(2) and pledge(2) hold for the life of a process, so the
 * test forks. The child calls sandbox_enter() and probes the file
 * system, and the parent keeps the right to remove the work
 * directory. The child exits 0 when every probe passes.
 *
 * A violation of the pledge kills the process, so the probe of the
 * pledge takes a second child of its own.
 *
 * OpenBSD answers a hidden path with ENOENT, and an unveiled path
 * of another permission with EACCES. The probes below read those
 * two values.
 *
 * The test needs a file outside the vault directory, so the work
 * directory of the run holds the vault directory and that file. The
 * program makes the work directory with mkdtemp(3) in the working
 * directory, and it removes the work directory at the end.
 *
 * The program prints nothing on a pass, and it exits 0. A wrong
 * value prints the probe to the standard error, and the program
 * exits 1.
 *
 * This test holds no secret and clears nothing.
 */

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "http.h"
#include "sandbox.h"

/* The file of the work directory that the unveil list must hide. */
#define OUTSIDE_FILE	"outside"

/* The file of the vault directory that the child writes. */
#define INSIDE_FILE	"inside"

static int	 probe_hidden(const char *);
static int	 probe_readonly(const char *);
static int	 probe_vault(const char *);
static int	 probe_pledge(const char *);
static int	 child(const char *, const char *, int);
static int	 writefile(const char *);
static void	 rmtree(const char *);

/*
 * probe_hidden(path):
 *	The file at path must exist, and the sandbox must hide it.
 *	The call gives 0 when the open fails with ENOENT.
 */
static int
probe_hidden(const char *path)
{
	int	 fd;

	errno = 0;
	if ((fd = open(path, O_RDONLY)) != -1) {
		close(fd);
		warnx("%s: the sandbox opens a path outside the list", path);
		return -1;
	}
	if (errno != ENOENT) {
		warnx("%s: the open gives errno %d, and ENOENT is the value "
		    "of a hidden path", path, errno);
		return -1;
	}
	return 0;
}

/*
 * probe_readonly(path):
 *	The file at path must open for a read, and must not open for
 *	a write. The call gives 0 for that pair of outcomes. The
 *	caller runs this probe against a file that the machine holds,
 *	so ENOENT reports a path that the list does not carry.
 *
 *	The trust anchors of libtls take the r permission
 *	(PROG-SPLIT-12).
 */
static int
probe_readonly(const char *path)
{
	int	 fd, rv = 0;

	errno = 0;
	if ((fd = open(path, O_RDONLY)) == -1) {
		warnx("%s: the sandbox reads no file of the r permission: "
		    "errno %d", path, errno);
		return -1;
	}
	close(fd);

	errno = 0;
	if ((fd = open(path, O_WRONLY)) != -1) {
		close(fd);
		warnx("%s: the sandbox writes a file of the r permission",
		    path);
		return -1;
	}
	if (errno != EACCES) {
		warnx("%s: the write gives errno %d, and EACCES is the value "
		    "of the r permission", path, errno);
		rv = -1;
	}
	return rv;
}

/*
 * probe_vault(vault):
 *	The vault directory must take a new file. The call gives 0
 *	when the create passes.
 */
static int
probe_vault(const char *vault)
{
	char	 path[PATH_MAX];
	int	 fd, n;

	n = snprintf(path, sizeof(path), "%s/%s", vault, INSIDE_FILE);
	if (n < 0 || (size_t)n >= sizeof(path)) {
		warnx("the path of the file inside the vault does not fit");
		return -1;
	}
	errno = 0;
	if ((fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR)) == -1) {
		warnx("%s: the sandbox writes no file of the vault: errno %d",
		    path, errno);
		return -1;
	}
	close(fd);
	return 0;
}

/*
 * probe_pledge(vault):
 *	The pledge must stop a syscall outside SANDBOX_PROMISES.
 *	That promise list holds inet and dns, and it holds no unix,
 *	so a socket of AF_UNIX is such a syscall. pledge(2) kills
 *	the process of a violation with SIGABRT, so this probe runs
 *	in a child of its own, and it reads the signal of that
 *	child.
 *
 *	The child sets RLIMIT_CORE to zero first, so the abort
 *	writes no core file. It exits 2 when the sandbox call
 *	itself fails, and 0 when the socket call returns.
 *
 *	The call gives 0 for the signal, and -1 for every other
 *	outcome.
 */
static int
probe_pledge(const char *vault)
{
	struct rlimit	 nocore = { 0, 0 };
	pid_t		 pid, done;
	int		 fd, status;

	if ((pid = fork()) == -1) {
		warn("fork");
		return -1;
	}
	if (pid == 0) {
		if (setrlimit(RLIMIT_CORE, &nocore) == -1)
			_exit(2);
		if (sandbox_enter(vault) != 0)
			_exit(2);
		if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) != -1)
			close(fd);
		_exit(0);
	}

	while ((done = waitpid(pid, &status, 0)) == -1 && errno == EINTR)
		;
	if (done != pid) {
		warn("waitpid");
		return -1;
	}
	if (WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT)
		return 0;
	if (WIFEXITED(status) && WEXITSTATUS(status) == 2) {
		warnx("the probe of the pledge: the sandbox call fails");
		return -1;
	}
	warnx("the pledge takes a socket of AF_UNIX, and the promises are "
	    "\"%s\"", SANDBOX_PROMISES);
	return -1;
}

/*
 * child(vault, outside, ca):
 *	The sandbox call, and the probes of it. The call gives 0 when
 *	every probe passes, and -1 when one probe fails. Every probe
 *	runs on each run, so one run reports every wrong value.
 *
 *	ca reports the trust anchors of libtls on this machine. A
 *	machine without that file gets a list that is one path
 *	shorter, and the probe of it then does not run.
 */
static int
child(const char *vault, const char *outside, int ca)
{
	int	 rv = 0;

	if (sandbox_enter(vault) != 0) {
		warn("sandbox_enter");
		return -1;
	}
	if (probe_hidden(outside) != 0)
		rv = -1;
	if (probe_hidden("/etc/passwd") != 0)
		rv = -1;
	if (ca && probe_readonly(HTTP_CA_FILE) != 0)
		rv = -1;
	if (probe_vault(vault) != 0)
		rv = -1;
	return rv;
}

/*
 * writefile(path):
 *	Make the file at path, with one byte in it. The call gives 0
 *	on a pass, and -1 on a failure.
 */
static int
writefile(const char *path)
{
	int	 fd;

	if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC,
	    S_IRUSR | S_IWUSR)) == -1)
		return -1;
	if (write(fd, "x", 1) != 1) {
		close(fd);
		return -1;
	}
	return close(fd);
}

/*
 * rmtree(dir):
 *	Remove the two files that this test makes, and then the two
 *	directories of it.
 */
static void
rmtree(const char *dir)
{
	char	 path[PATH_MAX];

	if (snprintf(path, sizeof(path), "%s/vault/%s", dir, INSIDE_FILE) > 0)
		(void)unlink(path);
	if (snprintf(path, sizeof(path), "%s/vault", dir) > 0)
		(void)rmdir(path);
	if (snprintf(path, sizeof(path), "%s/%s", dir, OUTSIDE_FILE) > 0)
		(void)unlink(path);
	(void)rmdir(dir);
}

int
main(void)
{
	struct stat	 sb;
	char		 work[] = "sandbox.XXXXXXXXXX";
	char		 cwd[PATH_MAX], dir[PATH_MAX], vault[PATH_MAX];
	char		 outside[PATH_MAX];
	pid_t		 pid, done;
	int		 ca, n, status, rv = 1;

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		err(1, "getcwd");
	if (mkdtemp(work) == NULL)
		err(1, "mkdtemp");

	/*
	 * unveil(2) reads a relative path against the working
	 * directory of the moment, and the child changes no working
	 * directory. The absolute path holds in every case.
	 */
	n = snprintf(dir, sizeof(dir), "%s/%s", cwd, work);
	if (n < 0 || (size_t)n >= sizeof(dir))
		errx(1, "the path of the work directory does not fit");
	n = snprintf(vault, sizeof(vault), "%s/vault", dir);
	if (n < 0 || (size_t)n >= sizeof(vault))
		errx(1, "the path of the vault directory does not fit");
	n = snprintf(outside, sizeof(outside), "%s/%s", dir, OUTSIDE_FILE);
	if (n < 0 || (size_t)n >= sizeof(outside))
		errx(1, "the path of the outside file does not fit");

	if (writefile(outside) != 0) {
		warn("%s", outside);
		goto out;
	}

	/*
	 * The parent reads the trust anchors before the sandbox, so
	 * the child holds a hidden path and an absent file apart.
	 */
	ca = stat(HTTP_CA_FILE, &sb) == 0;

	if ((pid = fork()) == -1) {
		warn("fork");
		goto out;
	}
	if (pid == 0)
		_exit(child(vault, outside, ca) == 0 ? 0 : 1);

	while ((done = waitpid(pid, &status, 0)) == -1 && errno == EINTR)
		;
	if (done != pid) {
		warn("waitpid");
		goto out;
	}
	if (!WIFEXITED(status)) {
		warnx("the sandboxed child died of the signal %d",
		    WTERMSIG(status));
		goto out;
	}
	if (WEXITSTATUS(status) != 0)
		goto out;

	/* The pledge, after the list: the child of it dies. */
	if (probe_pledge(vault) != 0)
		goto out;
	rv = 0;
out:
	rmtree(dir);
	return rv;
}
