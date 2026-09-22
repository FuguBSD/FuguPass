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
 * A program that the core execs takes a probe of its own. The list
 * reaches such a program through the execpromises argument of
 * pledge(2), and the child of a NULL argument holds the whole file
 * system. The probe execs this program again with the argument
 * EXEC_ARG, so the test needs no second program.
 *
 * OpenBSD answers a hidden path with ENOENT, and an unveiled path
 * of another permission with EACCES. The probes below read those
 * two values.
 *
 * The probe of a child holds the two halves of PROG-SPLIT-4: the
 * video devices of the unveil list, and the video promise of the
 * execpromises. An absent file gives ENOENT as a hidden path does,
 * so the parent opens each device before the sandbox, and it gives
 * the path of each device that it reaches to the child. That open
 * is the positive control of the probe: a device with no camera
 * gives ENXIO, and each value but ENOENT reports a file that the
 * machine holds. The child then opens each of those paths, and
 * ENOENT there reports a list without the device.
 *
 * The promise takes a probe of its own, because the open above runs
 * under the rpath promise of a child. The child makes the pledge
 * call of the scan helper, with SCAN_PROMISES of scan.h. A promise
 * outside the execpromises gives EPERM, and the kernel kills no
 * process of such a call.
 *
 * The child makes the first call of each helper as well:
 * scan_nocore() of scan.h, and qr_sandbox() of qr.h. Each one holds
 * RLIMIT_CORE at zero (SEC-MEMORY-3), and the execpromises hold no
 * proc promise. A setrlimit(2) call of such a child is a pledge
 * violation, and the kernel kills it with SIGABRT. The child of
 * probe_exec() therefore sets the core limit to zero before the
 * sandbox call, as main() of fugupass.c does, and each helper call
 * reads that limit and writes none.
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

#include <dirent.h>
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
#include "qr.h"
#include "sandbox.h"
#include "scan.h"

/* The file of the work directory that the unveil list must hide. */
#define OUTSIDE_FILE	"outside"

/* The file of the vault directory that the child writes. */
#define INSIDE_FILE	"inside"

/* The argument that makes this program the probe of a child. */
#define EXEC_ARG	"exec-probe"

/*
 * The runtime file of the unveil list that the probe of a child
 * reads. Every OpenBSD machine holds it, and the list of
 * sandbox.c carries it with the r permission.
 */
#define RUNTIME_FILE	"/usr/libexec/ld.so"

/*
 * The video devices of the unveil list (PROG-SPLIT-13). The list
 * holds the prefix itself and the ten units 0 to 9, so VIDEO_MAX is
 * 11 paths. A machine can hold a device above that bound, and the
 * list of the core carries no such path. VIDEO_MAX bounds the count
 * of the paths that the probe of a child takes on its command line.
 */
#define VIDEO_DIR	"/dev"
#define VIDEO_PREFIX	"video"
#define VIDEO_MAX	11

/*
 * The exit status of the probe of a child. 0 is a pass, and each
 * other value names one outcome of a run.
 */
#define EXEC_SANDBOX	2	/* the sandbox call fails */
#define EXEC_EXECV	3	/* the exec of this program fails */
#define EXEC_OPEN	4	/* the child opens the hidden path */
#define EXEC_ERRNO	5	/* the open gives another errno */
#define EXEC_RUNTIME	6	/* the child reads no runtime file */
#define EXEC_VIDEO	7	/* the list hides a video device */
#define EXEC_PROMISE	8	/* the pledge of the scan helper fails */
#define EXEC_NOCORE	9	/* the core limit call of a helper fails */
#define EXEC_QRSANDBOX	10	/* the sandbox of the render helper fails */

static int	 probe_hidden(const char *);
static int	 probe_readonly(const char *);
static int	 probe_vault(const char *);
static int	 probe_pledge(const char *);
static int	 probe_exec(const char *, const char *, const char *,
		     char [][PATH_MAX], int);
static int	 exec_probe(const char *, char *[], int);
static int	 video_devices(char [][PATH_MAX], int);
static int	 selfpath(const char *, const char *, char *, size_t);
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
 *	itself fails, 3 when the socket call fails for another
 *	reason, and 0 when the socket call gives a descriptor.
 *
 *	The call gives 0 for the signal, and -1 for every other
 *	outcome. Each outcome takes a report of its own, so no
 *	other failure reads as a pledge that takes the socket.
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
		if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
			warn("socket");
			_exit(3);
		}
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
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		warnx("the pledge takes a socket of AF_UNIX, and the "
		    "promises are \"%s\"", SANDBOX_PROMISES);
		return -1;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 2) {
		warnx("the probe of the pledge: the sandbox call fails");
		return -1;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 3) {
		warnx("the probe of the pledge: the socket call fails for "
		    "another reason");
		return -1;
	}
	warnx("the probe of the pledge: the status of the child is %d, and "
	    "SIGABRT is the outcome of a violation", status);
	return -1;
}

/*
 * probe_exec(vault, outside, self):
 *	A program that the core execs must not reach a path outside
 *	the unveil list (PROG-SPLIT-3). The list reaches such a
 *	program through the execpromises argument of pledge(2), and
 *	the child of a NULL argument holds the whole file system.
 *	This probe therefore fails when sandbox_enter() drops
 *	SANDBOX_EXEC_PROMISES.
 *
 *	The program of the probe is this program. The child unveils
 *	self with the x permission, as the sandbox unveils a compiled
 *	helper, and it then calls sandbox_enter() and execs self with
 *	the argument EXEC_ARG. main() reads that argument and runs
 *	exec_probe().
 *
 *	sandbox_enter() makes the vault directory before its first
 *	unveil call, and the first unveil call of a process hides
 *	every other path. This child therefore makes that directory
 *	and unveils it before it unveils self. The view of the child
 *	is then the list of sandbox_enter() and the path of self.
 *
 *	device holds the count video devices of this machine, and the
 *	command line of the child carries them after the hidden path.
 *	video_devices() reads that list, and the probe of the child
 *	opens each path of it (PROG-SPLIT-4).
 *
 *	The call gives 0 for the exit status 0 of that run, and -1
 *	for every other outcome. exec_probe() reports each outcome of
 *	its own, so no failure reads as a list that reaches the
 *	child.
 */
static int
probe_exec(const char *vault, const char *outside, const char *self,
    char device[][PATH_MAX], int count)
{
	char	*argv[4 + VIDEO_MAX];
	pid_t	 pid, done;
	int	 i, status;

	argv[0] = (char *)self;
	argv[1] = (char *)EXEC_ARG;
	argv[2] = (char *)outside;
	for (i = 0; i < count; i++)
		argv[3 + i] = device[i];
	argv[3 + count] = NULL;

	if ((pid = fork()) == -1) {
		warn("fork");
		return -1;
	}
	if (pid == 0) {
		struct rlimit	 nocore = { 0, 0 };

		/*
		 * The core limit of main() of fugupass.c, before the
		 * sandbox call (SEC-MEMORY-3). A child of this child
		 * inherits the zero limit, and the first call of each
		 * helper reads it.
		 */
		if (setrlimit(RLIMIT_CORE, &nocore) == -1)
			_exit(EXEC_SANDBOX);
		if (mkdir(vault, S_IRWXU) == -1 && errno != EEXIST)
			_exit(EXEC_SANDBOX);
		if (unveil(vault, "rwc") == -1)
			_exit(EXEC_SANDBOX);
		if (unveil(self, "x") == -1)
			_exit(EXEC_SANDBOX);
		if (sandbox_enter(vault) != 0)
			_exit(EXEC_SANDBOX);
		execv(self, argv);
		_exit(EXEC_EXECV);
	}

	while ((done = waitpid(pid, &status, 0)) == -1 && errno == EINTR)
		;
	if (done != pid) {
		warn("waitpid");
		return -1;
	}
	if (WIFSIGNALED(status)) {
		warnx("the probe of the child: the signal %d stops it, and "
		    "the promises of a child are \"%s\"", WTERMSIG(status),
		    SANDBOX_EXEC_PROMISES);
		return -1;
	}
	if (!WIFEXITED(status)) {
		warnx("the probe of the child: the status of it is %d",
		    status);
		return -1;
	}
	switch (WEXITSTATUS(status)) {
	case 0:
		return 0;
	case EXEC_SANDBOX:
		warnx("the probe of the child: the sandbox call fails");
		break;
	case EXEC_EXECV:
		warnx("the probe of the child: the exec of %s fails", self);
		break;
	default:
		break;
	}
	return -1;
}

/*
 * exec_probe(hidden, device, count):
 *	The probes of a child of the core. This program runs them
 *	after the exec of probe_exec(), and the exit status carries
 *	the outcome.
 *
 *	The file at hidden must exist, and the unveil list must hide
 *	it from this process. RUNTIME_FILE must open for a read,
 *	because the list carries it: a child of an empty view fails
 *	that probe, so the pass reports the list of the core and not
 *	the absence of one.
 *
 *	device holds the count video devices of the machine, and the
 *	parent proved each path of it before the sandbox. Each one
 *	must open here, or must fail with another errno than ENOENT:
 *	a machine with no camera answers the open with ENXIO, and the
 *	unveil list of the core carries the device (PROG-SPLIT-13).
 *	This probe runs before the pledge call below, because the
 *	open takes the rpath promise of a child.
 *
 *	The pledge call of the scan helper comes last. The promise
 *	set of that helper is SCAN_PROMISES, and a promise outside
 *	SANDBOX_EXEC_PROMISES gives EPERM there (PROG-SPLIT-4).
 */
static int
exec_probe(const char *hidden, char *device[], int count)
{
	int	 fd, i;

	errno = 0;
	if ((fd = open(hidden, O_RDONLY)) != -1) {
		close(fd);
		warnx("%s: a child of the core reads a path outside the "
		    "unveil list", hidden);
		return EXEC_OPEN;
	}
	if (errno != ENOENT) {
		warnx("%s: the open of the child gives errno %d, and ENOENT "
		    "is the value of a hidden path", hidden, errno);
		return EXEC_ERRNO;
	}
	errno = 0;
	if ((fd = open(RUNTIME_FILE, O_RDONLY)) == -1) {
		warnx("%s: the child reads no runtime file of the unveil "
		    "list: errno %d", RUNTIME_FILE, errno);
		return EXEC_RUNTIME;
	}
	close(fd);

	for (i = 0; i < count; i++) {
		errno = 0;
		if ((fd = open(device[i], O_RDONLY)) != -1) {
			close(fd);
			continue;
		}
		if (errno == ENOENT) {
			warnx("%s: the unveil list of the core hides a video "
			    "device of this machine, and the parent of this "
			    "child reached that device", device[i]);
			return EXEC_VIDEO;
		}
	}

	/*
	 * The first call of the scan helper, before the pledge call
	 * of it (SEC-MEMORY-3). The kernel kills this child of a
	 * setrlimit(2) call, so a pass reports the call that reads
	 * the inherited limit.
	 */
	if (scan_nocore() != 0) {
		warnx("the core limit of the scan helper fails: errno %d",
		    errno);
		return EXEC_NOCORE;
	}

	if (pledge(SCAN_PROMISES, NULL) == -1) {
		warnx("the promises \"%s\" of the scan helper give errno %d, "
		    "and the execpromises are \"%s\"", SCAN_PROMISES, errno,
		    SANDBOX_EXEC_PROMISES);
		return EXEC_PROMISE;
	}

	/*
	 * The sandbox of the render helper, last: it holds the core
	 * limit and the pledge call of QR_PROMISES, and that set
	 * takes no open of a path (PROG-SPLIT-5). The set stands
	 * inside the promises above, so the call reduces them.
	 */
	if (qr_sandbox() != 0) {
		warnx("the sandbox of the render helper fails: errno %d",
		    errno);
		return EXEC_QRSANDBOX;
	}
	return 0;
}

/*
 * video_devices(list, size):
 *	The video devices of this machine, to the size paths at list.
 *	The call reads VIDEO_DIR, and it takes each entry of the
 *	unveil list of PROG-SPLIT-13 that this process opens. That
 *	list holds VIDEO_PREFIX itself and the ten units 0 to 9, so
 *	the call drops /dev/video10 and every other name outside it.
 *	The list of the core carries no such path, and the child of
 *	the probe gets ENOENT there.
 *
 *	That open is the positive control of the video probe of
 *	exec_probe(). A hidden path and an absent file each give
 *	ENOENT, so a probe of ENOENT alone proves nothing. This
 *	process holds no sandbox, so an open of another outcome than
 *	ENOENT reports a device that the machine holds: a device with
 *	no camera gives ENXIO, and a device of another owner gives
 *	EACCES.
 *
 *	The call gives the count of the paths, and 0 for a machine
 *	with no video device. The probe of the child then reads the
 *	promise of PROG-SPLIT-4 alone.
 */
static int
video_devices(char list[][PATH_MAX], int size)
{
	struct dirent	*ent;
	DIR		*dir;
	const char	*unit;
	int		 fd, n, count = 0;

	if ((dir = opendir(VIDEO_DIR)) == NULL)
		return 0;
	while (count < size && (ent = readdir(dir)) != NULL) {
		if (strncmp(ent->d_name, VIDEO_PREFIX,
		    sizeof(VIDEO_PREFIX) - 1) != 0)
			continue;
		unit = ent->d_name + sizeof(VIDEO_PREFIX) - 1;
		if (unit[0] != '\0' && (unit[1] != '\0' ||
		    unit[0] < '0' || unit[0] > '9'))
			continue;
		n = snprintf(list[count], PATH_MAX, "%s/%s", VIDEO_DIR,
		    ent->d_name);
		if (n < 0 || n >= PATH_MAX)
			continue;
		errno = 0;
		if ((fd = open(list[count], O_RDONLY)) != -1)
			close(fd);
		else if (errno == ENOENT)
			continue;
		count++;
	}
	closedir(dir);
	return count;
}

/*
 * selfpath(argv0, cwd, buf, size):
 *	The absolute path of this program, from argv0 and the working
 *	directory cwd. unveil(2) and execv(3) each read a relative
 *	path against the working directory of the moment, and the
 *	absolute path holds in every case.
 *
 *	The call gives 0, and -1 for a path that size does not take.
 */
static int
selfpath(const char *argv0, const char *cwd, char *buf, size_t size)
{
	int	 n;

	if (argv0[0] == '/')
		n = snprintf(buf, size, "%s", argv0);
	else
		n = snprintf(buf, size, "%s/%s", cwd, argv0);
	if (n < 0 || (size_t)n >= size)
		return -1;
	return 0;
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
main(int argc, char *argv[])
{
	struct stat	 sb;
	char		 work[] = "sandbox.XXXXXXXXXX";
	char		 cwd[PATH_MAX], dir[PATH_MAX], vault[PATH_MAX];
	char		 outside[PATH_MAX], self[PATH_MAX];
	char		 device[VIDEO_MAX][PATH_MAX];
	pid_t		 pid, done;
	int		 ca, count, n, status, rv = 1;

	/* The exec of probe_exec() reaches this program here. */
	if (argc >= 3 && strcmp(argv[1], EXEC_ARG) == 0)
		return exec_probe(argv[2], argv + 3, argc - 3);
	if (argc != 1)
		errx(1, "usage: sandbox");

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		err(1, "getcwd");
	if (selfpath(argv[0], cwd, self, sizeof(self)) != 0)
		errx(1, "the path of this program does not fit");
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
	 * the child holds a hidden path and an absent file apart. The
	 * video devices of the machine take the same control, and
	 * video_devices() opens each one here (PROG-SPLIT-13).
	 */
	ca = stat(HTTP_CA_FILE, &sb) == 0;
	count = video_devices(device, VIDEO_MAX);

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

	/* The list of a child, after the pledge of this process. */
	if (probe_exec(vault, outside, self, device, count) != 0)
		goto out;
	rv = 0;
out:
	rmtree(dir);
	return rv;
}
