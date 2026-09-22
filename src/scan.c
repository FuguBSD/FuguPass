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
 * The scan helper of PROG-SCAN. scan.h states the interface.
 *
 * quirc of src/quirc decodes each frame (PROG-QR-5, PROG-BUILD-5).
 * The library takes one grey byte of each pixel, and it gives the
 * version, the mode and the payload of each code that it reads. The
 * mode and the payload length hold the gate of D-22: numeric mode and
 * 48 digits are a Standard SeedQR of 12 words, and every other code
 * is a failure.
 *
 * video(4) gives the frames. The read(2) access of that driver starts
 * the stream at the first read, and it needs no buffer map
 * (PROG-SCAN-9). The helper therefore opens the device, it reads one
 * frame at a time, and it takes the luminance byte of each YUYV
 * pixel as the grey byte of it. The mmap access needs VIDIOC_REQBUFS
 * and a map of the device, and this helper needs neither one.
 *
 * The frames of a plate scan are blank while kern.video.record is 0.
 * The driver blanks the image data of every reader at that value, and
 * it is the default (PROG-SCAN-11).
 *
 * read(2) on that driver blocks with no bound, so a device that opens
 * and gives no frame would hold the ceremony of the caller. The frame
 * loop therefore waits for each frame with poll(2), until the bound
 * of PROG-SCAN-9 (SCAN_SECONDS). poll(2) needs the stdio promise
 * alone, and video(4) reports a frame to it through the read filter
 * of the driver.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/videoio.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "quirc.h"

#include "scan.h"
#include "wordlist.h"

/* The frame that the helper asks of the device (PROG-SCAN-9). */
#define SCAN_WIDTH	640
#define SCAN_HEIGHT	480

/* The largest frame side that the helper reads, in pixels. */
#define SCAN_SIDE_MAX	8192

/* The digits of one word index (PROG-SCAN-2). */
#define SCAN_GROUP	4

/*
 * The line of 12 words fits SCAN_LINE_MAX bytes: each word takes at
 * most WORDLIST_MAX bytes, each word takes one separator after it,
 * and the line takes one terminator.
 */
_Static_assert(SCAN_WORDS * (WORDLIST_MAX + 1) + 1 <= SCAN_LINE_MAX,
    "SCAN_LINE_MAX must take 12 words, the separators and the terminator");

static enum scan_result	 scan_words(const struct quirc_data *, char *);

int
scan_nocore(void)
{
	struct rlimit	 limit, nocore = { 0, 0 };

	/*
	 * The core limit comes first, before every other act of the
	 * program: no crash of it writes the master to a core file
	 * (SEC-MEMORY-3).
	 *
	 * A child of the core process inherits the zero limit of that
	 * process, and the execpromises of it hold no proc promise
	 * (PROG-SPLIT-3). setrlimit(2) needs that promise, and the
	 * kernel kills a child that calls it. The call below therefore
	 * reads the limit first, and it writes the limit of a run
	 * outside the core process alone. getrlimit(2) needs the stdio
	 * promise alone (SEC-MEMORY-3).
	 */
	if (getrlimit(RLIMIT_CORE, &limit) == -1)
		return -1;
	if (limit.rlim_cur == 0)
		return 0;
	if (setrlimit(RLIMIT_CORE, &nocore) == -1)
		return -1;
	return 0;
}

/*
 * scan_words(data, line):
 *	The 12 words of the decoded code data, to the SCAN_LINE_MAX
 *	bytes at line (PROG-SCAN-2, PROG-SCAN-5).
 *
 *	The code must carry numeric mode and SCAN_DIGITS digits, and
 *	each group of SCAN_GROUP digits must name a word of the list
 *	(D-22, PROG-SCAN-10). The call gives the cause of a failure,
 *	and it then writes no byte of line.
 *
 *	The call builds the line in a buffer of its own, and it copies
 *	that buffer to line on a pass alone. A failure at the last
 *	word therefore leaves no part of a mnemonic at line.
 *
 *	rv starts at SCAN_INDEX, the cause of a failure inside the
 *	loop of the words. The two gates before that loop each write
 *	the cause of their own.
 */
static enum scan_result
scan_words(const struct quirc_data *data, char *line)
{
	char			 word[WORDLIST_MAX + 1];
	char			 out[SCAN_LINE_MAX];
	size_t			 index, len = 0, wordlen;
	enum scan_result	 rv = SCAN_INDEX;
	int			 i, k, digit;

	if (data->data_type != QUIRC_DATA_TYPE_NUMERIC) {
		rv = SCAN_MODE;
		goto out;
	}
	if (data->payload_len != SCAN_DIGITS) {
		rv = SCAN_COUNT;
		goto out;
	}
	for (i = 0; i < SCAN_WORDS; i++) {
		index = 0;
		for (k = 0; k < SCAN_GROUP; k++) {
			digit = data->payload[i * SCAN_GROUP + k];
			if (digit < '0' || digit > '9')
				goto out;
			index = index * 10 + (size_t)(digit - '0');
		}
		if (wordlist_word(index, word, sizeof(word)) != 0)
			goto out;
		if (i > 0)
			out[len++] = ' ';
		wordlen = strlen(word);
		memcpy(out + len, word, wordlen);
		len += wordlen;
	}
	out[len++] = '\n';
	out[len] = '\0';
	memcpy(line, out, len + 1);
	rv = SCAN_OK;
out:
	explicit_bzero(word, sizeof(word));
	explicit_bzero(out, sizeof(out));
	return rv;
}

const char *
scan_strerror(enum scan_result result)
{
	switch (result) {
	case SCAN_OK:
		return "the frame holds one Standard SeedQR of 12 words";
	case SCAN_MEMORY:
		return "the decoder takes no memory";
	case SCAN_NO_CODE:
		return "the frame holds no QR code";
	case SCAN_CORRUPT:
		return "the decode of the QR code fails";
	case SCAN_MODE:
		return "the QR code is outside numeric mode, and a Standard "
		    "SeedQR is numeric";
	case SCAN_COUNT:
		return "the QR code holds another count of digits, and a "
		    "Standard SeedQR of 12 words holds 48";
	case SCAN_INDEX:
		return "four digits of the QR code name no word of the list";
	}
	return "the decode of the frame fails";
}

enum scan_result
scan_decode(const unsigned char *gray, int w, int h, char *line)
{
	struct quirc		*q;
	struct quirc_code	 code;
	struct quirc_data	 data;
	uint8_t			*image;
	enum scan_result	 rv = SCAN_NO_CODE, one;
	int			 i, n;

	memset(&code, 0, sizeof(code));
	memset(&data, 0, sizeof(data));
	if (w <= 0 || h <= 0)
		return SCAN_NO_CODE;
	if ((q = quirc_new()) == NULL)
		return SCAN_MEMORY;
	if (quirc_resize(q, w, h) < 0) {
		quirc_destroy(q);
		return SCAN_MEMORY;
	}
	image = quirc_begin(q, NULL, NULL);
	memcpy(image, gray, (size_t)w * h);
	quirc_end(q);

	n = quirc_count(q);
	for (i = 0; i < n; i++) {
		quirc_extract(q, i, &code);
		if (quirc_decode(&code, &data) != QUIRC_SUCCESS) {
			rv = SCAN_CORRUPT;
			continue;
		}
		if ((one = scan_words(&data, line)) == SCAN_OK) {
			rv = SCAN_OK;
			break;
		}
		rv = one;
	}

	/*
	 * The payload of a mnemonic code is the master, so this call
	 * erases the buffers that it reads (SEC-MEMORY-1). quirc frees
	 * the grids and the capstones of the frame without an erasure,
	 * and scan.h names that residue.
	 */
	explicit_bzero(&data, sizeof(data));
	explicit_bzero(&code, sizeof(code));
	explicit_bzero(image, (size_t)w * h);
	quirc_destroy(q);
	return rv;
}

int
scan_wait(int fd, time_t deadline)
{
	struct pollfd	 pfd;
	time_t		 now;
	int		 ms, n;

	/*
	 * read(2) on video(4) blocks until the device gives a frame,
	 * and it takes no timeout. The wait below holds the bound of
	 * PROG-SCAN-9, so a device that gives no frame ends the scan
	 * at the deadline. poll(2) needs the stdio promise alone.
	 */
	now = time(NULL);
	if (now >= deadline)
		return 0;
	if (deadline - now > SCAN_SECONDS)
		ms = SCAN_SECONDS * 1000;
	else
		ms = (int)(deadline - now) * 1000;
	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if ((n = poll(&pfd, 1, ms)) == -1)
		return -1;
	if (n == 0)
		return 0;
	return 1;
}

int
scan_frames(const struct scan_stream *st, int seconds, FILE *out, FILE *err)
{
	unsigned char		*frame = NULL, *gray = NULL;
	char			 line[SCAN_LINE_MAX];
	enum scan_result	 last = SCAN_NO_CODE, result;
	time_t			 deadline;
	ssize_t			 n;
	size_t			 graylen;
	int			 x, y, frames = 0, ready, rv = 1;

	memset(line, 0, sizeof(line));
	graylen = (size_t)st->w * st->h;
	if ((frame = malloc(st->framelen)) == NULL ||
	    (gray = malloc(graylen)) == NULL) {
		fprintf(err, "fugupass-scan: the frame buffer: %s\n",
		    strerror(errno));
		goto out;
	}

	/*
	 * One scan reads frames for seconds seconds (PROG-SCAN-9).
	 * The core process reads the standard output of this child to
	 * its end, so an endless read would hold that ceremony. The
	 * loop therefore waits for each frame, and the wait ends at
	 * the deadline.
	 */
	deadline = time(NULL) + seconds;
	for (;;) {
		if (time(NULL) >= deadline) {
			if (frames == 0)
				fprintf(err, "fugupass-scan: %s: the device "
				    "gives no frame in %d seconds\n",
				    st->device, seconds);
			else
				fprintf(err, "fugupass-scan: no Standard "
				    "SeedQR in %d seconds: %s\n", seconds,
				    scan_strerror(last));
			goto out;
		}
		ready = scan_wait(st->fd, deadline);
		if (ready == -1) {
			if (errno == EINTR)
				continue;
			fprintf(err, "fugupass-scan: %s: the wait for a "
			    "frame: %s\n", st->device, strerror(errno));
			goto out;
		}
		if (ready == 0)
			continue;
		n = read(st->fd, frame, st->framelen);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			fprintf(err, "fugupass-scan: %s: the read of a frame: "
			    "%s\n", st->device, strerror(errno));
			goto out;
		}
		if ((size_t)n < (size_t)st->stride * st->h) {
			fprintf(err, "fugupass-scan: %s: the device gives %zd "
			    "bytes of a frame of %zu\n", st->device, n,
			    (size_t)st->stride * st->h);
			goto out;
		}
		frames++;
		for (y = 0; y < st->h; y++)
			for (x = 0; x < st->w; x++)
				gray[(size_t)y * st->w + x] =
				    frame[(size_t)y * st->stride + 2 * x];
		result = scan_decode(gray, st->w, st->h, line);
		if (result != SCAN_OK) {
			last = result;
			continue;
		}
		if (fputs(line, out) == EOF || fflush(out) == EOF) {
			fprintf(err, "fugupass-scan: the write of the words "
			    "fails\n");
			goto out;
		}
		rv = 0;
		goto out;
	}
out:
	if (frame != NULL) {
		explicit_bzero(frame, st->framelen);
		free(frame);
	}
	if (gray != NULL) {
		explicit_bzero(gray, graylen);
		free(gray);
	}
	explicit_bzero(line, sizeof(line));
	return rv;
}

int
scan_run(const char *device, FILE *out, FILE *err)
{
	struct v4l2_capability	 cap;
	struct v4l2_format	 fmt;
	struct scan_stream	 st;
	int			 fd = -1, rv = 1;

	memset(&st, 0, sizeof(st));
	st.device = device;

	/*
	 * The open comes before the pledge call, because the promise
	 * set of the helper holds no rpath (PROG-SPLIT-4). A machine
	 * with no video device fails here, and the report names the
	 * device (PROG-SCAN-7).
	 */
	if ((fd = open(device, O_RDONLY)) == -1) {
		fprintf(err, "fugupass-scan: %s: %s\n", device,
		    strerror(errno));
		return 1;
	}
	if (pledge(SCAN_PROMISES, NULL) == -1) {
		fprintf(err, "fugupass-scan: the pledge call: %s\n",
		    strerror(errno));
		goto out;
	}

	memset(&cap, 0, sizeof(cap));
	if (ioctl(fd, VIDIOC_QUERYCAP, &cap) == -1) {
		fprintf(err, "fugupass-scan: %s: the capabilities: %s\n",
		    device, strerror(errno));
		goto out;
	}
	if ((cap.capabilities & V4L2_CAP_VIDEO_CAPTURE) == 0 ||
	    (cap.capabilities & V4L2_CAP_READWRITE) == 0) {
		fprintf(err, "fugupass-scan: %s: the device captures no "
		    "video frame of the read access\n", device);
		goto out;
	}

	memset(&fmt, 0, sizeof(fmt));
	fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	fmt.fmt.pix.width = SCAN_WIDTH;
	fmt.fmt.pix.height = SCAN_HEIGHT;
	fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
	fmt.fmt.pix.field = V4L2_FIELD_ANY;
	if (ioctl(fd, VIDIOC_S_FMT, &fmt) == -1) {
		fprintf(err, "fugupass-scan: %s: the frame format: %s\n",
		    device, strerror(errno));
		goto out;
	}
	if (fmt.fmt.pix.pixelformat != V4L2_PIX_FMT_YUYV) {
		fprintf(err, "fugupass-scan: %s: the device gives no YUYV "
		    "frame, and the helper reads that one format\n", device);
		goto out;
	}
	st.w = (int)fmt.fmt.pix.width;
	st.h = (int)fmt.fmt.pix.height;
	st.stride = (int)fmt.fmt.pix.bytesperline;
	st.framelen = fmt.fmt.pix.sizeimage;
	if (st.w <= 0 || st.h <= 0 || st.w > SCAN_SIDE_MAX ||
	    st.h > SCAN_SIDE_MAX || st.stride < 2 * st.w ||
	    st.framelen < (size_t)st.stride * st.h) {
		fprintf(err, "fugupass-scan: %s: the frame of %d by %d "
		    "pixels is outside the bounds of the helper\n", device,
		    st.w, st.h);
		goto out;
	}

	st.fd = fd;
	rv = scan_frames(&st, SCAN_SECONDS, out, err);
out:
	if (fd != -1)
		close(fd);
	return rv;
}
