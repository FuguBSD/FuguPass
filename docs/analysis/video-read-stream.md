# The read path of video(4)

|         |                                                                       |
| ------- | --------------------------------------------------------------------- |
| Status  | Record. It holds the kernel source that answers PROG-SCAN-9.          |
| Covers  | The frame loop of `fugupass-scan`.                                    |
| Decides | Nothing. PROG-SCAN-9 decides, and this record gives the source of it. |

## The question

`fugupass-scan` waits for each frame with `poll(2)`, and it then reads that
frame with `read(2)` (PROG-SCAN-9). Two statements about the OpenBSD kernel hold
that design, and this record gives the source of each one.

1. The read stream of `video(4)` starts at the first `poll(2)` call. The wait
   stands before the first `read(2)` call, so that wait reaches a started
   stream.
2. `O_NONBLOCK` reaches no read of `video(4)`. A read of a device that gives no
   frame blocks without end, and the flags of the descriptor change nothing. The
   `poll(2)` wait is therefore the one bound of the frame loop.

No camera exists in the test guest, and no test opens a video device. This
record is the ground of the design.

The developer read the OpenBSD source of the tag `OPENBSD_7_8` on 2026-09-22.
That release is the release of the test guest. The first line of each file below
holds the RCS revision of it.

| File                     | Revision | Date       |
| ------------------------ | -------- | ---------- |
| `sys/dev/video.c`        | 1.61     | 2025-04-15 |
| `sys/sys/conf.h`         | 1.168    | 2025-09-08 |
| `sys/kern/sys_generic.c` | 1.160    | 2024-12-30 |

## The start of the stream

`struct cdevsw` of `sys/sys/conf.h` holds no `d_poll` entry point. The last
field of that structure is `d_kqfilter`, and the macro `cdev_video_init` of the
same file gives the `kqfilter` routine of the driver to that field. A character
device of OpenBSD therefore answers `poll(2)` through `kqueue(2)`.

`ppollregister()` of `sys/kern/sys_generic.c` converts each `pollfd` into kqueue
events. The `POLLIN` request of `scan_wait()` takes the branch below, and
`kqueue_register()` then calls the `kqfilter` routine of the driver with that
filter.

```c
		if (pl[i].events & (POLLIN | POLLRDNORM)) {
			EV_SET(kevp, pl[i].fd, EVFILT_READ,
			    EV_ADD|EV_ENABLE|__EV_POLL, 0, 0,
			    (void *)(p->p_kq_serial + i));
```

`videokqfilter()` of `sys/dev/video.c` is that routine of `video(4)`. It takes
`EVFILT_READ` and no other filter, and it holds the guard below.

```c
	if (sc->sc_vidmode == VIDMODE_NONE && sc->hw_if->start_read) {
		if (sc->hw_if->start_read(sc->hw_hdl))
			return (ENXIO);
		sc->sc_vidmode = VIDMODE_READ;
	}
```

`videoread()` of the same file holds that guard as well: the same
`sc_vidmode == VIDMODE_NONE` test, the same `hw_if->start_read()` call, and the
same `VIDMODE_READ` mode after it. The two entry points therefore start one
stream. The first wait of the frame loop starts it, and each later wait finds
the mode `VIDMODE_READ` and starts nothing.

## The block of a read

`videoread()` takes an `ioflag` argument, and the body of it reads no bit of
that argument. The name `ioflag` stands one time in `sys/dev/video.c`: in the
parameter list of that function. The file holds no `O_NONBLOCK` and no
`IO_NDELAY`.

A read of a device that holds no frame reaches the sleep below.

```c
	if (sc->sc_frames_ready < 1) {
		/* block userland read until a frame is ready */
		error = msleep_nsec(sc, &sc->sc_mtx, PWAIT | PCATCH,
		    "vid_rd", INFSLP);
```

`INFSLP` is a sleep without end, and no argument of the read shortens it. A
descriptor of `O_NONBLOCK` therefore gives no `EAGAIN`, and it blocks as a
descriptor without that flag blocks. The call holds `PCATCH`, so a signal ends
the sleep and the read gives `EINTR`.

A design of `O_NONBLOCK` and a read loop would remove the one bound of the frame
loop. The `poll(2)` wait of `scan_wait()` keeps that bound.

## What stays unproven

No camera has driven this path. The test guest holds a `video(4)` device and no
camera behind it, so a ceremony of the guest stops at the open of that device
(PROG-SCAN-7). `src/regress/scan.c` gives the frame loop the read end of a pipe
that carries no byte. That probe proves the bound of the loop and the report of
it, and a pipe is no `video(4)` device. The probe therefore proves no statement
of this record.

A camera on the machine of an operator is the first exercise of the path. This
record is a reading of the kernel source, and it is no measurement.
