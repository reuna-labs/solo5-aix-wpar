# Solo5 WPAR Tender — Design Notes

The `solo5-wpar` tender is the AIX Workload Partition (WPAR) port of Solo5's
[spt (Secure Process Tender)](../spt/). It runs a unikernel built for the
`solo5-spt` ABI as a plain AIX process inside an already-running WPAR, reusing
the spt guest/tender ABI verbatim and replacing Linux-specific mechanisms with
their AIX equivalents.

---

## Architecture overview

```
 containerd WPAR shim
       │
       │  mkwpar / startwpar
       │  installs kmod syscall bitmap
       │  creates TAP interface
       ▼
  solo5-wpar (this tender, inside the WPAR)
       │
       │  mmap()  — guest memory at [SPT_HOST_MEM_BASE, mem_size)
       │  poll()  — replaces epoll_wait
       │  SIGALRM — replaces timerfd
       │  read()/write() on /dev/tapN — network I/O
       │  pread()/pwrite() on image file — block I/O
       ▼
  unikernel (solo5-spt ELF)
```

---

## Confinement

On Linux/spt, confinement is a seccomp-BPF filter loaded immediately before
the unikernel's entry point. On AIX the equivalent is the **per-WPAR syscall
bitmap** installed by the containerd WPAR shim via `/dev/wpar_kmod` (the
`KmodPolicyManager` in `containerd/internal/wpar/kmod_types_aix.go`).

This tender **does not** load any seccomp filter. It simply loads and runs the
unikernel; all system-call restriction is already in place when the tender
process starts.

### Annotation: `io.containerd.wpar.solo5/syscall-profile`

Callers that need a tighter syscall profile than the default WPAR bitmap can
set the container annotation:

```
io.containerd.wpar.solo5/syscall-profile: <profile-name>
```

The containerd WPAR shim reads this annotation in `service.go` (Create path)
and selects the corresponding bitmap from a compiled-in profile table before
calling `KmodPolicyManager.Activate()`. The tender itself never reads
annotations; it relies solely on what is already in the kernel.

Predefined profile names (to be registered in the shim):

| Profile name  | Description |
|---------------|-------------|
| `default`     | All syscalls allowed (permissive; same as no annotation). |
| `solo5-spt`   | Solo5 spt-equivalent minimal set: `write(fd=1)`, `exit_group`, `poll`, `read`/`write` on registered fds, `clock_gettime`, `setitimer`. |
| `solo5-spt-net` | `solo5-spt` + `read`/`write` on TAP fd. |
| `solo5-spt-block` | `solo5-spt` + `pread`/`pwrite` on block fd. |

The `solo5-spt` profile is the closest AIX equivalent to the Linux seccomp
filter applied by spt_core.c. See §Syscall mapping below.

---

## Syscall mapping: Linux spt → AIX wpar

The following table maps each syscall in the Linux spt seccomp allowlist to
its AIX counterpart. On AIX, syscalls are numbered differently and some
syscalls simply do not exist; in those cases the AIX equivalent is noted.

| Solo5 operation    | Linux spt syscall           | AIX equivalent                |
|--------------------|-----------------------------|-------------------------------|
| Console write      | `write(fd=1)`               | `write(fd=1)` — identical     |
| Exit               | `exit_group`                | `_exit` / `exit`              |
| Wait for events    | `epoll_pwait(epollfd)`      | `poll(fds, nfds, timeout)`    |
| Set timer          | `timerfd_settime(timerfd)`  | `setitimer(ITIMER_REAL, …)`   |
| Clock read         | `clock_gettime(CLOCK_MONOTONIC)` | `clock_gettime(CLOCK_MONOTONIC)` — identical |
| Clock read         | `clock_gettime(CLOCK_REALTIME)`  | `clock_gettime(CLOCK_REALTIME)` — identical |
| x86-64 TLS         | `arch_prctl(ARCH_SET_FS)`   | N/A (not needed on POWER)     |
| Network read       | `read(tap_fd)`              | `read(tap_fd)` — identical    |
| Network write      | `write(tap_fd)`             | `write(tap_fd)` — identical   |
| Block read         | `pread64(blk_fd, …)`        | `pread(blk_fd, …)` (no `64` suffix on AIX) |
| Block write        | `pwrite64(blk_fd, …)`       | `pwrite(blk_fd, …)` (no `64` suffix) |

### epoll → poll

The spt binding passes `spt_boot_info.epollfd` to `epoll_pwait()`. The AIX
binding instead calls `poll(2)` using `spt_boot_info.epollfd` directly as the
file descriptor representing the timer pipe's read end. Network fds are passed
to the binding via the manifest's `hostfd` field and polled inline.

The `struct epoll_event` is replaced by `struct pollfd`. Events returned by
`poll()` with `POLLIN` on the timer slot (index 0, identified by
`SPT_INTERNAL_TIMERFD`) are translated to timer expiry; events on any other
slot are translated to network-receive notifications.

### timerfd → SIGALRM + pipe

`timerfd_settime` does not exist on AIX. The wpar binding calls
`setitimer(ITIMER_REAL, &itimerval, NULL)` directly. The wpar tender installs
a `SIGALRM` handler that writes one byte to a self-pipe; the read end of the
pipe is slot 0 in the `pollfds[]` array and is conveyed to the unikernel as
`spt_boot_info.epollfd`. `spt_boot_info.timerfd` is set to `-1`.

Draining the pipe (consuming the byte) before the next `poll()` is the
responsibility of the unikernel binding.

---

## Networking

TAP networking uses the AIX **ethertap** pseudo-driver. Each TAP interface
has its own character device node at `/dev/tapN`. The interface must be
pre-created by the administrator or the containerd WPAR shim before the tender
is invoked:

```sh
# Create the TAP interface (run once per host or per container by the shim):
mkdev -l tap0 -c if -s tap -t ethertap

# Pass the interface name to the tender:
solo5-wpar --net:service=tap0 unikernel.elf
```

The containerd WPAR shim may also open the TAP fd before exec-ing the tender
and pass it via the `@<num>` syntax:

```sh
solo5-wpar --net:service=@5 unikernel.elf
```

This is the preferred path for container integration, because it allows the
shim to configure the interface (address, routing) before the unikernel
processes any packets.

---

## Storage

Block storage uses regular files or character-mode block devices, opened
`O_RDWR` and sized via `lseek(SEEK_END)`.

### LVM logical volumes (not implemented)

AIX LVM logical volumes (`/dev/fslv00`, `/dev/hd1`, etc.) can be passed as
the `--block:NAME=PATH` path. The current implementation uses
`lseek(SEEK_END)` to determine capacity, which works on AIX character-mode
devices. For environments where `lseek(SEEK_END)` is unreliable (e.g. a
volume group member that has not been varied on), the correct AIX approach is:

```c
#include <sys/ioctl.h>
#include <sys/devinfo.h>

struct devinfo di;
ioctl(fd, IOCINFO, &di);
off_t capacity = (off_t)di.un.dk.numblks * di.un.dk.blksize;
```

This is tracked as a future improvement. File a bug with the label
`wpar-lvm-support` to request it.

### Raw device slices — "r mode" (not implemented)

The annotation:

```
io.containerd.wpar.solo5/block-device-mode: r
```

is **reserved** for a future "raw slice" mode where the block backing store is
a raw AIX disk partition (`/dev/rhdiskN`, `/dev/rhd*`). In raw mode:

- The fd is opened with `O_RDWR | O_DIRECT` (AIX equivalent).
- Capacity is determined via `IOCINFO`.
- The container must run with `PV_PROC_SYSCONFIG` or equivalent privilege.
- Offset bounds enforcement becomes the responsibility of the tender (via an
  AIX-specific interposer or kmod bitmap rule on `pread`/`pwrite` arguments),
  since the WPAR kernel bitmap does not filter syscall arguments.

Neither the shim nor this tender currently reads or acts on this annotation.

---

## Build

The tender is enabled when `configure.sh` detects an AIX host toolchain
(`CONFIG_WPAR_TENDER=1`). On non-AIX hosts it is silently omitted.

```sh
# On AIX with GCC:
./configure.sh
make
# Produces: tenders/wpar/solo5-wpar
```

The tender is installed alongside `solo5-spt` and `solo5-hvt`:

```sh
make install
# Installs as: ${PREFIX}/bin/solo5-wpar
```

---

## Integration with containerd WPAR shim

The containerd WPAR shim (`containerd-shim-wpar-v1`) invokes the tender as
part of its `Start` lifecycle step. The full invocation sequence is:

1. Shim creates the WPAR (`mkwpar`).
2. Shim installs the syscall bitmap (`KmodPolicyManager.Activate`).
3. Shim creates/opens the TAP interface and passes the fd.
4. Shim exec-s `solo5-wpar` inside the WPAR:

   ```sh
   solo5-wpar \
     --mem=512 \
     --net:eth0=@<tap_fd> \
     --block:data=@<blk_fd> \
     /path/to/unikernel.spt \
     [unikernel-args…]
   ```

5. The tender maps guest memory, registers the poll array, and launches the
   unikernel.

The annotation `io.containerd.wpar.solo5/syscall-profile` (see §Confinement)
is consumed by the shim in step 2, not by the tender.
