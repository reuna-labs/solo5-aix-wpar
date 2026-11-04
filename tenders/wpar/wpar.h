/*
 * Copyright (c) 2015-2019 Contributors as noted in the AUTHORS file
 *
 * This file is part of Solo5, a sandboxed execution environment.
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * wpar.h: wpar tender internal API definitions.
 *
 * The wpar tender is the AIX WPAR port of Solo5's spt (Secure Process Tender).
 * It runs the unikernel as a plain AIX process inside an already-running WPAR,
 * replacing seccomp with the per-WPAR syscall bitmap provided by the
 * wpar_kmod kernel extension (see WPAR.md for details).
 *
 * Confinement contract:
 *   - The containerd WPAR shim creates the WPAR and pre-installs the syscall
 *     bitmap policy (via /dev/wpar_kmod) before exec-ing this tender.
 *   - The tender does NOT touch the bitmap itself; it simply loads and runs
 *     the unikernel.  Callers that want additional per-WPAR syscall restriction
 *     must use the annotation "io.containerd.wpar.solo5/syscall-profile" (see
 *     WPAR.md §Annotations).
 *   - The tender does honour --x-exec-heap for unikernels whose binding was
 *     compiled with an executable heap.
 */

#ifndef WPAR_H
#define WPAR_H

#include <inttypes.h>
#include <err.h>
#include <poll.h>

#include "../common/cc.h"
#include "../common/elf.h"
#include "../common/mft.h"
#include "spt_abi.h"

/*
 * The wpar tender reuses the spt ABI verbatim — spt_boot_info, memory layout
 * constants, ABI version, etc.  The unikernel ELF must be built for the
 * solo5-spt target; this tender is a drop-in alternative runner.
 */

/*
 * Maximum number of open host file descriptors (net + block combined).
 */
#define WPAR_MAX_FDS  MFT_MAX_ENTRIES

/*
 * Central tender state, analogous to struct spt on Linux.
 *
 * AIX does not have epoll or timerfd; we use poll(2) and setitimer(2) instead.
 * The spt_boot_info epollfd/timerfd fields are filled with AIX-appropriate
 * substitutes:
 *
 *   epollfd  → the index into pollfds[] of the internal timer slot (SPT_INTERNAL_TIMERFD)
 *   timerfd  → not used (set to -1); timing is driven by SIGALRM / setitimer.
 *
 * The unikernel binding on AIX is expected to use poll(2) directly via the fd
 * it receives in spt_boot_info.epollfd.  See WPAR.md §Syscall mapping.
 */
struct wpar {
    uint8_t  *mem;
    size_t    mem_size;
    struct spt_boot_info *bi;

    /* poll(2) array, index 0 reserved for the internal timer pipe. */
    struct pollfd  pollfds[WPAR_MAX_FDS + 1];
    int            npollfds;

    /* Read end of the timer-wakeup pipe (index 0 in pollfds[]). */
    int timerfd_r;
    /* Write end of the timer-wakeup pipe (written by SIGALRM handler). */
    int timerfd_w;
};

struct wpar *wpar_init(size_t mem_size);

int wpar_guest_mprotect(void *t_arg, uint64_t addr_start, uint64_t addr_end,
                        int prot);

void wpar_boot_info_init(struct wpar *w, uint64_t p_end, int cmdline_argc,
                         char **cmdline_argv, struct mft *mft, size_t mft_size);

void wpar_run(struct wpar *w, uint64_t p_entry);

/*
 * Operations provided by a module. (setup) is required; others are optional.
 */
struct wpar_module_ops {
    int (*setup)(struct wpar *w, struct mft *mft);
    int (*handle_cmdarg)(char *cmdarg, struct mft *mft);
    const char *(*usage)(void);
};

struct wpar_module {
    const char name[32];
    struct wpar_module_ops ops;
};

/*
 * Declare a module (placed in the "modules" ELF section, same scheme as spt).
 */
#define DECLARE_MODULE(module_name, ...)                                        \
    static struct wpar_module __module_##module_name                            \
        __attribute((section("modules"), aligned(8)))                           \
        __attribute((used)) = {.name = #module_name, .ops = {__VA_ARGS__}};

#endif /* WPAR_H */
