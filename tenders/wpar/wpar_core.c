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
 * wpar_core.c: Core functionality for the AIX WPAR tender.
 *
 * Design notes
 * ============
 *
 * Confinement
 * -----------
 * On Linux/spt the confinement is a seccomp BPF filter loaded just before
 * spt_launch().  On AIX the equivalent is the per-WPAR syscall bitmap
 * registered by the containerd WPAR shim via /dev/wpar_kmod before this
 * process was exec'd.  This tender therefore contains NO seccomp logic.
 *
 * Event / timer model
 * -------------------
 * The spt binding uses epoll + timerfd.  AIX provides neither.  We replace
 * them with:
 *
 *   - poll(2)      : replaces epoll_wait / epoll_pwait
 *   - pipe(2)      : a self-pipe ("timer pipe") replaces timerfd; a SIGALRM
 *                    handler writes one byte to the write end whenever the
 *                    timer fires.  The unikernel sees the read end as its
 *                    "timerfd".
 *   - setitimer(2) : replaces timerfd_settime.  The unikernel calls
 *                    setitimer(ITIMER_REAL, …) directly; the timer pipe and
 *                    SIGALRM bridge the gap to poll(2).
 *
 * The spt_boot_info fields are populated as follows:
 *
 *   epollfd  ← index 0 (the poll fd array position of the timer pipe read-end)
 *   timerfd  ← -1  (setitimer is used instead; the unikernel must not call
 *                    timerfd_settime, which is not available on AIX)
 *
 * Memory layout
 * -------------
 * Identical to spt: the tender is linked/loaded at a high address (PIE or
 * -Ttext-segment) and the guest region starts at SPT_HOST_MEM_BASE, giving
 * the guest the illusion that its physical memory starts at address 0 while
 * the tender occupies a disjoint region above 4 GB.
 *
 * vm.mmap_min_addr does not exist on AIX; mmap of low addresses is allowed.
 * We therefore skip the vm.mmap_min_addr workaround and map from
 * SPT_HOST_MEM_BASE directly (same value as Linux, kept for ABI compatibility).
 */

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <poll.h>

#include "wpar.h"

/*
 * Defined by the standard AIX ld linker script to the lowest address of the
 * text segment.  Used to verify address-space separation between tender and
 * guest.
 */
extern long __executable_start;

static bool use_exec_heap = false;

/*
 * SIGALRM handler: write one byte to the timer pipe so that the unikernel's
 * poll() wakes up with the timer slot readable.
 *
 * SA_RESTART is NOT set — the signal should interrupt blocking poll() calls.
 */
static int g_timerfd_w = -1;

static void sigalrm_handler(int sig __attribute__((unused)))
{
    char one = 1;
    /*
     * Write a single byte; ignore EAGAIN (pipe already has data pending from
     * a previous un-consumed timer tick).
     */
    ssize_t n = write(g_timerfd_w, &one, 1);
    (void)n;
}

struct wpar *wpar_init(size_t mem_size)
{
    struct wpar *w = malloc(sizeof(struct wpar));
    if (w == NULL)
        err(1, "malloc");
    memset(w, 0, sizeof(struct wpar));

#if defined(__PIE__)
    assert((uint64_t)&__executable_start >= (1ULL << 32));
    assert((uint64_t)(mem_size - 1) < (uint64_t)&__executable_start);
#else
    assert((uint64_t)&__executable_start >= (1ULL << 30));
    if ((uint64_t)(mem_size - 1) >= (uint64_t)&__executable_start) {
        uint64_t max_mem_size_mb = (uint64_t)&__executable_start >> 20;
        warnx("Maximum guest memory size (%lu MB) exceeded.", max_mem_size_mb);
        errx(1, "Either decrease --mem, or recompile solo5-wpar as a PIE executable.");
    }
#endif

    /*
     * Map guest memory.  On AIX, mmap at low addresses is unrestricted, so
     * SPT_HOST_MEM_BASE (0x10000) is safe to use directly.  We still apply
     * the same offset trick as spt so that guest address 0 is unmapped.
     */
    int prot = PROT_READ | PROT_WRITE | (use_exec_heap ? PROT_EXEC : 0);
    w->mem = mmap((void *)(uintptr_t)SPT_HOST_MEM_BASE,
                  mem_size - SPT_HOST_MEM_BASE,
                  prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (w->mem == MAP_FAILED)
        err(1, "Error allocating guest memory");
    assert(w->mem == (void *)(uintptr_t)SPT_HOST_MEM_BASE);
    w->mem -= SPT_HOST_MEM_BASE;
    w->mem_size = mem_size;

    /*
     * Create the timer self-pipe.  Index 0 in pollfds[] is reserved for the
     * read end; the write end is used by sigalrm_handler.
     */
    int pipefds[2];
    if (pipe(pipefds) == -1)
        err(1, "pipe() failed");
    if (fcntl(pipefds[0], F_SETFL, O_NONBLOCK) == -1)
        err(1, "fcntl(timer pipe read end) failed");
    if (fcntl(pipefds[1], F_SETFL, O_NONBLOCK) == -1)
        err(1, "fcntl(timer pipe write end) failed");

    w->timerfd_r = pipefds[0];
    w->timerfd_w = pipefds[1];
    g_timerfd_w  = pipefds[1];

    /* Slot 0: the timer pipe read end, identified as SPT_INTERNAL_TIMERFD. */
    w->pollfds[0].fd     = w->timerfd_r;
    w->pollfds[0].events = POLLIN;
    w->npollfds = 1;

    /* Install SIGALRM handler. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigalrm_handler;
    sigemptyset(&sa.sa_mask);
    /* Do NOT set SA_RESTART — we need the signal to interrupt poll(). */
    if (sigaction(SIGALRM, &sa, NULL) == -1)
        err(1, "sigaction(SIGALRM) failed");

    return w;
}

int wpar_guest_mprotect(void *t_arg, uint64_t addr_start, uint64_t addr_end,
                        int prot)
{
    struct wpar *w = t_arg;

    assert(addr_start <= w->mem_size);
    assert(addr_end   <= w->mem_size);
    assert(addr_start < addr_end);

    uint8_t *vaddr_start = w->mem + addr_start;
    assert(vaddr_start >= w->mem);
    size_t size = addr_end - addr_start;
    assert(size > 0 && size <= w->mem_size);

    return mprotect(vaddr_start, size, prot);
}

static void setup_cmdline(uint8_t *cmdline, int argc, char **argv)
{
    size_t cmdline_free = SPT_CMDLINE_SIZE;

    cmdline[0] = 0;

    for (; *argv; argc--, argv++) {
        size_t alen = snprintf((char *)cmdline, cmdline_free, "%s%s", *argv,
                               (argc > 1) ? " " : "");
        if (alen >= cmdline_free) {
            errx(1, "Guest command line too long (max=%d characters)",
                 SPT_CMDLINE_SIZE - 1);
            break;
        }
        cmdline_free -= alen;
        cmdline      += alen;
    }
}

void wpar_boot_info_init(struct wpar *w, uint64_t p_end, int cmdline_argc,
                         char **cmdline_argv, struct mft *mft, size_t mft_size)
{
    uint64_t lowmem_pos = SPT_BOOT_INFO_BASE;

    struct spt_boot_info *bi =
        (struct spt_boot_info *)(w->mem + lowmem_pos);
    lowmem_pos += sizeof(struct spt_boot_info);

    bi->mem_size   = w->mem_size;
    bi->kernel_end = p_end;

    /*
     * epollfd: We pass the poll-array slot index (0) that the unikernel should
     * treat as the epoll fd token.  On AIX the unikernel binding calls poll(2)
     * directly; the actual file descriptor is w->timerfd_r.  Bindings compiled
     * for solo5-spt that use epoll_pwait(epollfd, …) will receive -1 for
     * ENOSYS and must fall back to poll(2) themselves.
     *
     * timerfd: -1 on AIX.  The unikernel must use setitimer(ITIMER_REAL,…)
     * instead of timerfd_settime.
     */
    bi->epollfd = w->timerfd_r; /* use the pipe read-fd directly */
    bi->timerfd = -1;

    bi->mft = (void *)lowmem_pos;
    memcpy(w->mem + lowmem_pos, mft, mft_size);
    lowmem_pos += mft_size;

    bi->cmdline = (void *)lowmem_pos;
    setup_cmdline(w->mem + lowmem_pos, cmdline_argc, cmdline_argv);
    lowmem_pos += SPT_CMDLINE_SIZE;

    w->bi = bi;
}

/*
 * Defined in wpar_launch_ppc64.S.
 */
extern void wpar_launch(uint64_t stack_start, void (*fn)(void *), void *arg);

void wpar_run(struct wpar *w, uint64_t p_entry)
{
    typedef void (*start_fn_t)(void *arg);
    start_fn_t start_fn = (start_fn_t)(w->mem + p_entry);

    /*
     * PPC64 (POWER) stack alignment: 16 bytes, minimum frame size 112 bytes.
     * We place the initial stack pointer at the top of guest memory, aligned
     * down by 112 bytes to leave a full frame as required by the ABI.
     */
    uint64_t sp = w->mem_size - 112;

    /*
     * There is no seccomp filter to load on AIX.  The per-WPAR syscall bitmap
     * policy has already been installed by the containerd WPAR shim before
     * exec'ing this tender.  We simply jump into the unikernel.
     */
    wpar_launch(sp, start_fn, w->mem + SPT_BOOT_INFO_BASE);

    abort(); /* wpar_launch() does not return */
}

static int handle_cmdarg(char *cmdarg,
                         struct mft *mft __attribute__((unused)))
{
    if (!strncmp("--x-exec-heap", cmdarg, 13)) {
        warnx("WARNING: The use of --x-exec-heap is dangerous and not"
              " recommended as it makes the heap and stack executable.");
        use_exec_heap = true;
        return 0;
    }
    return -1;
}

static int setup(struct wpar *w __attribute__((unused)),
                 struct mft   *mft __attribute__((unused)))
{
    /*
     * No seccomp policy to populate.  All confinement is provided by the
     * per-WPAR syscall bitmap installed by the containerd WPAR shim.  See
     * WPAR.md §Confinement for details.
     */
    return 0;
}

static const char *usage(void)
{
    return "--x-exec-heap (make the heap executable)."
           " WARNING: This option is dangerous and not recommended as it"
           " makes the heap and stack executable.";
}

DECLARE_MODULE(core, .setup = setup, .handle_cmdarg = handle_cmdarg,
               .usage = usage)
