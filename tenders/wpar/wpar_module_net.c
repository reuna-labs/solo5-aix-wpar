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
 * wpar_module_net.c: Network device module for the AIX WPAR tender.
 *
 * This module is a port of spt_module_net.c with the following changes:
 *
 *   - No seccomp rules to add; all I/O is permitted by the WPAR kmod policy.
 *   - epoll_ctl() is replaced by registering the TAP fd in the tender's
 *     pollfds[] array (struct wpar).  The unikernel receives the poll slot
 *     index as its "handle" via the manifest entry's hostfd; the fd stored
 *     in mft->e[i].b.hostfd is the real file descriptor used by poll(2).
 *
 * TAP on AIX
 * ----------
 * AIX provides TAP via the ethertap pseudo-driver.  A TAP interface named
 * "tapN" is created with:
 *
 *     mkdev -l tapN -c if -s tap -t ethertap
 *
 * and opened as:
 *
 *     fd = open("/dev/tapN", O_RDWR | O_NONBLOCK)
 *
 * There is no /dev/net/tun universal device; each tap interface has its own
 * character device node at /dev/tapN.  tap_attach.c handles this in the
 * __aix__ branch.
 *
 * The MTU is queried via SIOCGIFMTU exactly as on Linux and BSD.
 *
 * The @<num> pre-existing fd syntax is supported for container runtimes
 * (e.g. the containerd WPAR shim) that open and pre-configure the TAP fd
 * before exec'ing the tender.
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>

#ifdef __aix__
#include <net/if.h>
#else
#include <linux/if.h>
#endif

#include "../common/tap_attach.h"
#include "wpar.h"

static bool module_in_use;
static char ifaces[MFT_MAX_ENTRIES][IFNAMSIZ];

static int handle_cmdarg(char *cmdarg, struct mft *mft)
{
    enum { opt_net, opt_net_mac } which;

    if (strncmp("--net:", cmdarg, 6) == 0)
        which = opt_net;
    else if (strncmp("--net-mac:", cmdarg, 10) == 0)
        which = opt_net_mac;
    else
        return -1;

    char name[MFT_NAME_SIZE];
    char iface[IFNAMSIZ + 1];
    int rc;
    unsigned index;

    if (which == opt_net) {
        rc = sscanf(cmdarg,
                    "--net:%" XSTR(MFT_NAME_MAX) "[A-Za-z0-9]="
                                                 "%" XSTR(IFNAMSIZ) "s",
                    name, iface);
        if (rc != 2)
            return -1;
        if (strlen(iface) > IFNAMSIZ - 1)
            return -1;
        struct mft_entry *e =
            mft_get_by_name(mft, name, MFT_DEV_NET_BASIC, &index);
        if (e == NULL) {
            warnx("Resource not declared in manifest: '%s'", name);
            return -1;
        }
        memcpy(ifaces[index], iface, sizeof(ifaces[index]));
        e->attached    = true;
        module_in_use  = true;
    } else if (which == opt_net_mac) {
        uint8_t mac[6];
        rc = sscanf(cmdarg,
                    "--net-mac:%" XSTR(MFT_NAME_MAX) "[A-Za-z0-9]="
                                                     "%02" SCNx8 ":%02" SCNx8
                                                     ":%02" SCNx8 ":"
                                                     "%02" SCNx8 ":%02" SCNx8
                                                     ":%02" SCNx8,
                    name, &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        if (rc != 7)
            return -1;
        struct mft_entry *e =
            mft_get_by_name(mft, name, MFT_DEV_NET_BASIC, NULL);
        if (e == NULL) {
            warnx("Resource not declared in manifest: '%s'", name);
            return -1;
        }
        memcpy(e->u.net_basic.mac, mac, sizeof mac);
    }

    return 0;
}

static int setup(struct wpar *w, struct mft *mft)
{
    if (!module_in_use)
        return 0;

    for (unsigned i = 0; i != mft->entries; i++) {
        if (mft->e[i].type != MFT_DEV_NET_BASIC || !mft->e[i].attached)
            continue;

        int mtu = -1;
        int fd  = tap_attach(ifaces[i], &mtu);
        if (fd < 0 || mtu < 0)
            err(1, "Could not attach interface: %s", ifaces[i]);

        mft->e[i].u.net_basic.mtu = mtu;
        mft->e[i].b.hostfd        = fd;

        char no_mac[6] = {0};
        if (memcmp(mft->e[i].u.net_basic.mac, no_mac, sizeof no_mac) == 0)
            tap_attach_genmac(mft->e[i].u.net_basic.mac);

        /*
         * Register the TAP fd in the poll array so the unikernel can block on
         * network I/O via poll(2).  The slot index (w->npollfds before the
         * increment) is the value returned as data.u64 in the analogous epoll
         * event; on AIX the unikernel receives it as the event "key" from
         * poll(2).
         *
         * The manifest index i matches the solo5_handle_t, so the unikernel
         * can map from handle → slot.  We store the slot index in e->b.hostfd
         * for now (same as the fd, since poll() takes the actual fd — the
         * unikernel binding on AIX calls poll() directly with fds it inherits).
         */
        if (w->npollfds >= WPAR_MAX_FDS + 1)
            errx(1, "Too many network/block devices (max %d)", WPAR_MAX_FDS);

        w->pollfds[w->npollfds].fd     = fd;
        w->pollfds[w->npollfds].events = POLLIN;
        w->npollfds++;

        /*
         * No seccomp rules to add: all read()/write() calls are covered by
         * the per-WPAR kmod bitmap installed by the containerd WPAR shim.
         */
    }

    return 0;
}

static const char *usage(void)
{
    return "--net:NAME=IFACE | @NN (attach tap at IFACE or at fd @NN as "
           "network NAME)\n"
           "  [ --net-mac:NAME=HWADDR ] (set HWADDR for network NAME)";
}

DECLARE_MODULE(net, .setup = setup, .handle_cmdarg = handle_cmdarg,
               .usage = usage)
