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
 * wpar_module_block.c: Block device module for the AIX WPAR tender.
 *
 * This module is a straightforward port of spt_module_block.c.  The only
 * material difference is the absence of seccomp rules: the per-WPAR kmod
 * bitmap installed by the containerd shim is the confinement mechanism on
 * AIX.  All pread/pwrite calls within the capacity bounds are implicitly
 * permitted.
 *
 * LVM and raw device slices (NOTE — not implemented)
 * ---------------------------------------------------
 * On AIX, block storage may come from one of three sources:
 *
 *   1. Regular files (current implementation) — simplest and fully portable.
 *      Open O_RDWR, capacity via lseek(SEEK_END).
 *
 *   2. LVM logical volumes (e.g. /dev/fslv00) — expose a raw block device.
 *      The caller would pass the LVM LV device path via --block:NAME=/dev/fslvNN.
 *      Capacity must be obtained via ioctl(IOCINFO) on AIX (not BLKGETSIZE64
 *      which is Linux-only); see <sys/ioctl.h> and devinfo structure.  The
 *      existing block_attach() falls back to lseek(SEEK_END) which works on
 *      AIX character-mode LV devices opened O_RDWR, but is less reliable than
 *      IOCINFO for raw volume group elements.  An AIX-specific block_attach
 *      variant using IOCINFO should be added when LV backing is needed.
 *
 *   3. Raw device slices (rX mode) — AIX 's "raw disk" access via /dev/rhdiskN
 *      or /dev/rhd*.  Opening in O_RDWR gives direct sector access.  Capacity
 *      via IOCINFO or lseek(SEEK_END).  Requires the container to run with
 *      PV_PROC_SYSCONFIG or similar privilege.  Not implemented here; the
 *      containerd WPAR shim annotation
 *      "io.containerd.wpar.solo5/block-device-mode" with value "r" (raw) is
 *      reserved for this purpose but not yet consumed by either the shim or
 *      the tender.
 *
 * Until LVM/raw support is required, the regular-file path is sufficient for
 * disk-image-backed unikernels.
 */

#define _FILE_OFFSET_BITS 64
#include <assert.h>
#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "../common/block_attach.h"
#include "wpar.h"

static bool module_in_use;

#define BLOCK_PREFIX             "--block:"
#define BLOCK_SECTOR_SIZE_PREFIX "--block-sector-size:"

static int handle_cmdarg(char *cmdarg, struct mft *mft)
{
    enum {
        opt_block,
        opt_block_size,
    } which;

    if (strncmp(BLOCK_PREFIX, cmdarg, sizeof(BLOCK_PREFIX) - 1) == 0)
        which = opt_block;
    else if (strncmp(BLOCK_SECTOR_SIZE_PREFIX, cmdarg,
                     sizeof(BLOCK_SECTOR_SIZE_PREFIX) - 1) == 0)
        which = opt_block_size;
    else
        return -1;

    char name[MFT_NAME_SIZE];

    if (which == opt_block) {
        char path[PATH_MAX + 1];
        int rc = sscanf(cmdarg,
                        "--block:%" XSTR(MFT_NAME_MAX) "[A-Za-z0-9]="
                                                       "%" XSTR(PATH_MAX) "s",
                        name, path);
        if (rc != 2)
            return -1;

        struct mft_entry *e =
            mft_get_by_name(mft, name, MFT_DEV_BLOCK_BASIC, NULL);
        if (e == NULL) {
            warnx("Resource not declared in manifest: '%s'", name);
            return -1;
        }
        off_t capacity;
        int fd = block_attach(path, &capacity);
        e->u.block_basic.capacity = capacity;
        e->b.hostfd   = fd;
        e->attached   = true;
        module_in_use = true;
    } else if (which == opt_block_size) {
        uint16_t block_size;
        int rc = sscanf(cmdarg,
                        "--block-sector-size:%" XSTR(MFT_NAME_MAX) "[A-Za-z0-9]="
                                                                    "%hu",
                        name, &block_size);
        if (rc != 2)
            return -1;
        if (block_size < 512 || block_size & (block_size - 1)) {
            warnx("Block size must be a power of 2 greater than or equal 512");
            return -1;
        }
        struct mft_entry *e =
            mft_get_by_name(mft, name, MFT_DEV_BLOCK_BASIC, NULL);
        if (e == NULL) {
            warnx("Resource not declared in manifest: '%s'", name);
            return -1;
        }
        e->u.block_basic.block_size = block_size;
    }

    return 0;
}

static int setup(struct wpar *w __attribute__((unused)), struct mft *mft)
{
    if (!module_in_use)
        return 0;

    for (unsigned i = 0; i != mft->entries; i++) {
        if (mft->e[i].type != MFT_DEV_BLOCK_BASIC || !mft->e[i].attached)
            continue;

        if (mft->e[i].u.block_basic.block_size == 0)
            mft->e[i].u.block_basic.block_size = 512;

        const char *name       = mft->e[i].name;
        uint16_t    block_size = mft->e[i].u.block_basic.block_size;
        off_t       capacity   = mft->e[i].u.block_basic.capacity;

        assert((block_size & (block_size - 1)) == 0);
        if ((capacity & (block_size - 1)) != 0)
            errx(1,
                 "%." XSTR(MFT_NAME_MAX) "s: Backing storage size must be "
                                         "block aligned (%hu bytes)",
                 name, block_size);
        if (capacity < block_size)
            errx(1,
                 "%." XSTR(MFT_NAME_MAX) "s: Backing storage must be at least "
                                         "1 block (%hu bytes) in size",
                 name, block_size);

        /*
         * No seccomp rules to add.  On AIX all pread/pwrite(2) calls for the
         * block fd are permitted by the per-WPAR kmod bitmap.  The capacity
         * boundary is enforced by the unikernel binding (which must not issue
         * pread/pwrite beyond capacity - block_size), not by the tender.
         *
         * If stricter bounds enforcement is desired in the future, an AIX
         * equivalent would be a libc interposer or a kmod bitmap rule that
         * intercepts pread/pwrite and validates the offset argument before
         * forwarding.  That mechanism is out of scope here.
         */
    }

    return 0;
}

static const char *usage(void)
{
    return "--block:NAME=PATH (attach block device/file at PATH as block "
           "storage NAME)\n"
           "  [ --block-sector-size:NAME=SECTORSIZE ] (set sector size for "
           "block device NAME; must be a power of two >= 512)\n"
           "\n"
           "NOTE: LVM logical volumes (/dev/fslvNN) and raw disk slices\n"
           "      (/dev/rhdiskN) may be used as PATH, but the tender opens\n"
           "      them as regular files (O_RDWR + lseek for capacity).\n"
           "      For proper IOCINFO-based capacity detection on raw devices,\n"
           "      see the 'r mode' note in wpar_module_block.c and WPAR.md.";
}

DECLARE_MODULE(block, .setup = setup, .handle_cmdarg = handle_cmdarg,
               .usage = usage)
