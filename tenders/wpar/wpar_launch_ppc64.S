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
 * wpar_launch_ppc64.S: unikernel launch stub for 64-bit POWER (AIX).
 *
 * void wpar_launch(uint64_t stack_start, void (*fn)(void *), void *arg);
 *
 * Calling convention (AIX / ELF PPC64 ELFv1 — the AIX variant uses ELFv1
 * function descriptors; ELFv2 is the Linux-on-POWER convention):
 *
 *   r3 = stack_start   — new stack pointer
 *   r4 = fn            — function descriptor pointer (unikernel entry)
 *   r5 = arg           — argument to pass to fn
 *
 * ELFv1 function descriptors
 * ---------------------------
 * On AIX, a function pointer is a pointer to a three-word descriptor:
 *
 *   word 0: code address
 *   word 1: TOC pointer (r2)
 *   word 2: environment pointer (r11, used by nested functions / closures)
 *
 * The unikernel solo5-spt binary is compiled as a freestanding ELF that does
 * not use function descriptors — its entry point is a plain code address.
 * We therefore treat fn as a direct code address, not a descriptor, matching
 * the behaviour of the PPC64le Linux spt_launch.
 *
 * Steps:
 *   1. Load new stack pointer from r3 → r1.
 *   2. Move arg (r5) → r3  (first argument register).
 *   3. Load code address from fn (r4) → CTR.
 *   4. Branch to CTR (bctr).
 *
 * The minimum stack frame (112 bytes, per POWER ABI) has already been
 * subtracted from stack_start in wpar_core.c.
 */

#define ENTRY(x) .text; .globl x; .type x,@function; x:
#define END(x)   .size x, . - x

/*
 * r3: stack pointer to use
 * r4: function (plain code address) to call
 * r5: argument to pass to function
 */
ENTRY(wpar_launch)
	mr   %r1, %r3       /* load new stack pointer                */
	mr   %r3, %r5       /* move arg to first argument register   */
	mtctr %r4           /* load function address into CTR        */
	bctr                /* branch to CTR (does not return)       */
END(wpar_launch)
