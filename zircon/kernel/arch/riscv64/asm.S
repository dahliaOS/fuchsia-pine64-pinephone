// Copyright 2020 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <asm.h>
#include <arch/riscv64.h>
#include <arch/asm_macros.h>

#define REGOFF(x) ((x) * 8)

// void riscv64_context_switch(vaddr_t* old_sp, vaddr_t new_sp);
FUNCTION(riscv64_context_switch)
    sd    ra, REGOFF(0)(a0)
    sd    sp, REGOFF(1)(a0)
    sd    s0, REGOFF(2)(a0)
    sd    s1, REGOFF(3)(a0)
    sd    s2, REGOFF(4)(a0)
    sd    s3, REGOFF(5)(a0)
    sd    s4, REGOFF(6)(a0)
    sd    s5, REGOFF(7)(a0)
    sd    s6, REGOFF(8)(a0)
    sd    s7, REGOFF(9)(a0)
    sd    s8, REGOFF(10)(a0)
    sd    s9, REGOFF(11)(a0)
    sd    s10, REGOFF(12)(a0)
    sd    s11, REGOFF(13)(a0)

    ld    s11, REGOFF(13)(a1)
    ld    s10, REGOFF(12)(a1)
    ld    s9, REGOFF(11)(a1)
    ld    s8, REGOFF(10)(a1)
    ld    s7, REGOFF(9)(a1)
    ld    s6, REGOFF(8)(a1)
    ld    s5, REGOFF(7)(a1)
    ld    s4, REGOFF(6)(a1)
    ld    s3, REGOFF(5)(a1)
    ld    s2, REGOFF(4)(a1)
    ld    s1, REGOFF(3)(a1)
    ld    s0, REGOFF(2)(a1)
    ld    sp, REGOFF(1)(a1)
    ld    ra, REGOFF(0)(a1)

    ret
END_FUNCTION(riscv_context_switch)

/* top level exception handler for riscv64 in non vectored mode */
.balign 4
FUNCTION(riscv64_exception_entry)
    /* dump all the callee trashed regs on the stack */
    addi   sp, sp, -REGOFF(20) // subtract a multiple of 16 to align the stack in 32bit
    sd     t6, REGOFF(17)(sp)
    sd     t5, REGOFF(16)(sp)
    sd     t4, REGOFF(15)(sp)
    sd     t3, REGOFF(14)(sp)
    sd     t2, REGOFF(13)(sp)
    sd     t1, REGOFF(12)(sp)
    sd     t0, REGOFF(11)(sp)
    sd     a7, REGOFF(10)(sp)
    sd     a6, REGOFF(9)(sp)
    sd     a5, REGOFF(8)(sp)
    sd     a4, REGOFF(7)(sp)
    sd     a3, REGOFF(6)(sp)
    sd     a2, REGOFF(5)(sp)
    sd     a1, REGOFF(4)(sp)
    sd     a0, REGOFF(3)(sp)
    sd     ra, REGOFF(2)(sp)
    csrr   t0, RISCV_CSR_XSTATUS
    sd     t0, REGOFF(1)(sp)
    csrr   a0, RISCV_CSR_XCAUSE
    csrr   a1, RISCV_CSR_XEPC
    sd     a1, REGOFF(0)(sp)
    mv     a2, sp

    jal    riscv64_exception_handler

    /* put everything back */
    ld     t0, REGOFF(0)(sp)
    csrw   RISCV_CSR_XEPC, t0
    ld     t0, REGOFF(1)(sp)
    csrw   RISCV_CSR_XSTATUS, t0

    ld     ra, REGOFF(2)(sp)
    ld     a0, REGOFF(3)(sp)
    ld     a1, REGOFF(4)(sp)
    ld     a2, REGOFF(5)(sp)
    ld     a3, REGOFF(6)(sp)
    ld     a4, REGOFF(7)(sp)
    ld     a5, REGOFF(8)(sp)
    ld     a6, REGOFF(9)(sp)
    ld     a7, REGOFF(10)(sp)
    ld     t0, REGOFF(11)(sp)
    ld     t1, REGOFF(12)(sp)
    ld     t2, REGOFF(13)(sp)
    ld     t3, REGOFF(14)(sp)
    ld     t4, REGOFF(15)(sp)
    ld     t5, REGOFF(16)(sp)
    ld     t6, REGOFF(17)(sp)
    addi   sp, sp, REGOFF(20)

    RISCV_XRET
END_FUNCTION(riscv64_exception_entry)
