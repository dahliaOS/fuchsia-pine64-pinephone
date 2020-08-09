// Copyright 2016 The Fuchsia Authors
// Copyright (c) 2014 Travis Geiselbrecht
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT
#include <bits.h>
#include <debug.h>
#include <inttypes.h>
#include <lib/counters.h>
#include <lib/crashlog.h>
#include <platform.h>
#include <stdio.h>
#include <trace.h>
#include <zircon/syscalls/exception.h>
#include <zircon/types.h>

#include <arch/arch_ops.h>
#include <arch/exception.h>
#include <arch/thread.h>
#include <arch/user_copy.h>
#include <kernel/interrupt.h>
#include <kernel/thread.h>
#include <pretty/hexdump.h>
#include <vm/fault.h>
#include <vm/vm.h>

/* called from assembly */
extern "C" void arch_iframe_process_pending_signals(iframe_t* iframe) {
}

void arch_dump_exception_context(const arch_exception_context_t* context) {
}

void arch_fill_in_exception_context(const arch_exception_context_t* arch_context,
                                    zx_exception_report_t* report) {
}

zx_status_t arch_dispatch_user_policy_exception(void) {
    return ZX_OK;
}

bool arch_install_exception_context(Thread* thread, const arch_exception_context_t* context) {
    return true;
}

void arch_remove_exception_context(Thread* thread) { }

extern "C" void riscv64_exception_handler(long cause, ulong epc, struct riscv_short_iframe *frame) {
/*    LTRACEF("hart %u cause %#lx epc %#lx status %#lx\n",
            riscv_current_hart(), cause, epc, frame->status);

    enum handler_return ret = INT_NO_RESCHEDULE;

    // top bit of the cause register determines if it's an interrupt or not
    if (cause < 0) {
        switch (cause & LONG_MAX) {
#if WITH_SMP
            case RISCV_EXCEPTION_XSWI: // machine software interrupt
                ret = riscv_software_exception();
                break;
#endif
            case RISCV_EXCEPTION_XTIM: // machine timer interrupt
                ret = riscv_timer_exception();
                break;
            case RISCV_EXCEPTION_XEXT: // machine external interrupt
                ret = riscv_platform_irq();
                break;
            default:
                panic("unhandled exception cause %#lx, epc %#lx, tval %#lx\n", cause, epc, riscv_csr_read(RISCV_CSR_XTVAL));
        }
    } else {
        // all synchronous traps go here
        panic("unhandled exception cause %#lx, epc %#lx, tval %#lx\n", cause, epc, riscv_csr_read(RISCV_CSR_XTVAL));
    }

    if (ret == INT_RESCHEDULE) {
        thread_preempt();
    } */
}
