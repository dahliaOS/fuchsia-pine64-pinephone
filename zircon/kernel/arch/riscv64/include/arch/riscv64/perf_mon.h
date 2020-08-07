// Copyright 2020 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

// This file contains declarations internal to riscv64.
// Declarations visible outside of riscv64 belong in arch_perfmon.h.

#ifndef ZIRCON_KERNEL_ARCH_RISCV64_INCLUDE_ARCH_RISCV64_PERF_MON_H_
#define ZIRCON_KERNEL_ARCH_RISCV64_INCLUDE_ARCH_RISCV64_PERF_MON_H_

#include <arch/riscv64.h>

void riscv64_pmi_interrupt_handler(const iframe_t* frame);

#endif  // ZIRCON_KERNEL_ARCH_RISCV64_INCLUDE_ARCH_RISCV64_PERF_MON_H_
