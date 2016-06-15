// Copyright 2016 The Fuchsia Authors
// Copyright (c) 2012-2015 Travis Geiselbrecht
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <arch.h>
#include <err.h>
#include <debug.h>
#include <trace.h>
#include <dev/interrupt/arm_gicv2m.h>
#include <dev/interrupt/arm_gicv2m_msi.h>
#include <dev/pcie.h>
#include <dev/timer/arm_generic.h>
#include <dev/uart.h>
#include <dev/virtio.h>
#include <lk/init.h>
#include <kernel/vm.h>
#include <kernel/spinlock.h>
#include <platform.h>
#include <platform/gic.h>
#include <dev/interrupt.h>
#include <dev/interrupt_event.h>
#include <platform/qemu-virt.h>
#include <libfdt.h>
#include "platform_p.h"

#define DEFAULT_MEMORY_SIZE (MEMSIZE) /* try to fetch from the emulator via the fdt */

static const pcie_ecam_range_t PCIE_ECAM_WINDOWS[] = {
    {
        .io_range  = { .bus_addr = PCIE_ECAM_BASE_PHYS, .size = PCIE_ECAM_SIZE },
        .bus_start = 0x00,
        .bus_end   = (uint8_t)(PCIE_ECAM_SIZE / PCIE_ECAM_BYTE_PER_BUS) - 1,
    },
};

static const paddr_t GICV2M_REG_FRAMES[] = { GICV2M_FRAME_PHYS };

static status_t qemu_pcie_irq_swizzle(const pcie_common_state_t* common,
                                      uint pin,
                                      uint *irq)
{
    DEBUG_ASSERT(common && irq);
    DEBUG_ASSERT(pin < PCIE_MAX_LEGACY_IRQ_PINS);

    if (common->bus_id != 0)
        return ERR_NOT_FOUND;

    *irq = PCIE_INT_BASE + ((pin + common->dev_id) % PCIE_MAX_LEGACY_IRQ_PINS);
    return NO_ERROR;
}

static pcie_init_info_t PCIE_INIT_INFO = {
    .ecam_windows         = PCIE_ECAM_WINDOWS,
    .ecam_window_count    = countof(PCIE_ECAM_WINDOWS),
    .mmio_window_lo       = { .bus_addr = PCIE_MMIO_BASE_PHYS, .size = PCIE_MMIO_SIZE },
    .mmio_window_hi       = { .bus_addr = 0,                   .size = 0 },
    .pio_window           = { .bus_addr = PCIE_PIO_BASE_PHYS,  .size = PCIE_PIO_SIZE },
    .legacy_irq_swizzle   = qemu_pcie_irq_swizzle,
    .alloc_msi_block      = arm_gicv2m_alloc_msi_block,
    .free_msi_block       = arm_gicv2m_free_msi_block,
    .register_msi_handler = arm_gicv2m_register_msi_handler,
    .mask_unmask_msi      = arm_gicv2m_mask_unmask_msi,
};

/* initial memory mappings. parsed by start.S */
struct mmu_initial_mapping mmu_initial_mappings[] = {
    /* all of memory */
    {
        .phys = MEMORY_BASE_PHYS,
        .virt = KERNEL_BASE,
        .size = MEMORY_APERTURE_SIZE,
        .flags = 0,
        .name = "memory"
    },

    /* 1GB of peripherals */
    {
        .phys = PERIPHERAL_BASE_PHYS,
        .virt = PERIPHERAL_BASE_VIRT,
        .size = PERIPHERAL_BASE_SIZE,
        .flags = MMU_INITIAL_MAPPING_FLAG_DEVICE,
        .name = "peripherals"
    },

    /* null entry to terminate the list */
    { 0 }
};

static pmm_arena_t arena = {
    .name = "ram",
    .base = MEMORY_BASE_PHYS,
    .size = DEFAULT_MEMORY_SIZE,
    .flags = PMM_ARENA_FLAG_KMAP,
};

extern void psci_call(ulong arg0, ulong arg1, ulong arg2, ulong arg3);

void platform_early_init(void)
{
    /* initialize the interrupt controller */
    arm_gicv2m_init(GICV2M_REG_FRAMES, countof(GICV2M_REG_FRAMES));

    arm_generic_timer_init(ARM_GENERIC_TIMER_PHYSICAL_INT, 0);

    uart_init_early();

    /* look for a flattened device tree just before the kernel */
    const void *fdt = (void *)KERNEL_BASE;
    int err = fdt_check_header(fdt);
    if (err >= 0) {
        /* walk the nodes, looking for 'memory' */
        int depth = 0;
        int offset = 0;
        for (;;) {
            offset = fdt_next_node(fdt, offset, &depth);
            if (offset < 0)
                break;

            /* get the name */
            const char *name = fdt_get_name(fdt, offset, NULL);
            if (!name)
                continue;

            /* look for the 'memory' property */
            if (strcmp(name, "memory") == 0) {
                int lenp;
                const void *prop_ptr = fdt_getprop(fdt, offset, "reg", &lenp);
                if (prop_ptr && lenp == 0x10) {
                    /* we're looking at a memory descriptor */
                    //uint64_t base = fdt64_to_cpu(*(uint64_t *)prop_ptr);
                    uint64_t len = fdt64_to_cpu(*((const uint64_t *)prop_ptr + 1));

                    /* trim size on certain platforms */
#if ARCH_ARM
                    if (len > 1024*1024*1024U) {
                        len = 1024*1024*1024; /* only use the first 1GB on ARM32 */
                        printf("trimming memory to 1GB\n");
                    }
#endif

                    /* set the size in the pmm arena */
                    arena.size = len;
                }
            }
        }
    }

    /* add the main memory arena */
    pmm_add_arena(&arena);

    /* reserve the first 64k of ram, which should be holding the fdt */
    pmm_alloc_range(MEMBASE, 0x10000 / PAGE_SIZE, NULL);

    /* boot the secondary cpus using the Power State Coordintion Interface */
    ulong psci_call_num = 0x84000000 + 3; /* SMC32 CPU_ON */
#if ARCH_ARM64
    psci_call_num += 0x40000000; /* SMC64 */
#endif
    for (uint i = 1; i < SMP_MAX_CPUS; i++) {
        psci_call(psci_call_num, i, MEMBASE + KERNEL_LOAD_OFFSET, 0);
    }
}

void platform_init(void)
{
    uart_init();

    /* detect any virtio devices */
    uint virtio_irqs[NUM_VIRTIO_TRANSPORTS];
    for (int i = 0; i < NUM_VIRTIO_TRANSPORTS; i++) {
        virtio_irqs[i] = VIRTIO0_INT + i;
    }

    virtio_mmio_detect((void *)VIRTIO_BASE, NUM_VIRTIO_TRANSPORTS, virtio_irqs);

    /* Initialize the MSI allocator */
    status_t ret = arm_gic2vm_msi_init();
    if (ret != NO_ERROR) {
        TRACEF("Failed to initialize MSI allocator (ret = %d).  PCI will be "
               "restricted to legacy IRQ mode.\n", ret);
        PCIE_INIT_INFO.alloc_msi_block = NULL;
        PCIE_INIT_INFO.free_msi_block  = NULL;
    }

    /* Tell the PCIe subsystem where it can find its resources. */
    status_t status = pcie_init(&PCIE_INIT_INFO);
    if (status != NO_ERROR)
        TRACEF("Failed to initialize PCIe bus driver! (status = %d)\n", status);
}
