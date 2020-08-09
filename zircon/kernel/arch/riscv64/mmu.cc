// Copyright 2020 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <align.h>
#include <assert.h>
#include <bits.h>
#include <debug.h>
#include <err.h>
#include <inttypes.h>
#include <lib/heap.h>
#include <lib/ktrace.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <trace.h>
#include <zircon/types.h>

#include <arch/aspace.h>
#include <arch/mmu.h>
#include <bitmap/raw-bitmap.h>
#include <bitmap/storage.h>
#include <fbl/auto_call.h>
#include <fbl/auto_lock.h>
#include <kernel/mutex.h>
#include <ktl/algorithm.h>
#include <vm/arch_vm_aspace.h>
#include <vm/physmap.h>
#include <vm/pmm.h>
#include <vm/vm.h>

#define LOCAL_TRACE 0

pte_t kernel_pgtable[512] __ALIGNED(PAGE_SIZE);
paddr_t kernel_pgtable_phys; // filled in by start.S

static inline void riscv_set_satp(uint asid, paddr_t pt) {
  ulong satp;

  satp = RISCV_SATP_MODE_SV48;

  // make sure the asid is in range
  DEBUG_ASSERT((asid & RISCV_SATP_ASID_MASK) == 0);
  satp |= (ulong)asid << RISCV_SATP_ASID_SHIFT;

  // make sure the page table is aligned
  DEBUG_ASSERT(IS_PAGE_ALIGNED(pt));
  satp |= pt;

  riscv_csr_write(RISCV_CSR_SATP, satp);

  // TODO: TLB flush here or use asid properly
  // sfence.vma zero, zero
}

// given a va address and the level, compute the index in the current PT
static inline uint vaddr_to_index(vaddr_t va, uint level) {
  // levels count down from PT_LEVELS - 1
  DEBUG_ASSERT(level < RISCV_MMU_PT_LEVELS);

  // canonicalize the address
  va &= RISCV_MMU_CANONICAL_MASK;

  uint index = ((va >> PAGE_SIZE_SHIFT) >> (level * RISCV_MMU_PT_SHIFT)) & (RISCV_MMU_PT_ENTRIES - 1);
  LTRACEF_LEVEL(3, "canonical va %#lx, level %u = index %#x\n", va, level, index);

  return index;
}

static uintptr_t page_size_per_level(uint level) {
  // levels count down from PT_LEVELS - 1
  DEBUG_ASSERT(level < RISCV_MMU_PT_LEVELS);

  return 1UL << (PAGE_SIZE_SHIFT + level * RISCV_MMU_PT_SHIFT);
}

static uintptr_t page_mask_per_level(uint level) {
  return page_size_per_level(level) - 1;
}

static volatile pte_t *alloc_ptable(paddr_t *pa) {
  // grab a page from the pmm
  vm_page_t *p;
  zx_status_t status;
  status = pmm_alloc_page(0, &p, pa);
  if (status != ZX_OK) {
    return NULL;
  }

  // get the physical and virtual mappings of the page
  *pa = vaddr_to_paddr(p);
  pte_t *pte = static_cast<pte_t*>(paddr_to_physmap(*pa));

  // zero it out
  memset(pte, 0, PAGE_SIZE);

  smp_wmb();

  LTRACEF_LEVEL(3, "returning pa %#lx, va %p\n", *pa, pte);
  return pte;
}

static pte_t mmu_flags_to_pte(uint flags) {
  pte_t pte = 0;

  pte |= (flags & ARCH_MMU_FLAG_PERM_USER) ? RISCV_PTE_U : 0;
  pte |= (flags & ARCH_MMU_FLAG_PERM_READ) ? RISCV_PTE_R : (RISCV_PTE_R | RISCV_PTE_W);
  pte |= (flags & ARCH_MMU_FLAG_PERM_EXECUTE) ? RISCV_PTE_X : 0;

  return pte;
}

static uint pte_flags_to_mmu_flags(pte_t pte) {
  uint f = 0;
  if ((pte & (RISCV_PTE_R | RISCV_PTE_W)) == RISCV_PTE_R) {
    f |= ARCH_MMU_FLAG_PERM_READ;
  }
  f |= (pte & RISCV_PTE_X) ? ARCH_MMU_FLAG_PERM_EXECUTE : 0;
  f |= (pte & RISCV_PTE_U) ? ARCH_MMU_FLAG_PERM_USER : 0;
  return f;
}

zx_status_t RiscvArchVmAspace::Query(vaddr_t vaddr, paddr_t* paddr, uint* mmu_flags) {
  LTRACEF("aspace %p, vaddr %#lx\n", this, vaddr);

  // trim the vaddr to the aspace
  if (vaddr < base_ || vaddr > base_ + size_ - 1) {
    return ZX_ERR_OUT_OF_RANGE;
  }

  uint level = RISCV_MMU_PT_LEVELS - 1;
  uint index = vaddr_to_index(vaddr, level);
  volatile pte_t *ptep = pt_virt_ + index;

  // walk down through the levels, looking for a terminal entry that matches our address
  for (;;) {
    LTRACEF_LEVEL(2, "level %u, index %u, pte %p (%#lx)\n", level, index, ptep, *ptep);

    // look at our page table entry
    pte_t pte = *ptep;
    if ((pte & RISCV_PTE_V) == 0) {
      // invalid entry, terminate search
      return ZX_ERR_NOT_FOUND;
    } else if ((pte & RISCV_PTE_PERM_MASK) == 0) {
      // next level page table pointer (RWX = 0)
      paddr_t ptp = RISCV_PTE_PPN(pte);
      volatile pte_t *ptv = static_cast<volatile pte_t*>(paddr_to_physmap(ptp));

      LTRACEF_LEVEL(2, "next level page table at %p, pa %#lx\n", ptv, ptp);

      // go one level deeper
      level--;
      index = vaddr_to_index(vaddr, level);
      ptep = ptv + index;
    } else {
      // terminal entry
      LTRACEF_LEVEL(3, "terminal entry\n");

      if (paddr) {
        // extract the ppn
        paddr_t pa = RISCV_PTE_PPN(pte);
        uintptr_t page_mask = page_mask_per_level(level);

        // add the va offset into the physical address
        *paddr = pa | (vaddr & page_mask);
        LTRACEF_LEVEL(3, "raw pa %#lx, page_mask %#lx, final pa %#lx\n", pa, page_mask, *paddr);
      }

      if (mmu_flags) {
        // compute the flags
        *mmu_flags = pte_flags_to_mmu_flags(pte);
        LTRACEF_LEVEL(3, "computed flags %#x\n", *mmu_flags);
      }

      return ZX_OK;
    }

    // make sure we didn't decrement level one too many
    DEBUG_ASSERT(level < RISCV_MMU_PT_LEVELS);
  }
    // unreachable
  return ZX_OK;
}

zx_status_t RiscvArchVmAspace::MapContiguous(vaddr_t vaddr, paddr_t paddr, size_t count,
                                           uint mmu_flags, size_t* mapped) {
  return ZX_OK;
}

zx_status_t RiscvArchVmAspace::Map(vaddr_t vaddr, paddr_t* phys, size_t count, uint mmu_flags,
                                 size_t* mapped) {
  LTRACEF("vaddr %#lx paddr %#lx count %zu flags %#x\n", vaddr, *phys, count, mmu_flags);

restart:
  if (count == 0)
    return ZX_OK;

  // bootstrap the top level walk
  uint level = RISCV_MMU_PT_LEVELS - 1;
  uint index = vaddr_to_index(vaddr, level);
  volatile pte_t *ptep = pt_virt_ + index;

  for (;;) {
    LTRACEF_LEVEL(2, "level %u, index %u, pte %p (%#lx) va %#lx pa %#lx\n",
                  level, index, ptep, *ptep, vaddr, *phys);

    // look at our page table entry
    pte_t pte = *ptep;
    if (level > 0 && !(pte & RISCV_PTE_V)) {
      // invalid entry, will have to add a page table
      paddr_t ptp;
      volatile pte_t *ptv = alloc_ptable(&ptp);
      if (!ptv) {
        return ZX_ERR_NO_MEMORY;
      }

      LTRACEF_LEVEL(2, "new ptable table %p, pa %#lx\n", ptv, ptp);

      // link it in. RMW == 0 is a page table link
      pte = RISCV_PTE_PPN_TO_PTE(ptp) | RISCV_PTE_V;
      *ptep = pte;

      // go one level deeper
      level--;
      index = vaddr_to_index(vaddr, level);
      ptep = ptv + index;
    } else if ((pte & RISCV_PTE_V) && !(pte & RISCV_PTE_PERM_MASK)) {
      // next level page table pointer (RWX = 0)
      paddr_t ptp = RISCV_PTE_PPN(pte);
      volatile pte_t *ptv = static_cast<volatile pte_t*>(paddr_to_physmap(ptp));

      LTRACEF_LEVEL(2, "next level page table at %p, pa %#lx\n", ptv, ptp);

      // go one level deeper
      level--;
      index = vaddr_to_index(vaddr, level);
      ptep = ptv + index;
    } else if (pte & RISCV_PTE_V) {
      // terminal entry already exists
      if (level > 0) {
        PANIC_UNIMPLEMENTED;
      } else {
        PANIC_UNIMPLEMENTED;
      }
    } else {
       DEBUG_ASSERT(level == 0 && !(pte & RISCV_PTE_V));

      // hit a open terminal page table entry, lets add ours
      pte = RISCV_PTE_PPN_TO_PTE(*phys);
      pte |= mmu_flags_to_pte(mmu_flags);
      pte |= RISCV_PTE_A | RISCV_PTE_D | RISCV_PTE_V;
      pte |= (flags_ & ARCH_ASPACE_FLAG_KERNEL) ? RISCV_PTE_G : 0;

      LTRACEF_LEVEL(2, "added new terminal entry: pte %#lx\n", pte);

      *ptep = pte;

      // simple algorithm: restart walk from top, one page at a time
      // TODO: more efficiently deal with runs and large pages
      count--;
      *phys += PAGE_SIZE;
      vaddr += PAGE_SIZE;
      goto restart;
    }

    // make sure we didn't decrement level one too many
    DEBUG_ASSERT(level < RISCV_MMU_PT_LEVELS);
  }
  // unreachable
}

zx_status_t RiscvArchVmAspace::Unmap(vaddr_t vaddr, size_t count, size_t* unmapped) {
  LTRACEF("vaddr %#lx count %zu\n", vaddr, count);

  PANIC_UNIMPLEMENTED;
}

zx_status_t RiscvArchVmAspace::Protect(vaddr_t vaddr, size_t count, uint mmu_flags) {
  return ZX_OK;
}

zx_status_t RiscvArchVmAspace::HarvestAccessed(vaddr_t vaddr, size_t count,
                                               const HarvestCallback& accessed_callback) {
  return ZX_OK;
}

zx_status_t RiscvArchVmAspace::MarkAccessed(vaddr_t vaddr, size_t count) {
  return ZX_OK;
}

zx_status_t RiscvArchVmAspace::Init(vaddr_t base, size_t size, uint flags, page_alloc_fn_t paf) {
  LTRACEF("aspace %p, base %#lx, size %#zx, flags %#x\n", this, base, size, flags);

    // validate that the base + size is sane and doesn't wrap
  DEBUG_ASSERT(size > PAGE_SIZE);
  DEBUG_ASSERT(base + size - 1 > base);

  flags_ = flags;
  if (flags & ARCH_ASPACE_FLAG_KERNEL) {
    // at the moment we can only deal with address spaces as globally defined
    DEBUG_ASSERT(base == KERNEL_ASPACE_BASE);
    DEBUG_ASSERT(size == KERNEL_ASPACE_SIZE);

    base_ = base;
    size_ = size;
    pt_virt_ = kernel_pgtable;
    pt_phys_ = kernel_pgtable_phys;
  } else {
    PANIC_UNIMPLEMENTED;
  }

  LTRACEF("pt phys %#lx, pt virt %p\n", pt_phys_, pt_virt_);

  return ZX_OK;
}

zx_status_t RiscvArchVmAspace::Destroy() {
  LTRACEF("aspace %p\n", this);

  PANIC_UNIMPLEMENTED;
}

void RiscvArchVmAspace::ContextSwitch(RiscvArchVmAspace* old_aspace, RiscvArchVmAspace* aspace) {
  LTRACEF("aspace %p\n", aspace);

  PANIC_UNIMPLEMENTED;
}

void arch_zero_page(void* _ptr) {
}

RiscvArchVmAspace::RiscvArchVmAspace() = default;

RiscvArchVmAspace::~RiscvArchVmAspace() = default;

vaddr_t RiscvArchVmAspace::PickSpot(vaddr_t base, uint prev_region_mmu_flags, vaddr_t end,
                                  uint next_region_mmu_flags, vaddr_t align, size_t size,
                                  uint mmu_flags) {
  return PAGE_ALIGN(base);
}
