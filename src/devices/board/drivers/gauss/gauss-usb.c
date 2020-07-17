// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <zircon/syscalls.h>

#include <ddk/debug.h>
#include <ddk/platform-defs.h>
#include <hw/reg.h>
#include <soc/aml-a113/a113-hw.h>
#include <soc/aml-common/aml-usb-phy.h>

#include "gauss-hw.h"
#include "gauss.h"

#define BIT_MASK(start, count) (((1 << (count)) - 1) << (start))
#define SET_BITS(dest, start, count, value) \
  ((dest & ~BIT_MASK(start, count)) | (((value) << (start)) & BIT_MASK(start, count)))

static const pbus_mmio_t xhci_mmios[] = {
    {
        .base = DWC3_MMIO_BASE,
        .length = DWC3_MMIO_LENGTH,
    },
};

static const pbus_irq_t xhci_irqs[] = {
    {
        .irq = DWC3_IRQ,
        .mode = ZX_INTERRUPT_MODE_EDGE_HIGH,
    },
};

static const pbus_bti_t xhci_btis[] = {
    {
        .iommu_index = 0,
        .bti_id = BTI_USB_XHCI,
    },
};

static const pbus_dev_t xhci_dev = {
    .name = "xhci",
    .vid = PDEV_VID_GENERIC,
    .pid = PDEV_PID_GENERIC,
    .did = PDEV_DID_USB_XHCI,
    .mmio_list = xhci_mmios,
    .mmio_count = countof(xhci_mmios),
    .irq_list = xhci_irqs,
    .irq_count = countof(xhci_irqs),
    .bti_list = xhci_btis,
    .bti_count = countof(xhci_btis),
};

zx_status_t gauss_usb_init(gauss_bus_t* bus) {
  zx_status_t status =
      mmio_buffer_init_physical(&bus->usb_phy, 0xffe09000, 4096,
                                // Please do not use get_root_resource() in new code. See ZX-1467.
                                get_root_resource(), ZX_CACHE_POLICY_UNCACHED_DEVICE);
  if (status != ZX_OK) {
    zxlogf(ERROR, "gauss_usb_init io_buffer_init_physical failed %d", status);
    return status;
  }

  // Please do not use get_root_resource() in new code. See ZX-1467.
  status = zx_interrupt_create(get_root_resource(), USB_PHY_IRQ, ZX_INTERRUPT_MODE_DEFAULT,
                               &bus->usb_phy_irq_handle);
  if (status != ZX_OK) {
    zxlogf(ERROR, "gauss_usb_init zx_interrupt_create failed %d", status);
    mmio_buffer_release(&bus->usb_phy);
    return status;
  }

  MMIO_PTR volatile void* regs = bus->usb_phy.vaddr;

  // amlogic_new_usb2_init
  for (int i = 0; i < 4; i++) {
    MMIO_PTR volatile void* addr = regs + (i * PHY_REGISTER_SIZE) + U2P_R0_OFFSET;
    uint32_t temp = MmioRead32(addr);
    temp |= U2P_R0_POR;
    temp |= U2P_R0_DMPULLDOWN;
    temp |= U2P_R0_DPPULLDOWN;
    if (i == 1) {
      temp |= U2P_R0_IDPULLUP;
    }
    MmioWrite32(temp, addr);
    zx_nanosleep(zx_deadline_after(ZX_USEC(500)));
    temp = MmioRead32(addr);
    temp &= ~U2P_R0_POR;
    MmioWrite32(temp, addr);
  }

  // amlogic_new_usb3_init
  MMIO_PTR volatile void* addr = regs + (4 * PHY_REGISTER_SIZE);

  uint32_t temp = MmioRead32(addr + USB_R1_OFFSET);
  temp = SET_BITS(temp, USB_R1_U3H_FLADJ_30MHZ_REG_START, USB_R1_U3H_FLADJ_30MHZ_REG_BITS, 0x20);
  MmioWrite32(temp, addr + USB_R1_OFFSET);

  temp = MmioRead32(addr + USB_R5_OFFSET);
  temp |= USB_R5_IDDIG_EN0;
  temp |= USB_R5_IDDIG_EN1;
  temp = SET_BITS(temp, USB_R5_IDDIG_TH_START, USB_R5_IDDIG_TH_BITS, 255);
  MmioWrite32(temp, addr + USB_R5_OFFSET);

  if ((status = pbus_device_add(&bus->pbus, &xhci_dev)) != ZX_OK) {
    zxlogf(ERROR, "a113_usb_init could not add xhci_dev: %d", status);
    return status;
  }

  return ZX_OK;
}
