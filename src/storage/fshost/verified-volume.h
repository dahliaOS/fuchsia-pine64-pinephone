// Copyright 2020 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SRC_STORAGE_FSHOST_VERIFIED_VOLUME_INTERFACE_H_
#define SRC_STORAGE_FSHOST_VERIFIED_VOLUME_INTERFACE_H_

#include <digest/digest.h>
#include <fbl/unique_fd.h>
#include <lib/zx/time.h>
#include <zircon/types.h>

#include <optional>

namespace devmgr {

class VerifiedVolume {
 public:
  VerifiedVolume(fbl::unique_fd fd, fbl::unique_fd devfs_root, std::optional<digest::Digest> seal);

  // Waits for the "verity" child of fd to appear, then if a seal was passed in
  // at construction time, opens the device for verified read with that seal,
  // with a deadline of `timeout` for each operation.
  zx_status_t PrepareVerityDevice(const zx::duration& timeout);
 private:
  fbl::unique_fd fd_;
  fbl::unique_fd devfs_root_;
  std::optional<digest::Digest> seal_;
};

}  // namespace devmgr

#endif  // SRC_STORAGE_FSHOST_VERIFIED_VOLUME_INTERFACE_H_
