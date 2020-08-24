// Copyright 2020 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "verified-volume.h"

#include <fbl/string.h>
#include <fbl/string_buffer.h>
#include <lib/fdio/fdio.h>
#include <lib/fdio/cpp/caller.h>
#include <fuchsia/device/llcpp/fidl.h>
#include <fuchsia/hardware/block/verified/llcpp/fidl.h>
#include <ramdevice-client/ramdisk.h>  // for wait_for_device_at()

#include "block-device-interface.h"

namespace devmgr {

constexpr size_t kSha256SealLength = 32;

static zx_status_t RelativeTopologicalPath(fdio_cpp::UnownedFdioCaller& caller, fbl::String* out) {
  zx_status_t rc;
  // Get the full device path
  fbl::StringBuffer<PATH_MAX> path;
  path.Resize(path.capacity());
  size_t path_len;
  auto resp = ::llcpp::fuchsia::device::Controller::Call::GetTopologicalPath(
      zx::unowned_channel(caller.borrow_channel()));
  rc = resp.status();
  if (rc == ZX_OK) {
    if (resp->result.is_err()) {
      rc = resp->result.err();
    } else {
      auto& r = resp->result.response();
      path_len = r.path.size();
      memcpy(path.data(), r.path.data(), r.path.size());
    }
  }

  if (rc != ZX_OK) {
    printf("could not find parent device: %s\n", zx_status_get_string(rc));
    return rc;
  }

  // Verify that the path returned starts with "/dev/"
  const char* kSlashDevSlash = "/dev/";
  if (path_len < strlen(kSlashDevSlash)) {
    printf("path_len way too short: %lu\n", path_len);
    return ZX_ERR_INTERNAL;
  }
  if (strncmp(path.c_str(), kSlashDevSlash, strlen(kSlashDevSlash)) != 0) {
    printf("Expected device path to start with '/dev/' but got %s\n", path.c_str());
    return ZX_ERR_INTERNAL;
  }

  // Strip the leading "/dev/" and return the rest
  size_t path_len_sans_dev = path_len - strlen(kSlashDevSlash);
  memmove(path.begin(), path.begin() + strlen(kSlashDevSlash), path_len_sans_dev);

  path.Resize(path_len_sans_dev);
  *out = path.ToString();
  return ZX_OK;
}

VerifiedVolume::VerifiedVolume(fbl::unique_fd fd, fbl::unique_fd devfs_root,
                               std::optional<digest::Digest> seal)
    : fd_(std::move(fd)), devfs_root_(std::move(devfs_root)), seal_(std::move(seal)) {}

zx_status_t VerifiedVolume::PrepareVerityDevice(const zx::duration& timeout) {
  // By the time this is called, the request to bind the driver should already
  // have been sent.

  // Construct topological path of child `verity` device.
  fdio_cpp::UnownedFdioCaller caller(fd_.get());
  if (!caller) {
    printf("could not convert fd to io\n");
    return ZX_ERR_BAD_STATE;
  }

  zx_status_t rc;
  fbl::String path_base;
  if ((rc = RelativeTopologicalPath(caller, &path_base)) != ZX_OK) {
    printf("could not get topological path: %s\n", zx_status_get_string(rc));
    return rc;
  }
  fbl::String verity_manager_path = fbl::String::Concat({path_base, "/verity"});

  // Wait for the child device to appear within a few seconds.
  if ((rc = wait_for_device_at(devfs_root_.get(),
                               verity_manager_path.c_str(), timeout.get())) != ZX_OK) {
    printf("block-verity driver failed to appear at %s: %s\n", verity_manager_path.c_str(),
           zx_status_get_string(rc));
    return rc;
  }

  // Return, if we weren't given a seal.
  if (!seal_.has_value()) {
    return ZX_OK;
  }

  // Otherwise, prepare to open the child with the seal given.

  // Open manager device
  fbl::unique_fd verity_manager_fd(openat(devfs_root_.get(),
                                          verity_manager_path.c_str(), O_RDWR));
  if (!verity_manager_fd) {
    printf("couldn't open block-verity device manager at %s\n", verity_manager_path.c_str());
    return ZX_ERR_NOT_FOUND;
  }

  // Extract channel.
  zx::channel verity_manager_chan;
  rc = fdio_get_service_handle(verity_manager_fd.release(),
                               verity_manager_chan.reset_and_get_address());
  if (rc != ZX_OK) {
    printf("couldn't extract service handle from device manager: %s", zx_status_get_string(rc));
    return rc;
  }

  // Prepare arguments to send.
  fidl::aligned<::llcpp::fuchsia::hardware::block::verified::HashFunction> hash_function =
      ::llcpp::fuchsia::hardware::block::verified::HashFunction::SHA256;
  fidl::aligned<::llcpp::fuchsia::hardware::block::verified::BlockSize> block_size =
      ::llcpp::fuchsia::hardware::block::verified::BlockSize::SIZE_4096;
  auto config =
      ::llcpp::fuchsia::hardware::block::verified::Config::Builder(
          std::make_unique<::llcpp::fuchsia::hardware::block::verified::Config::Frame>())
          .set_hash_function(fidl::unowned_ptr(&hash_function))
          .set_block_size(fidl::unowned_ptr(&block_size))
          .build();

  ::llcpp::fuchsia::hardware::block::verified::Sha256Seal sha256_seal;
  seal_->CopyTo(sha256_seal.superblock_hash.begin(), kSha256SealLength);
  fidl::aligned<::llcpp::fuchsia::hardware::block::verified::Sha256Seal> aligned =
      std::move(sha256_seal);
  auto seal_to_send =
      ::llcpp::fuchsia::hardware::block::verified::Seal::WithSha256(fidl::unowned_ptr(&aligned));

  // Request the device be opened for verified read
  auto open_resp =
      ::llcpp::fuchsia::hardware::block::verified::DeviceManager::Call::OpenForVerifiedRead(
          zx::unowned_channel(verity_manager_chan), std::move(config), std::move(seal_to_send));
  if (open_resp.status() != ZX_OK) {
    return open_resp.status();
  }
  if (open_resp->result.is_err()) {
    return open_resp->result.err();
  }

  // Wait for the `verified` child device to appear
  fbl::unique_fd verified_fd;
  fbl::String verified_path = fbl::String::Concat({verity_manager_path, "/verified"});
  if ((rc = wait_for_device_at(devfs_root_.get(),
                               verified_path.c_str(), timeout.get())) != ZX_OK) {
    printf("verified device failed to appeat at %s: %s", verified_path.c_str(),
           zx_status_get_string(rc));
    return rc;
  }

  // And then for the `block` child of that verified device
  fbl::String verified_block_path = fbl::String::Concat({verified_path, "/block"});
  if ((rc = wait_for_device_at(devfs_root_.get(),
                               verified_block_path.c_str(), timeout.get())) != ZX_OK) {
    printf("block child of verified device failed to appeat at %s: %s",
           verified_block_path.c_str(), zx_status_get_string(rc));
    return rc;
  }

  return ZX_OK;
}

}  // namespace devmgr
