// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/sys/appmgr/namespace_builder.h"

#include <fcntl.h>
#include <lib/fdio/directory.h>
#include <lib/fdio/fd.h>
#include <lib/fdio/fdio.h>
#include <lib/fdio/limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <zircon/processargs.h>

#include <src/lib/fxl/strings/concatenate.h>

#include "src/lib/files/directory.h"
#include "src/lib/files/path.h"
#include "src/lib/files/unique_fd.h"
#include "src/lib/fsl/io/fd.h"
#include "src/sys/appmgr/allowlist.h"

namespace component {

constexpr char kDeprecatedDataName[] = "deprecated-data";
constexpr char kBlockedDataName[] = "data";

constexpr char kGlobalDataAllowlist[] =
    "allowlist/global_data.txt";

NamespaceBuilder::~NamespaceBuilder() = default;

void NamespaceBuilder::AddFlatNamespace(fuchsia::sys::FlatNamespacePtr ns) {
  if (ns && ns->paths.size() == ns->directories.size()) {
    for (size_t i = 0; i < ns->paths.size(); ++i) {
      AddDirectoryIfNotPresent(ns->paths.at(i), std::move(ns->directories.at(i)));
    }
  }
}

void NamespaceBuilder::AddPackage(zx::channel package) {
  PushDirectoryFromChannel("/pkg", std::move(package));
}

void NamespaceBuilder::AddConfigData(const SandboxMetadata& sandbox, const std::string& pkg_name) {
  for (const auto& feature : sandbox.features()) {
    if (feature == "config-data") {
      PushDirectoryFromPathAs("/pkgfs/packages/config-data/0/data/" + pkg_name, "/config/data");
    }
  }
}

void NamespaceBuilder::AddDirectoryIfNotPresent(const std::string& path, zx::channel directory) {
  if (std::find(paths_.begin(), paths_.end(), path) != paths_.end())
    return;
  PushDirectoryFromChannel(path, std::move(directory));
}

void NamespaceBuilder::AddServices(zx::channel services) {
  PushDirectoryFromChannel("/svc", std::move(services));
}

void NamespaceBuilder::AddHub(const HubDirectoryFactory& hub_directory_factory) {
  if (std::find(paths_.begin(), paths_.end(), "/hub") != paths_.end())
    return;
  PushDirectoryFromChannel("/hub", hub_directory_factory());
}

void NamespaceBuilder::AddSandbox(const SandboxMetadata& sandbox,
                                  const HubDirectoryFactory& hub_directory_factory) {
  AddSandbox(
      sandbox, hub_directory_factory,
      [] {
        FXL_NOTREACHED() << "IsolatedDataPathFactory unexpectedly used";
        return "";
      },
      [] {
        FXL_NOTREACHED() << "IsolatedCachePathFactory unexpectedly used";
        return "";
      },
      [] { return "/tmp"; });
}

void NamespaceBuilder::AddSandbox(const SandboxMetadata& sandbox,
                                  const HubDirectoryFactory& hub_directory_factory,
                                  const IsolatedDataPathFactory& isolated_data_path_factory,
                                  const IsolatedCachePathFactory& isolated_cache_path_factory,
                                  const IsolatedTempPathFactory& isolated_temp_path_factory) {
  for (const auto& path : sandbox.dev()) {
    if (path == "class") {
      FXL_LOG(WARNING) << "Ignoring request for all device classes";
      continue;
    }
    PushDirectoryFromPath("/dev/" + path);
  }

  for (const auto& path : sandbox.system()) {
    // 'deprecated-data' is the value used to access /system/data
    // to request a directory inside /system/data 'deprecated-data/some/path' is supplied
    if (path == kDeprecatedDataName ||
        path.find(fxl::Concatenate({kDeprecatedDataName, "/"})) == 0) {
      FXL_LOG(ERROR) << "Request for 'deprecated-data' by " << ns_id
                     << " ignored, this feature is no longer available";
    } else if (path == kBlockedDataName ||
               path.find(fxl::Concatenate({kBlockedDataName, "/"})) == 0) {
      FXL_LOG(ERROR) << "Request for 'data' in namespace '" << ns_id
                     << "' ignored, this feature is no longer available";
    } else {
      PushDirectoryFromPath("/system/" + path);
    }
  }

  for (const auto& path : sandbox.pkgfs())
    PushDirectoryFromPath("/pkgfs/" + path);

  // Prioritize isolated persistent storage over shell feature, if both are
  // present.
  if (sandbox.HasFeature("isolated-persistent-storage")) {
    PushDirectoryFromPathAs(isolated_data_path_factory(), "/data");
  }

  if (sandbox.HasFeature("deprecated-misc-storage")) {
    const std::string dataDir = "/data/misc";
    if (files::CreateDirectory(dataDir)) {
      PushDirectoryFromPathAs(dataDir, "/misc");
    } else {
      FXL_LOG(ERROR) << "Failed to create deprecated-misc-storage directory";
    }
  }

  if (sandbox.HasFeature("isolated-cache-storage")) {
    PushDirectoryFromPathAs(isolated_cache_path_factory(), "/cache");
  }

  for (const auto& feature : sandbox.features()) {
    if (feature == "build-info") {
      PushDirectoryFromPathAs("/pkgfs/packages/build-info/0/data", "/config/build-info");
    } else if (feature == "root-ssl-certificates") {
      PushDirectoryFromPathAs("/pkgfs/packages/root_ssl_certificates/0/data", "/config/ssl");
    } else if (feature == "deprecated-shell") {
      PushDirectoryFromPathAs("/pkgfs/packages/root_ssl_certificates/0/data", "/config/ssl");
      PushDirectoryFromPathAs("/pkgfs/packages/shell-commands/0/bin", "/bin");
      PushDirectoryFromPath("/blob");
      PushDirectoryFromPath("/boot");
      // Note that if the 'isolated-persistent-storage' feature is present,
      // this is a no-op since it has handled first above.
      // PushDirectoryFromPath does not override existing directories.
      PushDirectoryFromPath("/data");
      PushDirectoryFromPath("/dev");
      AddHub(hub_directory_factory);
      PushDirectoryFromPath("/install");
      PushDirectoryFromPath("/pkgfs");
      PushDirectoryFromPath("/system");
      PushDirectoryFromPath("/tmp");
      PushDirectoryFromPath("/volume");
    } else if (feature == "shell-commands") {
      PushDirectoryFromPathAs("/pkgfs/packages/shell-commands/0/bin", "/bin");
    } else if (feature == "system-temp") {
      PushDirectoryFromPath("/tmp");
    } else if (feature == "vulkan") {
      PushDirectoryFromPath("/dev/class/goldfish-address-space");
      PushDirectoryFromPath("/dev/class/goldfish-control");
      PushDirectoryFromPath("/dev/class/goldfish-pipe");
      PushDirectoryFromPath("/dev/class/gpu");
      PushDirectoryFromPathAs("/pkgfs/packages/config-data/0/data/vulkan-icd/icd.d",
                              "/config/vulkan/icd.d");
    } else if (feature == "isolated-temp") {
      PushDirectoryFromPathAs(isolated_temp_path_factory(), "/tmp");
    } else if (feature == "hub") {
      AddHub(hub_directory_factory);
    }
  }

  if (sandbox.HasInternalFeature("global-data")) {
    Allowlist global_data_allowlist(appmgr_config_dir_, kGlobalDataAllowlist, Allowlist::kExpected);
    if (global_data_allowlist.IsAllowed(ns_id)) {
      PushDirectoryFromPathAsWithPermissions("/data", "/global_data",
                                             O_DIRECTORY | O_RDONLY | O_ADMIN);
      PushDirectoryFromPathAsWithPermissions("/tmp", "/global_tmp",
                                             O_DIRECTORY | O_RDONLY | O_ADMIN);
    } else {
      FXL_LOG(WARNING) << "Component " << ns_id
                       << " is not allowed to use global-data. Blocked by allowlist.";
    }
  }

  for (const auto& path : sandbox.boot())
    PushDirectoryFromPath("/boot/" + path);
}

void NamespaceBuilder::PushDirectoryFromPath(std::string path) {
  PushDirectoryFromPathAs(path, path);
}

void NamespaceBuilder::PushDirectoryFromPathAs(std::string src_path, std::string dst_path) {
  PushDirectoryFromPathAsWithPermissions(std::move(src_path), std::move(dst_path),
                                         O_DIRECTORY | O_RDONLY);
}

void NamespaceBuilder::PushDirectoryFromPathAsWithPermissions(std::string src_path,
                                                              std::string dst_path,
                                                              uint64_t flags) {
  if (std::find(paths_.begin(), paths_.end(), dst_path) != paths_.end())
    return;
  fbl::unique_fd dir(open(src_path.c_str(), flags));
  if (!dir.is_valid())
    return;
  zx::channel handle = fsl::CloneChannelFromFileDescriptor(dir.get());
  if (!handle) {
    FXL_DLOG(WARNING) << "Failed to clone channel for " << src_path;
    return;
  }
  PushDirectoryFromChannel(std::move(dst_path), std::move(handle));
}

void NamespaceBuilder::PushDirectoryFromChannel(std::string path, zx::channel channel) {
  FXL_DCHECK(std::find(paths_.begin(), paths_.end(), path) == paths_.end());
  types_.push_back(PA_HND(PA_NS_DIR, types_.size()));
  handles_.push_back(channel.get());
  paths_.push_back(std::move(path));

  handle_pool_.push_back(std::move(channel));
}

fdio_flat_namespace_t* NamespaceBuilder::Build() {
  path_data_.resize(paths_.size());
  for (size_t i = 0; i < paths_.size(); ++i)
    path_data_[i] = paths_[i].c_str();

  flat_ns_.count = types_.size();
  flat_ns_.handle = handles_.data();
  flat_ns_.type = types_.data();
  flat_ns_.path = path_data_.data();
  Release();
  return &flat_ns_;
}

fuchsia::sys::FlatNamespace NamespaceBuilder::BuildForRunner() {
  fuchsia::sys::FlatNamespace flat_namespace;
  flat_namespace.paths.clear();
  flat_namespace.directories.clear();

  for (auto& path : paths_) {
    flat_namespace.paths.push_back(std::move(path));
  }

  for (auto& handle : handle_pool_) {
    flat_namespace.directories.push_back(std::move(handle));
  }
  return flat_namespace;
}

void NamespaceBuilder::Release() {
  for (auto& handle : handle_pool_)
    (void)handle.release();
  handle_pool_.clear();
}

}  // namespace component
