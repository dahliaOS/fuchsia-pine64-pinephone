<%include file="header.mako" />

assert(current_os == "fuchsia")

import("fuchsia_sdk_pkg.gni")

# These template is used to create build targets
# that test the generated build targets. It does not
# have any practical use outside testing.

# All vulkan targets
template("fuchsia_sdk_test_loadable_module_targets") {
  not_needed(["invoker"])
  group(target_name){
    deps = [
    % for dep in sorted(data.loadable_module_targets):
      "<%text>${fuchsia_sdk}</%text>/pkg/${dep}:all",
    % endfor
    ]
  }
}

# All FIDL targets
template("fuchsia_sdk_test_fidl_targets") {
  not_needed(["invoker"])
  group(target_name){
    deps = [
    % for dep in sorted(data.fidl_targets):
      "<%text>${fuchsia_sdk}</%text>/fidl/${dep}:all",
    % endfor
    ]
  }
}

# All CC source targets
template("fuchsia_sdk_test_cc_source_targets") {
  not_needed(["invoker"])
  group(target_name){
    deps = [
    % for dep in sorted(data.cc_source_targets):
      "<%text>${fuchsia_sdk}</%text>/pkg/${dep}:all",
    % endfor
    ]
  }
}

# All CC prebuilt targets
template("fuchsia_sdk_test_cc_prebuilt_targets") {
  not_needed(["invoker"])
  group(target_name){
    deps = [
    % for dep in sorted(data.cc_prebuilt_targets):
      "<%text>${fuchsia_sdk}</%text>/pkg/${dep}:all",
    % endfor
    ]
  }
}

# All test targets
template("fuchsia_sdk_test_targets"){
  not_needed(["invoker"])
  fuchsia_sdk_test_loadable_module_targets("loadable_module_targets"){
  }
  fuchsia_sdk_test_fidl_targets("fidl_targets"){
  }
  fuchsia_sdk_test_cc_source_targets("cc_source_targets"){
  }
  fuchsia_sdk_test_cc_prebuilt_targets("cc_prebuilt_targets"){
  }
  group(target_name){
    deps = [
      ":loadable_module_targets",
      ":fidl_targets",
      ":cc_source_targets",
      ":cc_prebuilt_targets",
    ]
  }
}
