# Copyright 2016 The Fuchsia Authors
# Copyright (c) 2008-2015 Travis Geiselbrecht
#
# Use of this source code is governed by a MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT

SUBARCH := x86-64
MODULES +=

# we're going to need to put the user cpio archive in the kernel binary directly
EMBED_USER_BOOTFS:=true

include project/virtual/test.mk
include project/virtual/user.mk
include project/target/pc-uefi.mk
