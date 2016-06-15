// Copyright 2016 The Fuchsia Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <magenta/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// This is a protocol for passing state to a new process
// via a message in a message pipe.

#define MX_PROCARGS_PROTOCOL 0x4150585d  // MXPA
#define MX_PROCARGS_VERSION 0x0001000

typedef struct mx_proc_args mx_proc_args_t;

struct mx_proc_args {
    // Protocol and version identifiers to allow for
    // different process start message protocols and
    // versioning of the same.
    uint32_t protocol;
    uint32_t version;

    // Offset from start of message to handle info
    // array, which contains one uint32_t per handle
    // passed along with the message.
    uint32_t handle_info_off;

    // Offset from start of message to arguments and
    // count of arguments.  Arguments are provided as
    // a set of null-terminated utf-8 strings, one
    // after the other.
    uint32_t args_off;
    uint32_t args_num;
};

// Handle Info entries associate a type and optional
// argument with each handle included in the process
// arguments message.
#define MX_HND_INFO(type, arg) (((type)&0xFFFF)|(((arg)&0xFFFF)<<16))
#define MX_HND_INFO_TYPE(n) ((n)&0xFFFF)
#define MX_HND_INFO_ARG(n) (((n) >> 16) & 0xFFFF)

// handle to our own process
#define MX_HND_TYPE_PROC_SELF 1

// Handle types the mxio library uses
#define MX_HND_TYPE_MXIO_ROOT 0x10
#define MX_HND_TYPE_MXIO_REMOTE 0x11
#define MX_HND_TYPE_MXIO_PIPE 0x12
#define MX_HND_TYPE_MXIO_EVENT 0x13

// Handle types for one-off use and prototyping
#define MX_HND_TYPE_USER0 0xFFF0
#define MX_HND_TYPE_USER1 0xFFF1
#define MX_HND_TYPE_USER2 0xFFF2

#define MX_PROC_INFO_MAGIC 0xd0dabb1e
#define MX_PROC_INFO_VERSION 0

// Utility to parse the above
typedef struct mx_proc_info mx_proc_info_t;
struct mx_proc_info {
    // Identifier and version of the mx_proc_info object.
    uint32_t magic;    // MX_PROC_INFO_MAGIC
    uint32_t version;  // MX_PROC_INFO_VERSION

    // Next available TLS slot. Increment atomically.
    uint32_t next_tls_slot;

    mx_proc_args_t* proc_args;

    mx_handle_t* handle;
    uint32_t* handle_info;
    int handle_count;

    char** argv;
    int argc;
};

#ifdef __cplusplus
}
#endif
