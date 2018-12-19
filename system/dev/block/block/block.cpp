// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <sys/param.h>

#include <algorithm>
#include <limits>
#include <new>

#include <ddk/binding.h>
#include <ddk/device.h>
#include <ddk/driver.h>
#include <ddk/metadata.h>
#include <ddktl/device.h>
#include <ddktl/protocol/block.h>
#include <ddktl/protocol/block/partition.h>
#include <fbl/auto_lock.h>
#include <fbl/mutex.h>
#include <lib/zx/fifo.h>
#include <lib/zx/vmo.h>
#include <zircon/boot/image.h>
#include <zircon/device/block.h>
#include <zircon/process.h>
#include <zircon/thread_annotations.h>

#include "server.h"
#include "server-manager.h"

class BlockDevice;

using BlockDeviceType = ddk::Device<BlockDevice,
                                    ddk::GetProtocolable,
                                    ddk::Ioctlable,
                                    ddk::Unbindable,
                                    ddk::Readable,
                                    ddk::Writable,
                                    ddk::GetSizable>;

class BlockDevice : public BlockDeviceType,
                    public ddk::BlockProtocol<BlockDevice, ddk::base_protocol> {
public:
    BlockDevice(zx_device_t* parent) : BlockDeviceType(parent) {
        block_protocol_t self { &block_protocol_ops_, this };
        self_protocol_ = ddk::BlockProtocolClient(&self);
        parent_protocol_ = ddk::BlockImplProtocolClient(parent);
        parent_partition_protocol_ = ddk::BlockPartitionProtocolClient(parent);
    };

    static zx_status_t Bind(void* ctx, zx_device_t* dev);

    void DdkUnbind();
    void DdkRelease();
    zx_status_t DdkGetProtocol(uint32_t proto_id, void* out_protocol);
    zx_status_t DdkIoctl(uint32_t op, const void* cmd, size_t cmd_len,
                         void* reply, size_t reply_len, size_t* out_actual);
    zx_status_t DdkRead(void* buf, size_t buf_len, zx_off_t off, size_t* actual);
    zx_status_t DdkWrite(const void* buf, size_t buf_len, zx_off_t off, size_t* actual);
    zx_off_t DdkGetSize();

    void BlockQuery(block_info_t* block_info, size_t* op_size);
    void BlockQueue(block_op_t* op, block_impl_queue_callback completion_cb, void* cookie);
    zx_status_t GetStats(const void* cmd, size_t cmd_len, void* reply, size_t reply_len,
                         size_t* out_actual);

private:
    static int ServerThread(void* arg);
    zx_status_t GetFifos(zx_handle_t* out_buf, size_t out_len, size_t* out_actual);
    zx_status_t AttachVmo(const void* in_buf, size_t in_len, vmoid_t* out_buf,
                          size_t out_len, size_t* out_actual);
    zx_status_t Rebind();
    zx_status_t DoIo(void* buf, size_t buf_len, zx_off_t off, bool write);

    // The block protocol of the device we are binding against.
    ddk::BlockImplProtocolClient parent_protocol_;
    // An optional partition protocol, if supported by the parent device.
    ddk::BlockPartitionProtocolClient parent_partition_protocol_;
    // The block protocol for ourselves, which redirects to the parent protocol,
    // but may also collect auxiliary information like statistics.
    ddk::BlockProtocolClient self_protocol_;
    block_info_t info_ = {};
    size_t block_op_size_ = 0;
    // True if we have metadata for a ZBI partition map.
    bool has_bootpart_ = false;

    // Manages the background FIFO server.
    ServerManager server_manager_;

    fbl::Mutex io_lock_;
    zx::vmo io_vmo_ TA_GUARDED(io_lock_);
    zx_status_t io_status_ = ZX_OK;
    sync_completion_t io_signal_;
    std::unique_ptr<uint8_t[]> io_op_;

    fbl::Mutex stat_lock_;
    // TODO(kmerrick) have this start as false and create IOCTL to toggle it.
    bool enable_stats_ TA_GUARDED(stat_lock_) = true;
    block_stats_t stats_ TA_GUARDED(stat_lock_) = {};
};

zx_status_t BlockDevice::GetFifos(zx_handle_t* out_buf, size_t out_len, size_t* out_actual) {
    if (out_len < sizeof(zx_handle_t)) {
        return ZX_ERR_INVALID_ARGS;
    }
    zx::fifo fifo;
    zx_status_t status = server_manager_.StartServer(&self_protocol_, &fifo);
    if (status != ZX_OK) {
        return status;
    }
    *out_buf = fifo.release();
    *out_actual = sizeof(zx_handle_t);
    return ZX_OK;
}

zx_status_t BlockDevice::AttachVmo(const void* in_buf, size_t in_len, vmoid_t* out_buf,
                                   size_t out_len, size_t* out_actual) {
    if ((in_len < sizeof(zx_handle_t)) || (out_len < sizeof(vmoid_t))) {
        return ZX_ERR_INVALID_ARGS;
    }

    zx::vmo vmo(*reinterpret_cast<const zx_handle_t*>(in_buf));
    zx_status_t status = server_manager_.AttachVmo(std::move(vmo),
                                                   reinterpret_cast<vmoid_t*>(out_buf));
    if (status != ZX_OK) {
        return status;
    }
    *out_actual = sizeof(vmoid_t);
    return ZX_OK;
}

zx_status_t BlockDevice::Rebind() {
    // remove our existing children, ask to bind new children
    return device_rebind(zxdev());
}

zx_status_t BlockDevice::DdkGetProtocol(uint32_t proto_id, void* out_protocol) {
    switch (proto_id) {
    case ZX_PROTOCOL_BLOCK: {
        self_protocol_.GetProto(static_cast<block_protocol_t*>(out_protocol));
        return ZX_OK;
    }
    case ZX_PROTOCOL_BLOCK_PARTITION: {
        if (!parent_partition_protocol_.is_valid()) {
            return ZX_ERR_NOT_SUPPORTED;
        }
        parent_partition_protocol_.GetProto(static_cast<block_partition_protocol_t*>(out_protocol));
        return ZX_OK;
    }
    default:
        return ZX_ERR_NOT_SUPPORTED;
    }
}

zx_status_t BlockDevice::DdkIoctl(uint32_t op, const void* cmd, size_t cmd_len, void* reply,
                                  size_t reply_len, size_t* out_actual) {
    switch (op) {
    case IOCTL_BLOCK_GET_FIFOS:
        return GetFifos(reinterpret_cast<zx_handle_t*>(reply), reply_len, out_actual);
    case IOCTL_BLOCK_ATTACH_VMO:
        return AttachVmo(cmd, cmd_len, reinterpret_cast<vmoid_t*>(reply), reply_len, out_actual);
    case IOCTL_BLOCK_FIFO_CLOSE: {
        return server_manager_.CloseFifoServer();
    }
    case IOCTL_BLOCK_RR_PART:
        return Rebind();
    case IOCTL_BLOCK_GET_INFO: {
        size_t actual;
        zx_status_t status = device_ioctl(parent(), op, cmd, cmd_len, reply, reply_len, &actual);
        if (status == ZX_OK) {
            if (actual >= sizeof(block_info_t)) {
                block_info_t* info = (block_info_t*)reply;
                // set or clear BLOCK_FLAG_BOOTPART appropriately
                if (has_bootpart_) {
                    info->flags |= BLOCK_FLAG_BOOTPART;
                } else {
                    info->flags &= ~BLOCK_FLAG_BOOTPART;
                }
            }
            if (out_actual) {
                *out_actual = actual;
            }
        }
        return status;
    }
    case IOCTL_BLOCK_GET_STATS: {
        return GetStats(cmd, cmd_len, reply, reply_len, out_actual);
    }
    case IOCTL_BLOCK_GET_TYPE_GUID: {
        if (!parent_partition_protocol_.is_valid()) {
            return ZX_ERR_NOT_SUPPORTED;
        }

        guid_t* guid = static_cast<guid_t*>(reply);
        if (reply_len < GUID_LENGTH) {
            return ZX_ERR_BUFFER_TOO_SMALL;
        }
        zx_status_t status = parent_partition_protocol_.GetGuid(GUIDTYPE_TYPE, guid);
        if (status != ZX_OK) {
            return status;
        }
        *out_actual = GUID_LENGTH;
        return ZX_OK;
    }
    case IOCTL_BLOCK_GET_PARTITION_GUID: {
        if (!parent_partition_protocol_.is_valid()) {
            return ZX_ERR_NOT_SUPPORTED;
        }

        guid_t* guid = static_cast<guid_t*>(reply);
        if (reply_len < GUID_LENGTH) {
            return ZX_ERR_BUFFER_TOO_SMALL;
        }
        zx_status_t status = parent_partition_protocol_.GetGuid(GUIDTYPE_INSTANCE, guid);
        if (status != ZX_OK) {
            return status;
        }
        *out_actual = GUID_LENGTH;
        return ZX_OK;
    }
    case IOCTL_BLOCK_GET_NAME: {
        if (!parent_partition_protocol_.is_valid()) {
            return ZX_ERR_NOT_SUPPORTED;
        }
        char* name = static_cast<char*>(reply);
        zx_status_t status = parent_partition_protocol_.GetName(name, reply_len);
        if (status != ZX_OK) {
            return status;
        }
        *out_actual = strlen(name);
        return status;
    }
    default:
        // TODO: this may no longer be necessary now that we handle IOCTL_BLOCK_GET_INFO here
        return device_ioctl(parent(), op, cmd, cmd_len, reply, reply_len, out_actual);
    }
}

// Adapter from read/write to block_op_t
// This is technically incorrect because the read/write hooks should not block,
// but the old adapter in devhost was *also* blocking, so we're no worse off
// than before, but now localized to the block middle layer.
// TODO(swetland) plumbing in devhosts to do deferred replies

// Define the maximum I/O possible for the midlayer; this is arbitrarily
// set to the size of RIO's max payload.
//
// If a smaller value of "max_transfer_size" is defined, that will
// be used instead.
constexpr uint32_t kMaxMidlayerIO = 8192;

zx_status_t BlockDevice::DoIo(void* buf, size_t buf_len, zx_off_t off, bool write) {
    fbl::AutoLock lock(&io_lock_);
    const size_t block_size = info_.block_size;
    const size_t max_xfer = std::min(info_.max_transfer_size, kMaxMidlayerIO);

    if (buf_len == 0) {
        return ZX_OK;
    }
    if ((buf_len % block_size) || (off % block_size)) {
        return ZX_ERR_INVALID_ARGS;
    }
    if (!io_vmo_) {
        if (zx::vmo::create(std::max(max_xfer, static_cast<size_t>(PAGE_SIZE)),
                            0, &io_vmo_) != ZX_OK) {
            return ZX_ERR_INTERNAL;
        }
    }

    // TODO(smklein): These requests can be queued simultaneously without
    // blocking. However, as the comment above mentions, this code probably
    // shouldn't be blocking at all.
    uint64_t sub_txn_offset = 0;
    while (sub_txn_offset < buf_len) {
        void* sub_buf = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(buf) + sub_txn_offset);
        size_t sub_txn_length = std::min(buf_len - sub_txn_offset, max_xfer);

        if (write) {
            if (io_vmo_.write(sub_buf, 0, sub_txn_length) != ZX_OK) {
                return ZX_ERR_INTERNAL;
            }
        }
        block_op_t* op = reinterpret_cast<block_op_t*>(io_op_.get());
        op->command = write ? BLOCK_OP_WRITE : BLOCK_OP_READ;
        ZX_DEBUG_ASSERT(sub_txn_length / block_size < std::numeric_limits<uint32_t>::max());
        op->rw.length = static_cast<uint32_t>(sub_txn_length / block_size);
        op->rw.vmo = io_vmo_.get();
        op->rw.offset_dev = (off + sub_txn_offset) / block_size;
        op->rw.offset_vmo = 0;

        sync_completion_reset(&io_signal_);
        auto completion_cb = [](void* cookie, zx_status_t status, block_op_t* op) {
            BlockDevice* bdev = reinterpret_cast<BlockDevice*>(cookie);
            bdev->io_status_ = status;
            sync_completion_signal(&bdev->io_signal_);
        };

        BlockQueue(op, completion_cb, this);
        sync_completion_wait(&io_signal_, ZX_TIME_INFINITE);

        if (io_status_ != ZX_OK) {
            return io_status_;
        }

        if (!write) {
            if (io_vmo_.read(sub_buf, 0, sub_txn_length) != ZX_OK) {
                return ZX_ERR_INTERNAL;
            }
        }
        sub_txn_offset += sub_txn_length;
    }

    return io_status_;
}

zx_status_t BlockDevice::DdkRead(void* buf, size_t buf_len, zx_off_t off, size_t* actual) {
    zx_status_t status = DoIo(buf, buf_len, off, false);
    *actual = (status == ZX_OK) ? buf_len : 0;
    return status;
}

zx_status_t BlockDevice::DdkWrite(const void* buf, size_t buf_len, zx_off_t off, size_t* actual) {
    zx_status_t status = DoIo(const_cast<void*>(buf), buf_len, off, true);
    *actual = (status == ZX_OK) ? buf_len : 0;
    return status;
}

zx_off_t BlockDevice::DdkGetSize() {
    return device_get_size(parent());
}

void BlockDevice::DdkUnbind() {
    DdkRemove();
}

void BlockDevice::DdkRelease() {
    delete this;
}

void BlockDevice::BlockQuery(block_info_t* block_info, size_t* op_size) {
    memcpy(block_info, &info_, sizeof(block_info_t));
    *op_size = block_op_size_;
}

void BlockDevice::BlockQueue(block_op_t* op, block_impl_queue_callback completion_cb,
                             void* cookie) {
    uint64_t command = op->command & BLOCK_OP_MASK;
    {
        fbl::AutoLock lock(&stat_lock_);
        stats_.total_ops++;
        if (command == BLOCK_OP_READ) {
            stats_.total_reads++;
            stats_.total_blocks_read += op->rw.length;
            stats_.total_blocks += op->rw.length;
        } else if (command == BLOCK_OP_WRITE) {
            stats_.total_writes++;
            stats_.total_blocks_written += op->rw.length;
            stats_.total_blocks += op->rw.length;
        }
    }
    parent_protocol_.Queue(op, completion_cb, cookie);
}

zx_status_t BlockDevice::GetStats(const void* cmd, size_t cmd_len, void* reply,
                                  size_t reply_len, size_t* out_actual) {
    if (cmd_len != sizeof(bool)) {
        return ZX_ERR_INVALID_ARGS;
    }
    block_stats_t* out = reinterpret_cast<block_stats_t*>(reply);
    if (reply_len < sizeof(*out)) {
        return ZX_ERR_BUFFER_TOO_SMALL;
    }

    fbl::AutoLock lock(&stat_lock_);
    if (enable_stats_) {
        out->total_ops = stats_.total_ops;
        out->total_blocks = stats_.total_blocks;
        out->total_reads = stats_.total_reads;
        out->total_blocks_read = stats_.total_blocks_read;
        out->total_writes = stats_.total_writes;
        out->total_blocks_written = stats_.total_blocks_written;
        bool clear = *(bool*)cmd;
        if (clear) {
            stats_.total_ops = 0;
            stats_.total_blocks = 0;
            stats_.total_reads = 0;
            stats_.total_blocks_read = 0;
            stats_.total_writes = 0;
            stats_.total_blocks_written = 0;
        }
        *out_actual = sizeof(*out);
        return ZX_OK;
    } else {
        return ZX_ERR_NOT_SUPPORTED;
    }
}

zx_status_t BlockDevice::Bind(void* ctx, zx_device_t* dev) {
    auto bdev = std::make_unique<BlockDevice>(dev);

    // The Block Implementation Protocol is required.
    if (!bdev->parent_protocol_.is_valid()) {
        printf("ERROR: block device '%s': does not support block protocol\n",
               device_get_name(dev));
        return ZX_ERR_NOT_SUPPORTED;
    }

    bdev->parent_protocol_.Query(&bdev->info_, &bdev->block_op_size_);

    if (bdev->info_.max_transfer_size < bdev->info_.block_size) {
        printf("ERROR: block device '%s': has smaller max xfer (0x%x) than block size (0x%x)\n",
               device_get_name(dev), bdev->info_.max_transfer_size, bdev->info_.block_size);
        return ZX_ERR_NOT_SUPPORTED;
    }

    zx_status_t status;
    bdev->io_op_ = std::make_unique<uint8_t[]>(bdev->block_op_size_);
    size_t block_size = bdev->info_.block_size;
    if ((block_size < 512) || (block_size & (block_size - 1))) {
        printf("block: device '%s': invalid block size: %zu\n",
               device_get_name(dev), block_size);
        return ZX_ERR_NOT_SUPPORTED;
    }

    // check to see if we have a ZBI partition map
    // and set BLOCK_FLAG_BOOTPART accordingly
    uint8_t buffer[METADATA_PARTITION_MAP_MAX];
    size_t actual;
    status = device_get_metadata(dev, DEVICE_METADATA_PARTITION_MAP, buffer, sizeof(buffer),
                                 &actual);
    if (status == ZX_OK && actual >= sizeof(zbi_partition_map_t)) {
        bdev->has_bootpart_ = true;
    }

    // We implement |ZX_PROTOCOL_BLOCK|, not |ZX_PROTOCOL_BLOCK_IMPL|. This is the
    // "core driver" protocol for block device drivers.
    status = bdev->DdkAdd("block");
    if (status != ZX_OK) {
        return status;
    }

    // The device has been added; we'll release it in blkdev_release.
    __UNUSED auto r = bdev.release();
    return ZX_OK;
}

static constexpr zx_driver_ops_t block_driver_ops = []() {
    zx_driver_ops_t ops = {};
    ops.version = DRIVER_OPS_VERSION;
    ops.bind = &BlockDevice::Bind;
    return ops;
}();

ZIRCON_DRIVER_BEGIN(block, block_driver_ops, "zircon", "0.1", 1)
    BI_MATCH_IF(EQ, BIND_PROTOCOL, ZX_PROTOCOL_BLOCK_IMPL),
ZIRCON_DRIVER_END(block)
