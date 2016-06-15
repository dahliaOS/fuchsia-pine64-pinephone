// Copyright 2016 The Fuchsia Authors
// Copyright (c) 2013 Corey Tabaka
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef __DEV_CLASS_BLOCK_H
#define __DEV_CLASS_BLOCK_H

#include <compiler.h>
#include <dev/driver.h>

/* block interface */
struct block_ops {
    struct driver_ops std;

    ssize_t (*get_block_size)(struct device *dev);
    ssize_t (*get_block_count)(struct device *dev);

    ssize_t (*write)(struct device *dev, off_t offset, const void *buf, size_t count);
    ssize_t (*read)(struct device *dev, off_t offset, void *buf, size_t count);

    status_t (*flush)(struct device *dev);
};

__BEGIN_CDECLS

ssize_t class_block_get_size(struct device *dev);
ssize_t class_block_get_count(struct device *dev);
ssize_t class_block_write(struct device *dev, off_t offset, const void *buf, size_t count);
ssize_t class_block_read(struct device *dev, off_t offset, void *buf, size_t count);
status_t class_block_flush(struct device *dev);

__END_CDECLS

#endif

