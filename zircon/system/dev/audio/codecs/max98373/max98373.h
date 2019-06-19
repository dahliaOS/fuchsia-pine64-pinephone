// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#pragma once

#include <threads.h>

#include <memory>

#include <ddk/debug.h>
#include <ddk/device.h>
#include <ddktl/device.h>
#include <ddktl/i2c-channel.h>
#include <ddktl/protocol/codec.h>
#include <ddktl/protocol/gpio.h>

namespace audio {

class Max98373;
using DeviceType = ddk::Device<Max98373, ddk::Unbindable>;

class Max98373 : public DeviceType, // Not final for unit tests.
                public ddk::CodecProtocol<Max98373, ddk::base_protocol> {
public:
    static zx_status_t Create(zx_device_t* parent);

    explicit Max98373(zx_device_t* device, const ddk::I2cChannel& i2c,
                     const ddk::GpioProtocolClient& codec_reset)
        : DeviceType(device), i2c_(i2c), codec_reset_(codec_reset) {}
    zx_status_t Bind();

    void DdkRelease() {
        delete this;
    }
    void DdkUnbind() {
        Shutdown();
        DdkRemove();
    }
    zx_status_t DdkSuspend(uint32_t flags) {
        Shutdown();
        return ZX_OK;
    }

    void CodecReset(codec_reset_callback callback, void* cookie);
    void CodecGetInfo(codec_get_info_callback callback, void* cookie);
    void CodecIsBridgeable(codec_is_bridgeable_callback callback, void* cookie);
    void CodecSetBridgedMode(bool enable_bridged_mode, codec_set_bridged_mode_callback callback,
                             void* cookie);
    void CodecGetDaiFormats(codec_get_dai_formats_callback callback, void* cookie);
    void CodecSetDaiFormat(const dai_format_t* format, codec_set_dai_format_callback callback,
                           void* cookie);
    void CodecGetGainFormat(codec_get_gain_format_callback callback, void* cookie);
    void CodecGetGainState(codec_get_gain_state_callback callback, void* cookie);
    void CodecSetGainState(const gain_state_t* gain_state, codec_set_gain_state_callback callback,
                           void* cookie);
    void CodecGetPlugState(codec_get_plug_state_callback callback, void* cookie);

    zx_status_t ResetAndInitialize();

protected:
    bool initialized_ = false; // Protected for unit tests.

private:
    static constexpr float kMaxGain = 0;
    static constexpr float kMinGain = -100.0;
    static constexpr float kGainStep = 0.5;

    zx_status_t WriteReg(uint8_t reg, uint8_t value);
    void Shutdown();

    ddk::I2cChannel i2c_;
    ddk::GpioProtocolClient codec_reset_;
    float current_gain_ = 0;
    thrd_t thread_;
};
} // namespace audio
