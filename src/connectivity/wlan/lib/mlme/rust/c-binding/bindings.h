// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SRC_CONNECTIVITY_WLAN_LIB_MLME_RUST_C_BINDING_BINDINGS_H_
#define SRC_CONNECTIVITY_WLAN_LIB_MLME_RUST_C_BINDING_BINDINGS_H_

// Warning:
// This file was autogenerated by cbindgen.
// Do not modify this file manually.

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * A STA running in Client mode.
 * The Client STA is in its early development process and does not yet manage its internal state
 * machine or track negotiated capabilities.
 */
typedef struct wlan_client_sta_t wlan_client_sta_t;

/**
 * Manages all SNS for a STA.
 */
typedef struct mlme_sequence_manager_t mlme_sequence_manager_t;

/**
 * An output buffer requires its owner to manage the underlying buffer's memory themselves.
 * An output buffer is used for every buffer handed from Rust to C++.
 */
typedef struct {
  /**
   * Pointer to the buffer's underlying data structure.
   */
  void *raw;
  /**
   * Pointer to the start of the buffer's data portion and the amount of bytes written.
   */
  uint8_t *data;
  uintptr_t written_bytes;
} mlme_out_buf_t;

/**
 * A `Device` allows transmitting frames and MLME messages.
 */
typedef struct {
  void *device;
  /**
   * Request to deliver an Ethernet II frame to Fuchsia's Netstack.
   */
  int32_t (*deliver_eth_frame)(void *device, const uint8_t *data, uintptr_t len);
  /**
   * Request to deliver a WLAN frame over the air.
   */
  int32_t (*send_wlan_frame)(void *device, mlme_out_buf_t buf, uint32_t flags);
  /**
   * Returns an unowned channel handle to MLME's SME peer, or ZX_HANDLE_INVALID
   * if no SME channel is available.
   */
  uint32_t (*get_sme_channel)(void *device);
} mlme_device_ops_t;

/**
 * An input buffer will always be returned to its original owner when no longer being used.
 * An input buffer is used for every buffer handed from C++ to Rust.
 */
typedef struct {
  /**
   * Returns the buffer's ownership and free it.
   */
  void (*free_buffer)(void *raw);
  /**
   * Pointer to the buffer's underlying data structure.
   */
  void *raw;
  /**
   * Pointer to the start of the buffer's data portion and its length.
   */
  uint8_t *data;
  uintptr_t len;
} mlme_in_buf_t;

typedef struct {
  /**
   * Acquire a `InBuf` with a given minimum length from the provider.
   * The provider must release the underlying buffer's ownership and transfer it to this crate.
   * The buffer will be returned via the `free_buffer` callback when it's no longer used.
   */
  mlme_in_buf_t (*get_buffer)(uintptr_t min_len);
} mlme_buffer_provider_ops_t;

extern "C" void client_sta_delete(wlan_client_sta_t *sta);

extern "C" int32_t client_sta_handle_data_frame(wlan_client_sta_t *sta, const uint8_t *data_frame,
                                                uintptr_t data_frame_len, bool has_padding);

extern "C" wlan_client_sta_t *client_sta_new(mlme_device_ops_t device,
                                             mlme_buffer_provider_ops_t buf_provider,
                                             const uint8_t (*bssid)[6],
                                             const uint8_t (*iface_mac)[6]);

extern "C" int32_t client_sta_send_data_frame(wlan_client_sta_t *sta, const uint8_t (*src)[6],
                                              const uint8_t (*dest)[6], bool is_protected,
                                              bool is_qos, uint16_t ether_type,
                                              const uint8_t *payload, uintptr_t payload_len);

extern "C" int32_t client_sta_send_deauth_frame(wlan_client_sta_t *sta, uint16_t reason_code);

extern "C" int32_t client_sta_send_keep_alive_resp_frame(wlan_client_sta_t *sta);

extern "C" int32_t client_sta_send_open_auth_frame(wlan_client_sta_t *sta);

extern "C" mlme_sequence_manager_t *client_sta_seq_mgr(wlan_client_sta_t *sta);

extern "C" int32_t mlme_is_valid_open_auth_resp(const uint8_t *data, uintptr_t len);

extern "C" void mlme_sequence_manager_delete(mlme_sequence_manager_t *mgr);

extern "C" mlme_sequence_manager_t *mlme_sequence_manager_new(void);

extern "C" uint32_t mlme_sequence_manager_next_sns1(mlme_sequence_manager_t *mgr,
                                                    const uint8_t (*sta_addr)[6]);

extern "C" uint32_t mlme_sequence_manager_next_sns2(mlme_sequence_manager_t *mgr,
                                                    const uint8_t (*sta_addr)[6], uint16_t tid);

#endif /* SRC_CONNECTIVITY_WLAN_LIB_MLME_RUST_C_BINDING_BINDINGS_H_ */
