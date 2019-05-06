// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SRC_CONNECTIVITY_BLUETOOTH_CORE_BT_HOST_GAP_PAIRING_STATE_H_
#define SRC_CONNECTIVITY_BLUETOOTH_CORE_BT_HOST_GAP_PAIRING_STATE_H_

#include <fbl/macros.h>

#include "src/connectivity/bluetooth/core/bt-host/hci/hci.h"
#include "src/connectivity/bluetooth/core/bt-host/sm/smp.h"

namespace bt {
namespace gap {

// Represents the local user interaction that will occur, as inferred from Core
// Spec v5.0 Vol 3, Part C, Sec 5.2.2.6 (Table 5.7). This is not directly
// coupled to the reply action for the HCI "User" event for pairing; e.g.
// kDisplayPasskey may mean automatically confirming User Confirmation Request
// or displaying the value from User Passkey Notification.
enum class PairingAction {
  // Don't involve the user.
  kAutomatic,

  // Request yes/no consent.
  kGetConsent,

  // Display 6-digit value with "cancel."
  kDisplayPasskey,

  // Display 6-digit value with "yes/no."
  kComparePasskey,

  // Request a 6-digit value entry.
  kRequestPasskey,
};

class PairingState final {
 public:
  // Used to report the status of a pairing procedure.
  using StatusCallback =
      fit::function<void(hci::ConnectionHandle, hci::Status)>;
  PairingState(StatusCallback status_cb);
  ~PairingState() = default;

  bool initiator() const { return initiator_; }

  // Starts pairing against the peer, if pairing is not already in progress.
  // If not, this device becomes the pairing initiator, and returns
  // |kSendAuthenticationRequest| to indicate that the caller shall send an
  // Authentication Request for this peer.
  enum class InitiatorAction {
    kDoNotSendAuthenticationRequest,
    kSendAuthenticationRequest,
  };
  [[nodiscard]] InitiatorAction InitiatePairing();

  void OnIoCapabilityResponse(hci::IOCapability peer_iocap);

 private:
  enum class State {
    // Wait for initiator's IO Capability Response or for locally-initiated
    // pairing.
    kIdle,

    // As initiator, wait for IO Capability Request or Authentication Complete.
    kInitiatorPairingStarted,

    // As initiator, wait for IO Capability Response.
    kInitiatorWaitIoCapResponse,

    // As responder, wait for IO Capability Request.
    kResponderWaitIoCapRequest,

    // Wait for controller event for pairing action.
    kWaitPairingEvent,

    // Wait for Simple Pairing Complete.
    kWaitPairingComplete,

    // Wait for Link Key Notification.
    kWaitLinkKey,

    // As initiator, wait for Authentication Complete.
    kInitiatorWaitAuthComplete,

    // Wait for Encryption Change.
    kWaitEncryption,

    // Error occurred; wait for link closure and ignore events.
    kFailed,
  };

  State state() const { return state_; }

  bool initiator_;
  State state_;

  DISALLOW_COPY_AND_ASSIGN_ALLOW_MOVE(PairingState);
};

PairingAction GetInitiatorPairingAction(hci::IOCapability initiator_cap,
                                        hci::IOCapability responder_cap);
PairingAction GetResponderPairingAction(hci::IOCapability initiator_cap,
                                        hci::IOCapability responder_cap);
hci::EventCode GetExpectedEvent(hci::IOCapability local_cap,
                                hci::IOCapability peer_cap);
bool IsPairingAuthenticated(hci::IOCapability local_cap,
                            hci::IOCapability peer_cap);

}  // namespace gap
}  // namespace bt

#endif  // SRC_CONNECTIVITY_BLUETOOTH_CORE_BT_HOST_GAP_PAIRING_STATE_H_
