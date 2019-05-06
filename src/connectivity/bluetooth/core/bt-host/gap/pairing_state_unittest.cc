// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/connectivity/bluetooth/core/bt-host/gap/pairing_state.h"

#include "gtest/gtest.h"

namespace bt {
namespace gap {
namespace {

using hci::IOCapability;
using hci::kUserConfirmationRequestEventCode;
using hci::kUserPasskeyNotificationEventCode;
using hci::kUserPasskeyRequestEventCode;

void NoOpStatusCallback(hci::ConnectionHandle, hci::Status){};

TEST(GAP_PairingStateTest, PairingStateStartsAsResponder) {
  PairingState pairing_state(NoOpStatusCallback);
  EXPECT_FALSE(pairing_state.initiator());
}

TEST(GAP_PairingStateTest, PairingStateRemainsResponderAfterPeerIoCapResponse) {
  PairingState pairing_state(NoOpStatusCallback);
  pairing_state.OnIoCapabilityResponse(hci::IOCapability::kDisplayYesNo);
  EXPECT_FALSE(pairing_state.initiator());
}

TEST(GAP_PairingStateTest,
     PairingStateBecomesInitiatorAfterLocalPairingInitiated) {
  PairingState pairing_state(NoOpStatusCallback);
  EXPECT_EQ(PairingState::InitiatorAction::kSendAuthenticationRequest,
            pairing_state.InitiatePairing());
  EXPECT_TRUE(pairing_state.initiator());
}

TEST(GAP_PairingStateTest, PairingStateSendsAuthenticationRequestExactlyOnce) {
  PairingState pairing_state(NoOpStatusCallback);
  EXPECT_EQ(PairingState::InitiatorAction::kSendAuthenticationRequest,
            pairing_state.InitiatePairing());
  EXPECT_TRUE(pairing_state.initiator());

  EXPECT_EQ(PairingState::InitiatorAction::kDoNotSendAuthenticationRequest,
            pairing_state.InitiatePairing());
  EXPECT_TRUE(pairing_state.initiator());
}

TEST(
    GAP_PairingStateTest,
    PairingStateRemainsResponderIfPairingInitiatedWhileResponderPairingInProgress) {
  PairingState pairing_state(NoOpStatusCallback);
  pairing_state.OnIoCapabilityResponse(hci::IOCapability::kDisplayYesNo);
  ASSERT_FALSE(pairing_state.initiator());

  EXPECT_EQ(PairingState::InitiatorAction::kDoNotSendAuthenticationRequest,
            pairing_state.InitiatePairing());
  EXPECT_FALSE(pairing_state.initiator());
}

// Test helper to inspect StatusCallback invocations.
class TestStatusHandler final {
 public:
  auto MakeStatusCallback() {
    return [this]([[maybe_unused]] hci::ConnectionHandle, hci::Status status) {
      call_count_++;
      status_ = status;
    };
  }

  auto call_count() const { return call_count_; }

  // Returns std::nullopt if |call_count() < 1|, otherwise the most recent
  // status this was called with.
  auto& status() const { return status_; }

 private:
  int call_count_ = 0;
  std::optional<hci::Status> status_;
};

TEST(GAP_PairingStateTest, TestStatusHandlerTracksStatusCallbackInvocations) {
  TestStatusHandler handler;
  EXPECT_EQ(0, handler.call_count());
  EXPECT_FALSE(handler.status());

  PairingState::StatusCallback status_cb = handler.MakeStatusCallback();
  EXPECT_EQ(0, handler.call_count());
  EXPECT_FALSE(handler.status());

  status_cb(hci::ConnectionHandle(0x0A0B),
            hci::Status(hci::StatusCode::kPairingNotAllowed));
  EXPECT_EQ(1, handler.call_count());
  ASSERT_TRUE(handler.status());
  EXPECT_EQ(hci::Status(hci::StatusCode::kPairingNotAllowed),
            *handler.status());
}

// PairingAction expected answers are inferred from "device A" Authentication
// Stage 1 specs in v5.0 Vol 3, Part C, Sec 5.2.2.6, Table 5.7.
TEST(GAP_PairingStateTest, GetInitiatorPairingAction) {
  EXPECT_EQ(PairingAction::kAutomatic,
            GetInitiatorPairingAction(IOCapability::kDisplayOnly,
                                      IOCapability::kDisplayOnly));
  EXPECT_EQ(PairingAction::kDisplayPasskey,
            GetInitiatorPairingAction(IOCapability::kDisplayOnly,
                                      IOCapability::kDisplayYesNo));
  EXPECT_EQ(PairingAction::kDisplayPasskey,
            GetInitiatorPairingAction(IOCapability::kDisplayOnly,
                                      IOCapability::kKeyboardOnly));
  EXPECT_EQ(PairingAction::kAutomatic,
            GetInitiatorPairingAction(IOCapability::kDisplayOnly,
                                      IOCapability::kNoInputNoOutput));

  EXPECT_EQ(PairingAction::kComparePasskey,
            GetInitiatorPairingAction(IOCapability::kDisplayYesNo,
                                      IOCapability::kDisplayOnly));
  EXPECT_EQ(PairingAction::kDisplayPasskey,
            GetInitiatorPairingAction(IOCapability::kDisplayYesNo,
                                      IOCapability::kDisplayYesNo));
  EXPECT_EQ(PairingAction::kDisplayPasskey,
            GetInitiatorPairingAction(IOCapability::kDisplayYesNo,
                                      IOCapability::kKeyboardOnly));
  EXPECT_EQ(PairingAction::kGetConsent,
            GetInitiatorPairingAction(IOCapability::kDisplayYesNo,
                                      IOCapability::kNoInputNoOutput));

  EXPECT_EQ(PairingAction::kRequestPasskey,
            GetInitiatorPairingAction(IOCapability::kKeyboardOnly,
                                      IOCapability::kDisplayOnly));
  EXPECT_EQ(PairingAction::kRequestPasskey,
            GetInitiatorPairingAction(IOCapability::kKeyboardOnly,
                                      IOCapability::kDisplayYesNo));
  EXPECT_EQ(PairingAction::kRequestPasskey,
            GetInitiatorPairingAction(IOCapability::kKeyboardOnly,
                                      IOCapability::kKeyboardOnly));
  EXPECT_EQ(PairingAction::kAutomatic,
            GetInitiatorPairingAction(IOCapability::kKeyboardOnly,
                                      IOCapability::kNoInputNoOutput));

  EXPECT_EQ(PairingAction::kAutomatic,
            GetInitiatorPairingAction(IOCapability::kNoInputNoOutput,
                                      IOCapability::kDisplayOnly));
  EXPECT_EQ(PairingAction::kAutomatic,
            GetInitiatorPairingAction(IOCapability::kNoInputNoOutput,
                                      IOCapability::kDisplayYesNo));
  EXPECT_EQ(PairingAction::kAutomatic,
            GetInitiatorPairingAction(IOCapability::kNoInputNoOutput,
                                      IOCapability::kKeyboardOnly));
  EXPECT_EQ(PairingAction::kAutomatic,
            GetInitiatorPairingAction(IOCapability::kNoInputNoOutput,
                                      IOCapability::kNoInputNoOutput));
}

// Ibid., but for "device B."
TEST(GAP_PairingStateTest, GetResponderPairingAction) {
  EXPECT_EQ(PairingAction::kAutomatic,
            GetResponderPairingAction(IOCapability::kDisplayOnly,
                                      IOCapability::kDisplayOnly));
  EXPECT_EQ(PairingAction::kComparePasskey,
            GetResponderPairingAction(IOCapability::kDisplayOnly,
                                      IOCapability::kDisplayYesNo));
  EXPECT_EQ(PairingAction::kRequestPasskey,
            GetResponderPairingAction(IOCapability::kDisplayOnly,
                                      IOCapability::kKeyboardOnly));
  EXPECT_EQ(PairingAction::kAutomatic,
            GetResponderPairingAction(IOCapability::kDisplayOnly,
                                      IOCapability::kNoInputNoOutput));

  EXPECT_EQ(PairingAction::kDisplayPasskey,
            GetResponderPairingAction(IOCapability::kDisplayYesNo,
                                      IOCapability::kDisplayOnly));
  EXPECT_EQ(PairingAction::kComparePasskey,
            GetResponderPairingAction(IOCapability::kDisplayYesNo,
                                      IOCapability::kDisplayYesNo));
  EXPECT_EQ(PairingAction::kRequestPasskey,
            GetResponderPairingAction(IOCapability::kDisplayYesNo,
                                      IOCapability::kKeyboardOnly));
  EXPECT_EQ(PairingAction::kAutomatic,
            GetResponderPairingAction(IOCapability::kDisplayYesNo,
                                      IOCapability::kNoInputNoOutput));

  EXPECT_EQ(PairingAction::kDisplayPasskey,
            GetResponderPairingAction(IOCapability::kKeyboardOnly,
                                      IOCapability::kDisplayOnly));
  EXPECT_EQ(PairingAction::kDisplayPasskey,
            GetResponderPairingAction(IOCapability::kKeyboardOnly,
                                      IOCapability::kDisplayYesNo));
  EXPECT_EQ(PairingAction::kRequestPasskey,
            GetResponderPairingAction(IOCapability::kKeyboardOnly,
                                      IOCapability::kKeyboardOnly));
  EXPECT_EQ(PairingAction::kAutomatic,
            GetResponderPairingAction(IOCapability::kKeyboardOnly,
                                      IOCapability::kNoInputNoOutput));

  EXPECT_EQ(PairingAction::kAutomatic,
            GetResponderPairingAction(IOCapability::kNoInputNoOutput,
                                      IOCapability::kDisplayOnly));
  EXPECT_EQ(PairingAction::kGetConsent,
            GetResponderPairingAction(IOCapability::kNoInputNoOutput,
                                      IOCapability::kDisplayYesNo));
  EXPECT_EQ(PairingAction::kGetConsent,
            GetResponderPairingAction(IOCapability::kNoInputNoOutput,
                                      IOCapability::kKeyboardOnly));
  EXPECT_EQ(PairingAction::kAutomatic,
            GetResponderPairingAction(IOCapability::kNoInputNoOutput,
                                      IOCapability::kNoInputNoOutput));
}

// Events are obtained from ibid. association models, mapped to HCI sequences in
// v5.0 Vol 3, Vol 2, Part F, Sec 4.2.10–15.
TEST(GAP_PairingStateTest, GetExpectedEvent) {
  EXPECT_EQ(
      kUserConfirmationRequestEventCode,
      GetExpectedEvent(IOCapability::kDisplayOnly, IOCapability::kDisplayOnly));
  EXPECT_EQ(kUserConfirmationRequestEventCode,
            GetExpectedEvent(IOCapability::kDisplayOnly,
                             IOCapability::kDisplayYesNo));
  EXPECT_EQ(kUserPasskeyNotificationEventCode,
            GetExpectedEvent(IOCapability::kDisplayOnly,
                             IOCapability::kKeyboardOnly));
  EXPECT_EQ(kUserConfirmationRequestEventCode,
            GetExpectedEvent(IOCapability::kDisplayOnly,
                             IOCapability::kNoInputNoOutput));

  EXPECT_EQ(kUserConfirmationRequestEventCode,
            GetExpectedEvent(IOCapability::kDisplayYesNo,
                             IOCapability::kDisplayOnly));
  EXPECT_EQ(kUserConfirmationRequestEventCode,
            GetExpectedEvent(IOCapability::kDisplayYesNo,
                             IOCapability::kDisplayYesNo));
  EXPECT_EQ(kUserPasskeyNotificationEventCode,
            GetExpectedEvent(IOCapability::kDisplayYesNo,
                             IOCapability::kKeyboardOnly));
  EXPECT_EQ(kUserConfirmationRequestEventCode,
            GetExpectedEvent(IOCapability::kDisplayYesNo,
                             IOCapability::kNoInputNoOutput));

  EXPECT_EQ(kUserPasskeyRequestEventCode,
            GetExpectedEvent(IOCapability::kKeyboardOnly,
                             IOCapability::kDisplayOnly));
  EXPECT_EQ(kUserPasskeyRequestEventCode,
            GetExpectedEvent(IOCapability::kKeyboardOnly,
                             IOCapability::kDisplayYesNo));
  EXPECT_EQ(kUserPasskeyRequestEventCode,
            GetExpectedEvent(IOCapability::kKeyboardOnly,
                             IOCapability::kKeyboardOnly));
  EXPECT_EQ(kUserConfirmationRequestEventCode,
            GetExpectedEvent(IOCapability::kKeyboardOnly,
                             IOCapability::kNoInputNoOutput));

  EXPECT_EQ(kUserConfirmationRequestEventCode,
            GetExpectedEvent(IOCapability::kNoInputNoOutput,
                             IOCapability::kDisplayOnly));
  EXPECT_EQ(kUserConfirmationRequestEventCode,
            GetExpectedEvent(IOCapability::kNoInputNoOutput,
                             IOCapability::kDisplayYesNo));
  EXPECT_EQ(kUserConfirmationRequestEventCode,
            GetExpectedEvent(IOCapability::kNoInputNoOutput,
                             IOCapability::kKeyboardOnly));
  EXPECT_EQ(kUserConfirmationRequestEventCode,
            GetExpectedEvent(IOCapability::kNoInputNoOutput,
                             IOCapability::kNoInputNoOutput));
}

// Level of authentication from ibid. table.
TEST(GAP_PairingStateTest, IsPairingAuthenticated) {
  EXPECT_FALSE(IsPairingAuthenticated(IOCapability::kDisplayOnly,
                                      IOCapability::kDisplayOnly));
  EXPECT_FALSE(IsPairingAuthenticated(IOCapability::kDisplayOnly,
                                      IOCapability::kDisplayYesNo));
  EXPECT_TRUE(IsPairingAuthenticated(IOCapability::kDisplayOnly,
                                     IOCapability::kKeyboardOnly));
  EXPECT_FALSE(IsPairingAuthenticated(IOCapability::kDisplayOnly,
                                      IOCapability::kNoInputNoOutput));

  EXPECT_FALSE(IsPairingAuthenticated(IOCapability::kDisplayYesNo,
                                      IOCapability::kDisplayOnly));
  EXPECT_TRUE(IsPairingAuthenticated(IOCapability::kDisplayYesNo,
                                     IOCapability::kDisplayYesNo));
  EXPECT_TRUE(IsPairingAuthenticated(IOCapability::kDisplayYesNo,
                                     IOCapability::kKeyboardOnly));
  EXPECT_FALSE(IsPairingAuthenticated(IOCapability::kDisplayYesNo,
                                      IOCapability::kNoInputNoOutput));

  EXPECT_TRUE(IsPairingAuthenticated(IOCapability::kKeyboardOnly,
                                     IOCapability::kDisplayOnly));
  EXPECT_TRUE(IsPairingAuthenticated(IOCapability::kKeyboardOnly,
                                     IOCapability::kDisplayYesNo));
  EXPECT_TRUE(IsPairingAuthenticated(IOCapability::kKeyboardOnly,
                                     IOCapability::kKeyboardOnly));
  EXPECT_FALSE(IsPairingAuthenticated(IOCapability::kKeyboardOnly,
                                      IOCapability::kNoInputNoOutput));

  EXPECT_FALSE(IsPairingAuthenticated(IOCapability::kNoInputNoOutput,
                                      IOCapability::kDisplayOnly));
  EXPECT_FALSE(IsPairingAuthenticated(IOCapability::kNoInputNoOutput,
                                      IOCapability::kDisplayYesNo));
  EXPECT_FALSE(IsPairingAuthenticated(IOCapability::kNoInputNoOutput,
                                      IOCapability::kKeyboardOnly));
  EXPECT_FALSE(IsPairingAuthenticated(IOCapability::kNoInputNoOutput,
                                      IOCapability::kNoInputNoOutput));
}

}  // namespace
}  // namespace gap
}  // namespace bt
