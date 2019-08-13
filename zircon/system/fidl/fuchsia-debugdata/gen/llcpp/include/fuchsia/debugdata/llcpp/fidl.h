// WARNING: This file is machine generated by fidlgen.

#pragma once

#include <lib/fidl/internal.h>
#include <lib/fidl/cpp/vector_view.h>
#include <lib/fidl/cpp/string_view.h>
#include <lib/fidl/llcpp/array.h>
#include <lib/fidl/llcpp/coding.h>
#include <lib/fidl/llcpp/sync_call.h>
#include <lib/fidl/llcpp/traits.h>
#include <lib/fidl/llcpp/transaction.h>
#include <lib/fit/function.h>
#include <lib/zx/channel.h>
#include <lib/zx/vmo.h>
#include <zircon/fidl.h>

namespace llcpp {

namespace fuchsia {
namespace debugdata {

class DebugData;

extern "C" const fidl_type_t fuchsia_debugdata_DebugDataPublishRequestTable;
extern "C" const fidl_type_t fuchsia_debugdata_DebugDataLoadConfigRequestTable;
extern "C" const fidl_type_t fuchsia_debugdata_DebugDataLoadConfigResponseTable;

// DebugData defines the interface for instrumentation configuration and data publishing.
class DebugData final {
  DebugData() = delete;
 public:
  static constexpr char Name[] = "fuchsia.debugdata.DebugData";

  struct PublishRequest final {
    FIDL_ALIGNDECL
    fidl_message_header_t _hdr;
    ::fidl::StringView data_sink;
    ::zx::vmo data;

    static constexpr const fidl_type_t* Type = &fuchsia_debugdata_DebugDataPublishRequestTable;
    static constexpr uint32_t MaxNumHandles = 1;
    static constexpr uint32_t PrimarySize = 40;
    static constexpr uint32_t MaxOutOfLine = 1024;
    static constexpr bool HasFlexibleEnvelope = false;
    static constexpr ::fidl::internal::TransactionalMessageKind MessageKind =
        ::fidl::internal::TransactionalMessageKind::kRequest;
  };

  struct LoadConfigResponse final {
    FIDL_ALIGNDECL
    fidl_message_header_t _hdr;
    ::zx::vmo config;

    static constexpr const fidl_type_t* Type = &fuchsia_debugdata_DebugDataLoadConfigResponseTable;
    static constexpr uint32_t MaxNumHandles = 1;
    static constexpr uint32_t PrimarySize = 24;
    static constexpr uint32_t MaxOutOfLine = 0;
    static constexpr bool HasFlexibleEnvelope = false;
    static constexpr ::fidl::internal::TransactionalMessageKind MessageKind =
        ::fidl::internal::TransactionalMessageKind::kResponse;
  };
  struct LoadConfigRequest final {
    FIDL_ALIGNDECL
    fidl_message_header_t _hdr;
    ::fidl::StringView config_name;

    static constexpr const fidl_type_t* Type = &fuchsia_debugdata_DebugDataLoadConfigRequestTable;
    static constexpr uint32_t MaxNumHandles = 0;
    static constexpr uint32_t PrimarySize = 32;
    static constexpr uint32_t MaxOutOfLine = 1024;
    static constexpr bool HasFlexibleEnvelope = false;
    static constexpr ::fidl::internal::TransactionalMessageKind MessageKind =
        ::fidl::internal::TransactionalMessageKind::kRequest;
    using ResponseType = LoadConfigResponse;
  };


  // Collection of return types of FIDL calls in this interface.
  class ResultOf final {
    ResultOf() = delete;
   private:
    class Publish_Impl final : private ::fidl::internal::StatusAndError {
      using Super = ::fidl::internal::StatusAndError;
     public:
      Publish_Impl(zx::unowned_channel _client_end, ::fidl::StringView data_sink, ::zx::vmo data);
      ~Publish_Impl() = default;
      Publish_Impl(Publish_Impl&& other) = default;
      Publish_Impl& operator=(Publish_Impl&& other) = default;
      using Super::status;
      using Super::error;
      using Super::ok;
    };
    template <typename ResponseType>
    class LoadConfig_Impl final : private ::fidl::internal::OwnedSyncCallBase<ResponseType> {
      using Super = ::fidl::internal::OwnedSyncCallBase<ResponseType>;
     public:
      LoadConfig_Impl(zx::unowned_channel _client_end, ::fidl::StringView config_name);
      ~LoadConfig_Impl() = default;
      LoadConfig_Impl(LoadConfig_Impl&& other) = default;
      LoadConfig_Impl& operator=(LoadConfig_Impl&& other) = default;
      using Super::status;
      using Super::error;
      using Super::ok;
      using Super::Unwrap;
      using Super::value;
      using Super::operator->;
      using Super::operator*;
    };

   public:
    using Publish = Publish_Impl;
    using LoadConfig = LoadConfig_Impl<LoadConfigResponse>;
  };

  // Collection of return types of FIDL calls in this interface,
  // when the caller-allocate flavor or in-place call is used.
  class UnownedResultOf final {
    UnownedResultOf() = delete;
   private:
    class Publish_Impl final : private ::fidl::internal::StatusAndError {
      using Super = ::fidl::internal::StatusAndError;
     public:
      Publish_Impl(zx::unowned_channel _client_end, ::fidl::BytePart _request_buffer, ::fidl::StringView data_sink, ::zx::vmo data);
      ~Publish_Impl() = default;
      Publish_Impl(Publish_Impl&& other) = default;
      Publish_Impl& operator=(Publish_Impl&& other) = default;
      using Super::status;
      using Super::error;
      using Super::ok;
    };
    template <typename ResponseType>
    class LoadConfig_Impl final : private ::fidl::internal::UnownedSyncCallBase<ResponseType> {
      using Super = ::fidl::internal::UnownedSyncCallBase<ResponseType>;
     public:
      LoadConfig_Impl(zx::unowned_channel _client_end, ::fidl::BytePart _request_buffer, ::fidl::StringView config_name, ::fidl::BytePart _response_buffer);
      ~LoadConfig_Impl() = default;
      LoadConfig_Impl(LoadConfig_Impl&& other) = default;
      LoadConfig_Impl& operator=(LoadConfig_Impl&& other) = default;
      using Super::status;
      using Super::error;
      using Super::ok;
      using Super::Unwrap;
      using Super::value;
      using Super::operator->;
      using Super::operator*;
    };

   public:
    using Publish = Publish_Impl;
    using LoadConfig = LoadConfig_Impl<LoadConfigResponse>;
  };

  class SyncClient final {
   public:
    explicit SyncClient(::zx::channel channel) : channel_(std::move(channel)) {}
    ~SyncClient() = default;
    SyncClient(SyncClient&&) = default;
    SyncClient& operator=(SyncClient&&) = default;

    const ::zx::channel& channel() const { return channel_; }

    ::zx::channel* mutable_channel() { return &channel_; }

    // The program runtime sends a string naming a `data_sink` and transfers the sole handle to
    // a VMO containing the `data` it wants published there.  The `data_sink` string identifies
    // a type of data, and the VMO's object name can specifically identify the data set in this
    // VMO.  The client must transfer the only handle to the VMO (which prevents the VMO being
    // resized without the receiver's knowledge), but it might still have the VMO mapped in and
    // continue to write data to it.  Code instrumentation runtimes use this to deliver large
    // binary trace results.
    // Request is heap-allocated.
    ResultOf::Publish Publish(::fidl::StringView data_sink, ::zx::vmo data);

    // The program runtime sends a string naming a `data_sink` and transfers the sole handle to
    // a VMO containing the `data` it wants published there.  The `data_sink` string identifies
    // a type of data, and the VMO's object name can specifically identify the data set in this
    // VMO.  The client must transfer the only handle to the VMO (which prevents the VMO being
    // resized without the receiver's knowledge), but it might still have the VMO mapped in and
    // continue to write data to it.  Code instrumentation runtimes use this to deliver large
    // binary trace results.
    // Caller provides the backing storage for FIDL message via request and response buffers.
    UnownedResultOf::Publish Publish(::fidl::BytePart _request_buffer, ::fidl::StringView data_sink, ::zx::vmo data);

    // The program runtime names a `config_name` referring to a debug configuration of some kind
    // and gets back a VMO to read configuration data from.  The sanitizer runtimes use this to
    // allow large options text to be stored in a file rather than passed directly in environment
    // strings.
    // Allocates 24 bytes of response buffer on the stack. Request is heap-allocated.
    ResultOf::LoadConfig LoadConfig(::fidl::StringView config_name);

    // The program runtime names a `config_name` referring to a debug configuration of some kind
    // and gets back a VMO to read configuration data from.  The sanitizer runtimes use this to
    // allow large options text to be stored in a file rather than passed directly in environment
    // strings.
    // Caller provides the backing storage for FIDL message via request and response buffers.
    UnownedResultOf::LoadConfig LoadConfig(::fidl::BytePart _request_buffer, ::fidl::StringView config_name, ::fidl::BytePart _response_buffer);

   private:
    ::zx::channel channel_;
  };

  // Methods to make a sync FIDL call directly on an unowned channel, avoiding setting up a client.
  class Call final {
    Call() = delete;
   public:

    // The program runtime sends a string naming a `data_sink` and transfers the sole handle to
    // a VMO containing the `data` it wants published there.  The `data_sink` string identifies
    // a type of data, and the VMO's object name can specifically identify the data set in this
    // VMO.  The client must transfer the only handle to the VMO (which prevents the VMO being
    // resized without the receiver's knowledge), but it might still have the VMO mapped in and
    // continue to write data to it.  Code instrumentation runtimes use this to deliver large
    // binary trace results.
    // Request is heap-allocated.
    static ResultOf::Publish Publish(zx::unowned_channel _client_end, ::fidl::StringView data_sink, ::zx::vmo data);

    // The program runtime sends a string naming a `data_sink` and transfers the sole handle to
    // a VMO containing the `data` it wants published there.  The `data_sink` string identifies
    // a type of data, and the VMO's object name can specifically identify the data set in this
    // VMO.  The client must transfer the only handle to the VMO (which prevents the VMO being
    // resized without the receiver's knowledge), but it might still have the VMO mapped in and
    // continue to write data to it.  Code instrumentation runtimes use this to deliver large
    // binary trace results.
    // Caller provides the backing storage for FIDL message via request and response buffers.
    static UnownedResultOf::Publish Publish(zx::unowned_channel _client_end, ::fidl::BytePart _request_buffer, ::fidl::StringView data_sink, ::zx::vmo data);

    // The program runtime names a `config_name` referring to a debug configuration of some kind
    // and gets back a VMO to read configuration data from.  The sanitizer runtimes use this to
    // allow large options text to be stored in a file rather than passed directly in environment
    // strings.
    // Allocates 24 bytes of response buffer on the stack. Request is heap-allocated.
    static ResultOf::LoadConfig LoadConfig(zx::unowned_channel _client_end, ::fidl::StringView config_name);

    // The program runtime names a `config_name` referring to a debug configuration of some kind
    // and gets back a VMO to read configuration data from.  The sanitizer runtimes use this to
    // allow large options text to be stored in a file rather than passed directly in environment
    // strings.
    // Caller provides the backing storage for FIDL message via request and response buffers.
    static UnownedResultOf::LoadConfig LoadConfig(zx::unowned_channel _client_end, ::fidl::BytePart _request_buffer, ::fidl::StringView config_name, ::fidl::BytePart _response_buffer);

  };

  // Messages are encoded and decoded in-place when these methods are used.
  // Additionally, requests must be already laid-out according to the FIDL wire-format.
  class InPlace final {
    InPlace() = delete;
   public:

    // The program runtime sends a string naming a `data_sink` and transfers the sole handle to
    // a VMO containing the `data` it wants published there.  The `data_sink` string identifies
    // a type of data, and the VMO's object name can specifically identify the data set in this
    // VMO.  The client must transfer the only handle to the VMO (which prevents the VMO being
    // resized without the receiver's knowledge), but it might still have the VMO mapped in and
    // continue to write data to it.  Code instrumentation runtimes use this to deliver large
    // binary trace results.
    static ::fidl::internal::StatusAndError Publish(zx::unowned_channel _client_end, ::fidl::DecodedMessage<PublishRequest> params);

    // The program runtime names a `config_name` referring to a debug configuration of some kind
    // and gets back a VMO to read configuration data from.  The sanitizer runtimes use this to
    // allow large options text to be stored in a file rather than passed directly in environment
    // strings.
    static ::fidl::DecodeResult<LoadConfigResponse> LoadConfig(zx::unowned_channel _client_end, ::fidl::DecodedMessage<LoadConfigRequest> params, ::fidl::BytePart response_buffer);

  };

  // Pure-virtual interface to be implemented by a server.
  class Interface {
   public:
    Interface() = default;
    virtual ~Interface() = default;
    using _Outer = DebugData;
    using _Base = ::fidl::CompleterBase;

    using PublishCompleter = ::fidl::Completer<>;

    virtual void Publish(::fidl::StringView data_sink, ::zx::vmo data, PublishCompleter::Sync _completer) = 0;

    class LoadConfigCompleterBase : public _Base {
     public:
      void Reply(::zx::vmo config);
      void Reply(::fidl::BytePart _buffer, ::zx::vmo config);
      void Reply(::fidl::DecodedMessage<LoadConfigResponse> params);

     protected:
      using ::fidl::CompleterBase::CompleterBase;
    };

    using LoadConfigCompleter = ::fidl::Completer<LoadConfigCompleterBase>;

    virtual void LoadConfig(::fidl::StringView config_name, LoadConfigCompleter::Sync _completer) = 0;

  };

  // Attempts to dispatch the incoming message to a handler function in the server implementation.
  // If there is no matching handler, it returns false, leaving the message and transaction intact.
  // In all other cases, it consumes the message and returns true.
  // It is possible to chain multiple TryDispatch functions in this manner.
  static bool TryDispatch(Interface* impl, fidl_msg_t* msg, ::fidl::Transaction* txn);

  // Dispatches the incoming message to one of the handlers functions in the interface.
  // If there is no matching handler, it closes all the handles in |msg| and closes the channel with
  // a |ZX_ERR_NOT_SUPPORTED| epitaph, before returning false. The message should then be discarded.
  static bool Dispatch(Interface* impl, fidl_msg_t* msg, ::fidl::Transaction* txn);

  // Same as |Dispatch|, but takes a |void*| instead of |Interface*|. Only used with |fidl::Bind|
  // to reduce template expansion.
  // Do not call this method manually. Use |Dispatch| instead.
  static bool TypeErasedDispatch(void* impl, fidl_msg_t* msg, ::fidl::Transaction* txn) {
    return Dispatch(static_cast<Interface*>(impl), msg, txn);
  }

};

// The maximum length, in bytes, of data sink or configuration name.
constexpr uint64_t MAX_NAME = 1024u;

}  // namespace debugdata
}  // namespace fuchsia
}  // namespace llcpp

namespace fidl {

template <>
struct IsFidlType<::llcpp::fuchsia::debugdata::DebugData::PublishRequest> : public std::true_type {};
template <>
struct IsFidlMessage<::llcpp::fuchsia::debugdata::DebugData::PublishRequest> : public std::true_type {};
static_assert(sizeof(::llcpp::fuchsia::debugdata::DebugData::PublishRequest)
    == ::llcpp::fuchsia::debugdata::DebugData::PublishRequest::PrimarySize);
static_assert(offsetof(::llcpp::fuchsia::debugdata::DebugData::PublishRequest, data_sink) == 16);
static_assert(offsetof(::llcpp::fuchsia::debugdata::DebugData::PublishRequest, data) == 32);

template <>
struct IsFidlType<::llcpp::fuchsia::debugdata::DebugData::LoadConfigRequest> : public std::true_type {};
template <>
struct IsFidlMessage<::llcpp::fuchsia::debugdata::DebugData::LoadConfigRequest> : public std::true_type {};
static_assert(sizeof(::llcpp::fuchsia::debugdata::DebugData::LoadConfigRequest)
    == ::llcpp::fuchsia::debugdata::DebugData::LoadConfigRequest::PrimarySize);
static_assert(offsetof(::llcpp::fuchsia::debugdata::DebugData::LoadConfigRequest, config_name) == 16);

template <>
struct IsFidlType<::llcpp::fuchsia::debugdata::DebugData::LoadConfigResponse> : public std::true_type {};
template <>
struct IsFidlMessage<::llcpp::fuchsia::debugdata::DebugData::LoadConfigResponse> : public std::true_type {};
static_assert(sizeof(::llcpp::fuchsia::debugdata::DebugData::LoadConfigResponse)
    == ::llcpp::fuchsia::debugdata::DebugData::LoadConfigResponse::PrimarySize);
static_assert(offsetof(::llcpp::fuchsia::debugdata::DebugData::LoadConfigResponse, config) == 16);

}  // namespace fidl
