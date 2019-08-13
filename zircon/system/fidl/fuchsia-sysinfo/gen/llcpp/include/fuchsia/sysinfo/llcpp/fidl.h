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
#include <lib/zx/job.h>
#include <lib/zx/resource.h>
#include <zircon/fidl.h>

namespace llcpp {

namespace fuchsia {
namespace sysinfo {

class Device;
enum class InterruptControllerType : uint32_t {
  UNKNOWN = 0u,
  APIC = 1u,
  GIC_V2 = 2u,
  GIC_V3 = 3u,
};


struct InterruptControllerInfo;

extern "C" const fidl_type_t fuchsia_sysinfo_DeviceGetRootJobResponseTable;
extern "C" const fidl_type_t fuchsia_sysinfo_DeviceGetHypervisorResourceResponseTable;
extern "C" const fidl_type_t fuchsia_sysinfo_DeviceGetBoardNameResponseTable;
extern "C" const fidl_type_t fuchsia_sysinfo_DeviceGetInterruptControllerInfoResponseTable;

class Device final {
  Device() = delete;
 public:

  struct GetRootJobResponse final {
    FIDL_ALIGNDECL
    fidl_message_header_t _hdr;
    int32_t status;
    ::zx::job job;

    static constexpr const fidl_type_t* Type = &fuchsia_sysinfo_DeviceGetRootJobResponseTable;
    static constexpr uint32_t MaxNumHandles = 1;
    static constexpr uint32_t PrimarySize = 24;
    static constexpr uint32_t MaxOutOfLine = 0;
    static constexpr bool HasFlexibleEnvelope = false;
    static constexpr ::fidl::internal::TransactionalMessageKind MessageKind =
        ::fidl::internal::TransactionalMessageKind::kResponse;
  };
  using GetRootJobRequest = ::fidl::AnyZeroArgMessage;

  struct GetHypervisorResourceResponse final {
    FIDL_ALIGNDECL
    fidl_message_header_t _hdr;
    int32_t status;
    ::zx::resource resource;

    static constexpr const fidl_type_t* Type = &fuchsia_sysinfo_DeviceGetHypervisorResourceResponseTable;
    static constexpr uint32_t MaxNumHandles = 1;
    static constexpr uint32_t PrimarySize = 24;
    static constexpr uint32_t MaxOutOfLine = 0;
    static constexpr bool HasFlexibleEnvelope = false;
    static constexpr ::fidl::internal::TransactionalMessageKind MessageKind =
        ::fidl::internal::TransactionalMessageKind::kResponse;
  };
  using GetHypervisorResourceRequest = ::fidl::AnyZeroArgMessage;

  struct GetBoardNameResponse final {
    FIDL_ALIGNDECL
    fidl_message_header_t _hdr;
    int32_t status;
    ::fidl::StringView name;

    static constexpr const fidl_type_t* Type = &fuchsia_sysinfo_DeviceGetBoardNameResponseTable;
    static constexpr uint32_t MaxNumHandles = 0;
    static constexpr uint32_t PrimarySize = 40;
    static constexpr uint32_t MaxOutOfLine = 32;
    static constexpr bool HasFlexibleEnvelope = false;
    static constexpr ::fidl::internal::TransactionalMessageKind MessageKind =
        ::fidl::internal::TransactionalMessageKind::kResponse;
  };
  using GetBoardNameRequest = ::fidl::AnyZeroArgMessage;

  struct GetInterruptControllerInfoResponse final {
    FIDL_ALIGNDECL
    fidl_message_header_t _hdr;
    int32_t status;
    InterruptControllerInfo* info;

    static constexpr const fidl_type_t* Type = &fuchsia_sysinfo_DeviceGetInterruptControllerInfoResponseTable;
    static constexpr uint32_t MaxNumHandles = 0;
    static constexpr uint32_t PrimarySize = 32;
    static constexpr uint32_t MaxOutOfLine = 8;
    static constexpr bool HasFlexibleEnvelope = false;
    static constexpr ::fidl::internal::TransactionalMessageKind MessageKind =
        ::fidl::internal::TransactionalMessageKind::kResponse;
  };
  using GetInterruptControllerInfoRequest = ::fidl::AnyZeroArgMessage;


  // Collection of return types of FIDL calls in this interface.
  class ResultOf final {
    ResultOf() = delete;
   private:
    template <typename ResponseType>
    class GetRootJob_Impl final : private ::fidl::internal::OwnedSyncCallBase<ResponseType> {
      using Super = ::fidl::internal::OwnedSyncCallBase<ResponseType>;
     public:
      GetRootJob_Impl(zx::unowned_channel _client_end);
      ~GetRootJob_Impl() = default;
      GetRootJob_Impl(GetRootJob_Impl&& other) = default;
      GetRootJob_Impl& operator=(GetRootJob_Impl&& other) = default;
      using Super::status;
      using Super::error;
      using Super::ok;
      using Super::Unwrap;
      using Super::value;
      using Super::operator->;
      using Super::operator*;
    };
    template <typename ResponseType>
    class GetHypervisorResource_Impl final : private ::fidl::internal::OwnedSyncCallBase<ResponseType> {
      using Super = ::fidl::internal::OwnedSyncCallBase<ResponseType>;
     public:
      GetHypervisorResource_Impl(zx::unowned_channel _client_end);
      ~GetHypervisorResource_Impl() = default;
      GetHypervisorResource_Impl(GetHypervisorResource_Impl&& other) = default;
      GetHypervisorResource_Impl& operator=(GetHypervisorResource_Impl&& other) = default;
      using Super::status;
      using Super::error;
      using Super::ok;
      using Super::Unwrap;
      using Super::value;
      using Super::operator->;
      using Super::operator*;
    };
    template <typename ResponseType>
    class GetBoardName_Impl final : private ::fidl::internal::OwnedSyncCallBase<ResponseType> {
      using Super = ::fidl::internal::OwnedSyncCallBase<ResponseType>;
     public:
      GetBoardName_Impl(zx::unowned_channel _client_end);
      ~GetBoardName_Impl() = default;
      GetBoardName_Impl(GetBoardName_Impl&& other) = default;
      GetBoardName_Impl& operator=(GetBoardName_Impl&& other) = default;
      using Super::status;
      using Super::error;
      using Super::ok;
      using Super::Unwrap;
      using Super::value;
      using Super::operator->;
      using Super::operator*;
    };
    template <typename ResponseType>
    class GetInterruptControllerInfo_Impl final : private ::fidl::internal::OwnedSyncCallBase<ResponseType> {
      using Super = ::fidl::internal::OwnedSyncCallBase<ResponseType>;
     public:
      GetInterruptControllerInfo_Impl(zx::unowned_channel _client_end);
      ~GetInterruptControllerInfo_Impl() = default;
      GetInterruptControllerInfo_Impl(GetInterruptControllerInfo_Impl&& other) = default;
      GetInterruptControllerInfo_Impl& operator=(GetInterruptControllerInfo_Impl&& other) = default;
      using Super::status;
      using Super::error;
      using Super::ok;
      using Super::Unwrap;
      using Super::value;
      using Super::operator->;
      using Super::operator*;
    };

   public:
    using GetRootJob = GetRootJob_Impl<GetRootJobResponse>;
    using GetHypervisorResource = GetHypervisorResource_Impl<GetHypervisorResourceResponse>;
    using GetBoardName = GetBoardName_Impl<GetBoardNameResponse>;
    using GetInterruptControllerInfo = GetInterruptControllerInfo_Impl<GetInterruptControllerInfoResponse>;
  };

  // Collection of return types of FIDL calls in this interface,
  // when the caller-allocate flavor or in-place call is used.
  class UnownedResultOf final {
    UnownedResultOf() = delete;
   private:
    template <typename ResponseType>
    class GetRootJob_Impl final : private ::fidl::internal::UnownedSyncCallBase<ResponseType> {
      using Super = ::fidl::internal::UnownedSyncCallBase<ResponseType>;
     public:
      GetRootJob_Impl(zx::unowned_channel _client_end, ::fidl::BytePart _response_buffer);
      ~GetRootJob_Impl() = default;
      GetRootJob_Impl(GetRootJob_Impl&& other) = default;
      GetRootJob_Impl& operator=(GetRootJob_Impl&& other) = default;
      using Super::status;
      using Super::error;
      using Super::ok;
      using Super::Unwrap;
      using Super::value;
      using Super::operator->;
      using Super::operator*;
    };
    template <typename ResponseType>
    class GetHypervisorResource_Impl final : private ::fidl::internal::UnownedSyncCallBase<ResponseType> {
      using Super = ::fidl::internal::UnownedSyncCallBase<ResponseType>;
     public:
      GetHypervisorResource_Impl(zx::unowned_channel _client_end, ::fidl::BytePart _response_buffer);
      ~GetHypervisorResource_Impl() = default;
      GetHypervisorResource_Impl(GetHypervisorResource_Impl&& other) = default;
      GetHypervisorResource_Impl& operator=(GetHypervisorResource_Impl&& other) = default;
      using Super::status;
      using Super::error;
      using Super::ok;
      using Super::Unwrap;
      using Super::value;
      using Super::operator->;
      using Super::operator*;
    };
    template <typename ResponseType>
    class GetBoardName_Impl final : private ::fidl::internal::UnownedSyncCallBase<ResponseType> {
      using Super = ::fidl::internal::UnownedSyncCallBase<ResponseType>;
     public:
      GetBoardName_Impl(zx::unowned_channel _client_end, ::fidl::BytePart _response_buffer);
      ~GetBoardName_Impl() = default;
      GetBoardName_Impl(GetBoardName_Impl&& other) = default;
      GetBoardName_Impl& operator=(GetBoardName_Impl&& other) = default;
      using Super::status;
      using Super::error;
      using Super::ok;
      using Super::Unwrap;
      using Super::value;
      using Super::operator->;
      using Super::operator*;
    };
    template <typename ResponseType>
    class GetInterruptControllerInfo_Impl final : private ::fidl::internal::UnownedSyncCallBase<ResponseType> {
      using Super = ::fidl::internal::UnownedSyncCallBase<ResponseType>;
     public:
      GetInterruptControllerInfo_Impl(zx::unowned_channel _client_end, ::fidl::BytePart _response_buffer);
      ~GetInterruptControllerInfo_Impl() = default;
      GetInterruptControllerInfo_Impl(GetInterruptControllerInfo_Impl&& other) = default;
      GetInterruptControllerInfo_Impl& operator=(GetInterruptControllerInfo_Impl&& other) = default;
      using Super::status;
      using Super::error;
      using Super::ok;
      using Super::Unwrap;
      using Super::value;
      using Super::operator->;
      using Super::operator*;
    };

   public:
    using GetRootJob = GetRootJob_Impl<GetRootJobResponse>;
    using GetHypervisorResource = GetHypervisorResource_Impl<GetHypervisorResourceResponse>;
    using GetBoardName = GetBoardName_Impl<GetBoardNameResponse>;
    using GetInterruptControllerInfo = GetInterruptControllerInfo_Impl<GetInterruptControllerInfoResponse>;
  };

  class SyncClient final {
   public:
    explicit SyncClient(::zx::channel channel) : channel_(std::move(channel)) {}
    ~SyncClient() = default;
    SyncClient(SyncClient&&) = default;
    SyncClient& operator=(SyncClient&&) = default;

    const ::zx::channel& channel() const { return channel_; }

    ::zx::channel* mutable_channel() { return &channel_; }

    // Allocates 40 bytes of message buffer on the stack. No heap allocation necessary.
    ResultOf::GetRootJob GetRootJob();

    // Caller provides the backing storage for FIDL message via request and response buffers.
    UnownedResultOf::GetRootJob GetRootJob(::fidl::BytePart _response_buffer);

    // Allocates 40 bytes of message buffer on the stack. No heap allocation necessary.
    ResultOf::GetHypervisorResource GetHypervisorResource();

    // Caller provides the backing storage for FIDL message via request and response buffers.
    UnownedResultOf::GetHypervisorResource GetHypervisorResource(::fidl::BytePart _response_buffer);

    // Allocates 88 bytes of message buffer on the stack. No heap allocation necessary.
    ResultOf::GetBoardName GetBoardName();

    // Caller provides the backing storage for FIDL message via request and response buffers.
    UnownedResultOf::GetBoardName GetBoardName(::fidl::BytePart _response_buffer);

    // Allocates 56 bytes of message buffer on the stack. No heap allocation necessary.
    ResultOf::GetInterruptControllerInfo GetInterruptControllerInfo();

    // Caller provides the backing storage for FIDL message via request and response buffers.
    UnownedResultOf::GetInterruptControllerInfo GetInterruptControllerInfo(::fidl::BytePart _response_buffer);

   private:
    ::zx::channel channel_;
  };

  // Methods to make a sync FIDL call directly on an unowned channel, avoiding setting up a client.
  class Call final {
    Call() = delete;
   public:

    // Allocates 40 bytes of message buffer on the stack. No heap allocation necessary.
    static ResultOf::GetRootJob GetRootJob(zx::unowned_channel _client_end);

    // Caller provides the backing storage for FIDL message via request and response buffers.
    static UnownedResultOf::GetRootJob GetRootJob(zx::unowned_channel _client_end, ::fidl::BytePart _response_buffer);

    // Allocates 40 bytes of message buffer on the stack. No heap allocation necessary.
    static ResultOf::GetHypervisorResource GetHypervisorResource(zx::unowned_channel _client_end);

    // Caller provides the backing storage for FIDL message via request and response buffers.
    static UnownedResultOf::GetHypervisorResource GetHypervisorResource(zx::unowned_channel _client_end, ::fidl::BytePart _response_buffer);

    // Allocates 88 bytes of message buffer on the stack. No heap allocation necessary.
    static ResultOf::GetBoardName GetBoardName(zx::unowned_channel _client_end);

    // Caller provides the backing storage for FIDL message via request and response buffers.
    static UnownedResultOf::GetBoardName GetBoardName(zx::unowned_channel _client_end, ::fidl::BytePart _response_buffer);

    // Allocates 56 bytes of message buffer on the stack. No heap allocation necessary.
    static ResultOf::GetInterruptControllerInfo GetInterruptControllerInfo(zx::unowned_channel _client_end);

    // Caller provides the backing storage for FIDL message via request and response buffers.
    static UnownedResultOf::GetInterruptControllerInfo GetInterruptControllerInfo(zx::unowned_channel _client_end, ::fidl::BytePart _response_buffer);

  };

  // Messages are encoded and decoded in-place when these methods are used.
  // Additionally, requests must be already laid-out according to the FIDL wire-format.
  class InPlace final {
    InPlace() = delete;
   public:

    static ::fidl::DecodeResult<GetRootJobResponse> GetRootJob(zx::unowned_channel _client_end, ::fidl::BytePart response_buffer);

    static ::fidl::DecodeResult<GetHypervisorResourceResponse> GetHypervisorResource(zx::unowned_channel _client_end, ::fidl::BytePart response_buffer);

    static ::fidl::DecodeResult<GetBoardNameResponse> GetBoardName(zx::unowned_channel _client_end, ::fidl::BytePart response_buffer);

    static ::fidl::DecodeResult<GetInterruptControllerInfoResponse> GetInterruptControllerInfo(zx::unowned_channel _client_end, ::fidl::BytePart response_buffer);

  };

  // Pure-virtual interface to be implemented by a server.
  class Interface {
   public:
    Interface() = default;
    virtual ~Interface() = default;
    using _Outer = Device;
    using _Base = ::fidl::CompleterBase;

    class GetRootJobCompleterBase : public _Base {
     public:
      void Reply(int32_t status, ::zx::job job);
      void Reply(::fidl::BytePart _buffer, int32_t status, ::zx::job job);
      void Reply(::fidl::DecodedMessage<GetRootJobResponse> params);

     protected:
      using ::fidl::CompleterBase::CompleterBase;
    };

    using GetRootJobCompleter = ::fidl::Completer<GetRootJobCompleterBase>;

    virtual void GetRootJob(GetRootJobCompleter::Sync _completer) = 0;

    class GetHypervisorResourceCompleterBase : public _Base {
     public:
      void Reply(int32_t status, ::zx::resource resource);
      void Reply(::fidl::BytePart _buffer, int32_t status, ::zx::resource resource);
      void Reply(::fidl::DecodedMessage<GetHypervisorResourceResponse> params);

     protected:
      using ::fidl::CompleterBase::CompleterBase;
    };

    using GetHypervisorResourceCompleter = ::fidl::Completer<GetHypervisorResourceCompleterBase>;

    virtual void GetHypervisorResource(GetHypervisorResourceCompleter::Sync _completer) = 0;

    class GetBoardNameCompleterBase : public _Base {
     public:
      void Reply(int32_t status, ::fidl::StringView name);
      void Reply(::fidl::BytePart _buffer, int32_t status, ::fidl::StringView name);
      void Reply(::fidl::DecodedMessage<GetBoardNameResponse> params);

     protected:
      using ::fidl::CompleterBase::CompleterBase;
    };

    using GetBoardNameCompleter = ::fidl::Completer<GetBoardNameCompleterBase>;

    virtual void GetBoardName(GetBoardNameCompleter::Sync _completer) = 0;

    class GetInterruptControllerInfoCompleterBase : public _Base {
     public:
      void Reply(int32_t status, InterruptControllerInfo* info);
      void Reply(::fidl::BytePart _buffer, int32_t status, InterruptControllerInfo* info);
      void Reply(::fidl::DecodedMessage<GetInterruptControllerInfoResponse> params);

     protected:
      using ::fidl::CompleterBase::CompleterBase;
    };

    using GetInterruptControllerInfoCompleter = ::fidl::Completer<GetInterruptControllerInfoCompleterBase>;

    virtual void GetInterruptControllerInfo(GetInterruptControllerInfoCompleter::Sync _completer) = 0;

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

constexpr uint8_t SYSINFO_BOARD_NAME_LEN = 32u;



struct InterruptControllerInfo {
  static constexpr const fidl_type_t* Type = nullptr;
  static constexpr uint32_t MaxNumHandles = 0;
  static constexpr uint32_t PrimarySize = 4;
  [[maybe_unused]]
  static constexpr uint32_t MaxOutOfLine = 0;

  InterruptControllerType type = {};
};

}  // namespace sysinfo
}  // namespace fuchsia
}  // namespace llcpp

namespace fidl {

template <>
struct IsFidlType<::llcpp::fuchsia::sysinfo::Device::GetRootJobResponse> : public std::true_type {};
template <>
struct IsFidlMessage<::llcpp::fuchsia::sysinfo::Device::GetRootJobResponse> : public std::true_type {};
static_assert(sizeof(::llcpp::fuchsia::sysinfo::Device::GetRootJobResponse)
    == ::llcpp::fuchsia::sysinfo::Device::GetRootJobResponse::PrimarySize);
static_assert(offsetof(::llcpp::fuchsia::sysinfo::Device::GetRootJobResponse, status) == 16);
static_assert(offsetof(::llcpp::fuchsia::sysinfo::Device::GetRootJobResponse, job) == 20);

template <>
struct IsFidlType<::llcpp::fuchsia::sysinfo::Device::GetHypervisorResourceResponse> : public std::true_type {};
template <>
struct IsFidlMessage<::llcpp::fuchsia::sysinfo::Device::GetHypervisorResourceResponse> : public std::true_type {};
static_assert(sizeof(::llcpp::fuchsia::sysinfo::Device::GetHypervisorResourceResponse)
    == ::llcpp::fuchsia::sysinfo::Device::GetHypervisorResourceResponse::PrimarySize);
static_assert(offsetof(::llcpp::fuchsia::sysinfo::Device::GetHypervisorResourceResponse, status) == 16);
static_assert(offsetof(::llcpp::fuchsia::sysinfo::Device::GetHypervisorResourceResponse, resource) == 20);

template <>
struct IsFidlType<::llcpp::fuchsia::sysinfo::Device::GetBoardNameResponse> : public std::true_type {};
template <>
struct IsFidlMessage<::llcpp::fuchsia::sysinfo::Device::GetBoardNameResponse> : public std::true_type {};
static_assert(sizeof(::llcpp::fuchsia::sysinfo::Device::GetBoardNameResponse)
    == ::llcpp::fuchsia::sysinfo::Device::GetBoardNameResponse::PrimarySize);
static_assert(offsetof(::llcpp::fuchsia::sysinfo::Device::GetBoardNameResponse, status) == 16);
static_assert(offsetof(::llcpp::fuchsia::sysinfo::Device::GetBoardNameResponse, name) == 24);

template <>
struct IsFidlType<::llcpp::fuchsia::sysinfo::Device::GetInterruptControllerInfoResponse> : public std::true_type {};
template <>
struct IsFidlMessage<::llcpp::fuchsia::sysinfo::Device::GetInterruptControllerInfoResponse> : public std::true_type {};
static_assert(sizeof(::llcpp::fuchsia::sysinfo::Device::GetInterruptControllerInfoResponse)
    == ::llcpp::fuchsia::sysinfo::Device::GetInterruptControllerInfoResponse::PrimarySize);
static_assert(offsetof(::llcpp::fuchsia::sysinfo::Device::GetInterruptControllerInfoResponse, status) == 16);
static_assert(offsetof(::llcpp::fuchsia::sysinfo::Device::GetInterruptControllerInfoResponse, info) == 24);

template <>
struct IsFidlType<::llcpp::fuchsia::sysinfo::InterruptControllerInfo> : public std::true_type {};
static_assert(std::is_standard_layout_v<::llcpp::fuchsia::sysinfo::InterruptControllerInfo>);
static_assert(offsetof(::llcpp::fuchsia::sysinfo::InterruptControllerInfo, type) == 0);
static_assert(sizeof(::llcpp::fuchsia::sysinfo::InterruptControllerInfo) == ::llcpp::fuchsia::sysinfo::InterruptControllerInfo::PrimarySize);

}  // namespace fidl
