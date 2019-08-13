// WARNING: This file is machine generated by fidlgen.

#include <fuchsia/exception/llcpp/fidl.h>
#include <memory>

namespace llcpp {

namespace fuchsia {
namespace exception {

namespace {

[[maybe_unused]]
constexpr uint64_t kHandler_OnException_GenOrdinal = 0x7ec50e5a00000000lu;
extern "C" const fidl_type_t fuchsia_exception_HandlerOnExceptionRequestTable;

}  // namespace
template <>
Handler::ResultOf::OnException_Impl<Handler::OnExceptionResponse>::OnException_Impl(zx::unowned_channel _client_end, ::zx::exception exception, ExceptionInfo info) {
  constexpr uint32_t _kWriteAllocSize = ::fidl::internal::ClampedMessageSize<OnExceptionRequest, ::fidl::MessageDirection::kSending>();
  ::fidl::internal::AlignedBuffer<_kWriteAllocSize> _write_bytes_inlined;
  auto& _write_bytes_array = _write_bytes_inlined;
  uint8_t* _write_bytes = _write_bytes_array.view().data();
  memset(_write_bytes, 0, OnExceptionRequest::PrimarySize);
  auto& _request = *reinterpret_cast<OnExceptionRequest*>(_write_bytes);
  _request.exception = std::move(exception);
  _request.info = std::move(info);
  ::fidl::BytePart _request_bytes(_write_bytes, _kWriteAllocSize, sizeof(OnExceptionRequest));
  ::fidl::DecodedMessage<OnExceptionRequest> _decoded_request(std::move(_request_bytes));
  Super::SetResult(
      Handler::InPlace::OnException(std::move(_client_end), std::move(_decoded_request), Super::response_buffer()));
}

Handler::ResultOf::OnException Handler::SyncClient::OnException(::zx::exception exception, ExceptionInfo info) {
  return ResultOf::OnException(zx::unowned_channel(this->channel_), std::move(exception), std::move(info));
}

Handler::ResultOf::OnException Handler::Call::OnException(zx::unowned_channel _client_end, ::zx::exception exception, ExceptionInfo info) {
  return ResultOf::OnException(std::move(_client_end), std::move(exception), std::move(info));
}

template <>
Handler::UnownedResultOf::OnException_Impl<Handler::OnExceptionResponse>::OnException_Impl(zx::unowned_channel _client_end, ::fidl::BytePart _request_buffer, ::zx::exception exception, ExceptionInfo info, ::fidl::BytePart _response_buffer) {
  if (_request_buffer.capacity() < OnExceptionRequest::PrimarySize) {
    Super::SetFailure(::fidl::DecodeResult<OnExceptionResponse>(ZX_ERR_BUFFER_TOO_SMALL, ::fidl::internal::kErrorRequestBufferTooSmall));
    return;
  }
  memset(_request_buffer.data(), 0, OnExceptionRequest::PrimarySize);
  auto& _request = *reinterpret_cast<OnExceptionRequest*>(_request_buffer.data());
  _request.exception = std::move(exception);
  _request.info = std::move(info);
  _request_buffer.set_actual(sizeof(OnExceptionRequest));
  ::fidl::DecodedMessage<OnExceptionRequest> _decoded_request(std::move(_request_buffer));
  Super::SetResult(
      Handler::InPlace::OnException(std::move(_client_end), std::move(_decoded_request), std::move(_response_buffer)));
}

Handler::UnownedResultOf::OnException Handler::SyncClient::OnException(::fidl::BytePart _request_buffer, ::zx::exception exception, ExceptionInfo info, ::fidl::BytePart _response_buffer) {
  return UnownedResultOf::OnException(zx::unowned_channel(this->channel_), std::move(_request_buffer), std::move(exception), std::move(info), std::move(_response_buffer));
}

Handler::UnownedResultOf::OnException Handler::Call::OnException(zx::unowned_channel _client_end, ::fidl::BytePart _request_buffer, ::zx::exception exception, ExceptionInfo info, ::fidl::BytePart _response_buffer) {
  return UnownedResultOf::OnException(std::move(_client_end), std::move(_request_buffer), std::move(exception), std::move(info), std::move(_response_buffer));
}

::fidl::DecodeResult<Handler::OnExceptionResponse> Handler::InPlace::OnException(zx::unowned_channel _client_end, ::fidl::DecodedMessage<OnExceptionRequest> params, ::fidl::BytePart response_buffer) {
  params.message()->_hdr = {};
  params.message()->_hdr.ordinal = kHandler_OnException_GenOrdinal;
  auto _encode_request_result = ::fidl::Encode(std::move(params));
  if (_encode_request_result.status != ZX_OK) {
    return ::fidl::DecodeResult<Handler::OnExceptionResponse>::FromFailure(
        std::move(_encode_request_result));
  }
  auto _call_result = ::fidl::Call<OnExceptionRequest, OnExceptionResponse>(
    std::move(_client_end), std::move(_encode_request_result.message), std::move(response_buffer));
  if (_call_result.status != ZX_OK) {
    return ::fidl::DecodeResult<Handler::OnExceptionResponse>::FromFailure(
        std::move(_call_result));
  }
  return ::fidl::Decode(std::move(_call_result.message));
}


bool Handler::TryDispatch(Interface* impl, fidl_msg_t* msg, ::fidl::Transaction* txn) {
  if (msg->num_bytes < sizeof(fidl_message_header_t)) {
    zx_handle_close_many(msg->handles, msg->num_handles);
    txn->Close(ZX_ERR_INVALID_ARGS);
    return true;
  }
  fidl_message_header_t* hdr = reinterpret_cast<fidl_message_header_t*>(msg->bytes);
  switch (hdr->ordinal) {
    case kHandler_OnException_GenOrdinal:
    {
      auto result = ::fidl::DecodeAs<OnExceptionRequest>(msg);
      if (result.status != ZX_OK) {
        txn->Close(ZX_ERR_INVALID_ARGS);
        return true;
      }
      auto message = result.message.message();
      impl->OnException(std::move(message->exception), std::move(message->info),
        Interface::OnExceptionCompleter::Sync(txn));
      return true;
    }
    default: {
      return false;
    }
  }
}

bool Handler::Dispatch(Interface* impl, fidl_msg_t* msg, ::fidl::Transaction* txn) {
  bool found = TryDispatch(impl, msg, txn);
  if (!found) {
    zx_handle_close_many(msg->handles, msg->num_handles);
    txn->Close(ZX_ERR_NOT_SUPPORTED);
  }
  return found;
}


void Handler::Interface::OnExceptionCompleterBase::Reply() {
  constexpr uint32_t _kWriteAllocSize = ::fidl::internal::ClampedMessageSize<OnExceptionResponse, ::fidl::MessageDirection::kSending>();
  FIDL_ALIGNDECL uint8_t _write_bytes[_kWriteAllocSize] = {};
  auto& _response = *reinterpret_cast<OnExceptionResponse*>(_write_bytes);
  _response._hdr.ordinal = kHandler_OnException_GenOrdinal;
  ::fidl::BytePart _response_bytes(_write_bytes, _kWriteAllocSize, sizeof(OnExceptionResponse));
  CompleterBase::SendReply(::fidl::DecodedMessage<OnExceptionResponse>(std::move(_response_bytes)));
}


}  // namespace exception
}  // namespace fuchsia
}  // namespace llcpp
