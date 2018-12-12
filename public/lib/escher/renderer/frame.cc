// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lib/escher/renderer/frame.h"

#ifdef OS_FUCHSIA
#include <zircon/syscalls.h>
#endif

#include "lib/escher/escher.h"
#include "lib/escher/impl/frame_manager.h"
#include "lib/escher/util/trace_macros.h"
#include "lib/escher/vk/command_buffer.h"
#include "lib/fxl/macros.h"

namespace escher {

namespace {

// Generates a unique frame count for each created frame.
static uint64_t NextFrameNumber() {
  static std::atomic<uint64_t> counter(0);
  return ++counter;
}

}  // anonymous namespace

const ResourceTypeInfo Frame::kTypeInfo("Frame", ResourceType::kResource,
                                        ResourceType::kFrame);

Frame::Frame(impl::FrameManager* manager,
             escher::CommandBuffer::Type requested_type,
             BlockAllocator allocator,
             impl::UniformBufferPoolWeakPtr uniform_buffer_pool,
             uint64_t frame_number, const char* trace_literal,
             const char* gpu_vthread_literal, uint64_t gpu_vthread_id,
             bool enable_gpu_logging)
    : Resource(manager),
      frame_number_(frame_number),
      escher_frame_number_(NextFrameNumber()),
      trace_literal_(trace_literal),
      gpu_vthread_literal_(gpu_vthread_literal),
      gpu_vthread_id_(gpu_vthread_id),
      enable_gpu_logging_(enable_gpu_logging),
      queue_(escher()->device()->vk_main_queue()),
      command_buffer_type_(requested_type),
      block_allocator_(std::move(allocator)),
      uniform_block_allocator_(std::move(uniform_buffer_pool)),
      profiler_(escher()->supports_timer_queries()
                    ? fxl::MakeRefCounted<TimestampProfiler>(
                          escher()->vk_device(), escher()->timestamp_period())
                    : TimestampProfilerPtr()) {
  FXL_DCHECK(queue_);
}

Frame::~Frame() {
  // Why can we confidently state that if this DCHECK fires, it is because
  // EndFrame() was not called?  Because when EndFrame() submits the command
  // buffer, it registers a closure that will only be called once the frame has
  // finished rendering, and because this closure both:
  // - refs the Frame, keeping it alive until the closure completes
  // - sets the state to kReadyToBegin.
  FXL_DCHECK(state_ == State::kReadyToBegin)
      << "EndFrame() was not called - state_: " << static_cast<int>(state_);
}

impl::CommandBuffer* Frame::command_buffer() const {
  FXL_DCHECK(command_buffer_) << "Cannot access command buffer.";
  return command_buffer_->impl();
}

vk::CommandBuffer Frame::vk_command_buffer() const {
  FXL_DCHECK(command_buffer_) << "Cannot access command buffer.";
  return command_buffer_->vk();
}

void Frame::BeginFrame() {
  TRACE_DURATION("gfx", "escher::Frame::BeginFrame", "frame_number",
                 frame_number_, "escher_frame_number", escher_frame_number_);
  FXL_DCHECK(state_ == State::kReadyToBegin);
  static_cast<impl::FrameManager*>(owner())->IncrementNumOutstandingFrames();
  IssueCommandBuffer();
  AddTimestamp("start of frame");
}

void Frame::IssueCommandBuffer() {
  FXL_DCHECK(!command_buffer_);
  state_ = State::kInProgress;

  command_buffer_ = CommandBuffer::NewForType(escher(), command_buffer_type_);
  command_buffer_sequence_number_ = command_buffer_->impl()->sequence_number();
}

void Frame::SubmitPartialFrame(const SemaphorePtr& frame_done) {
  FXL_DCHECK(command_buffer_);

  ++submission_count_;
  TRACE_DURATION("gfx", "escher::Frame::SubmitPartialFrame", "frame_number",
                 frame_number_, "escher_frame_number", escher_frame_number_,
                 "submission_index", submission_count_);
  FXL_DCHECK(state_ == State::kInProgress);

  command_buffer_->impl()->AddSignalSemaphore(frame_done);
  command_buffer_->impl()->Submit(queue_, nullptr);

  // Command buffer has submitted, clear the current command buffer data to
  // recycle it.
  command_buffer_ = nullptr;
  command_buffer_sequence_number_ = 0;
  // Issue a new command buffer this frame can be used for more submits.
  IssueCommandBuffer();
}

void Frame::EndFrame(const SemaphorePtr& frame_done,
                     FrameRetiredCallback frame_retired_callback) {
  FXL_DCHECK(command_buffer_);

  ++submission_count_;
  TRACE_DURATION("gfx", "escher::Frame::EndFrame", "frame_number",
                 frame_number_, "escher_frame_number", escher_frame_number_,
                 "submission_index", submission_count_);
  FXL_DCHECK(state_ == State::kInProgress);
  state_ = State::kFinishing;

  AddTimestamp("end of frame");

  command_buffer_->impl()->AddSignalSemaphore(frame_done);

  // Submit the final command buffer and register a callback to perform a
  // variety of bookkeeping and cleanup tasks.
  //
  // NOTE: this closure refs this Frame via a FramePtr, guaranteeing that it
  // will not be destroyed until the frame is finished rendering.
  command_buffer_->impl()->Submit(
      queue_, [client_callback{std::move(frame_retired_callback)},
               profiler{std::move(profiler_)}, frame_number = frame_number_,
               escher_frame_number = escher_frame_number_,
               trace_literal = trace_literal_,
               gpu_vthread_literal = gpu_vthread_literal_,
               gpu_vthread_id = gpu_vthread_id_,
               enable_gpu_logging = enable_gpu_logging_,
               this_frame = FramePtr(this)]() {
        // Run the client-specified callback.
        if (client_callback) {
          client_callback();
        }

        // If GPU profiling was enabled, read/interpret the query results and:
        // - add them to the system trace (if active).
        // - if specified, log a summary.
        if (profiler) {
          auto timestamps = profiler->GetQueryResults();
          auto trace_events = profiler->ProcessTraceEvents(timestamps);

          profiler->TraceGpuQueryResults(trace_events, frame_number,
                                         escher_frame_number, trace_literal,
                                         gpu_vthread_literal, gpu_vthread_id);

          if (enable_gpu_logging) {
            profiler->LogGpuQueryResults(escher_frame_number, timestamps);
          }
        }

        // Notify the FrameManager that this frame is completely finished
        // rendering.
        static_cast<impl::FrameManager*>(this_frame->owner())
            ->DecrementNumOutstandingFrames();

        // |this_frame| refs the frame until rendering is finished, and
        // therefore keeps alive everything in |keep_alive_|.
        this_frame->keep_alive_.clear();

        // The frame is now ready for reuse or destruction.
        this_frame->state_ = State::kReadyToBegin;
      });

  command_buffer_ = nullptr;
  command_buffer_sequence_number_ = 0;

  // Keep per-frame uniform buffers alive until frame is finished rendering.
  for (auto& buf : uniform_block_allocator_.TakeBuffers()) {
    // TODO(ES-103): reconsider this keep-alive scheme.
    // TODO(ES-106): test that blocks make it back to the pool but only after
    // the frame is finished rendering.
    KeepAlive(std::move(buf));
  }

  // Immediately release per-frame CPU memory; it is no longer needed now that
  // all work has been submitted to the GPU.
  block_allocator_.Reset();

  escher()->Cleanup();
}

void Frame::AddTimestamp(const char* name, vk::PipelineStageFlagBits stages) {
  if (profiler_)
    profiler_->AddTimestamp(command_buffer_->impl(), stages, name);
}

void Frame::KeepAlive(ResourcePtr resource) {
  keep_alive_.push_back(std::move(resource));
}

CommandBufferPtr Frame::TakeCommandBuffer() {
  return std::move(command_buffer_);
}

void Frame::PutCommandBuffer(CommandBufferPtr command_buffer) {
  FXL_DCHECK(!command_buffer_ && command_buffer);
  FXL_DCHECK(command_buffer_sequence_number_ ==
             command_buffer->impl()->sequence_number());

  command_buffer_ = std::move(command_buffer);
}

GpuAllocator* Frame::gpu_allocator() { return escher()->gpu_allocator(); }

}  // namespace escher
