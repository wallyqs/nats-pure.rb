# frozen_string_literal: true

# Copyright 2021 The NATS Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require_relative "consume"
require_relative "errors"

module NATS
  class JetStream
    # Consumer is a handle to a JetStream pull consumer, like the Consumer
    # of the nats.go jetstream package, which js.consumer and the consumer
    # methods of a {Stream} return. It reads the messages of the consumer
    # through a {PullSubscription} bound to it, which it makes when first
    # used and keeps, so that what a fetch leaves behind goes to the next
    # one. It keeps the info of the consumer from when it was got, or last
    # refreshed with info, as cached_info.
    #
    # @example Read the messages of a consumer.
    #
    #   consumer = js.consumer("ORDERS", "processor")
    #   consumer.fetch(10).each(&:ack)
    #   msgs = consumer.messages
    #   msgs.next(timeout: 5).ack
    #
    # @!visibility public
    class Consumer
      # @return [String] Name of the stream of the consumer.
      attr_reader :stream

      # @return [String] Name of the consumer.
      attr_reader :name

      # @!visibility private
      def initialize(js, stream, info)
        @js = js
        @stream = stream
        @name = info.name
        @info = info
        @lock = Mutex.new
        @psub = nil
      end

      # info gets the current info of the consumer, and caches it.
      # @param params [Hash] Options to customize API request.
      # @option params [Float] :timeout Time to wait for response.
      # @return [JetStream::API::ConsumerInfo]
      def info(params = {})
        @info = @js.consumer_info(@stream, @name, params)
      end

      # cached_info is the info of the consumer from when the handle was
      # made, or info was last called, without asking the server.
      # @return [JetStream::API::ConsumerInfo]
      def cached_info
        @info
      end

      # fetch pulls a batch of messages, like {PullSubscription#fetch}, with
      # the same options.
      # @param batch [Integer] Number of messages to pull.
      # @param params [Hash] Options of {PullSubscription#fetch}.
      # @yieldparam msg [NATS::Msg] Each message, as it comes.
      # @return [Array<NATS::Msg>]
      def fetch(batch = 1, params = {}, &block)
        psub.fetch(batch, params, &block)
      end

      # fetch_bytes pulls messages of up to max_bytes in all, as the server
      # counts them, like FetchBytes of nats.go.
      # @param max_bytes [Integer] Most bytes to take.
      # @param params [Hash] Options of {PullSubscription#fetch}.
      # @yieldparam msg [NATS::Msg] Each message, as it comes.
      # @return [Array<NATS::Msg>]
      def fetch_bytes(max_bytes, params = {}, &block)
        psub.fetch(MessagesContext::BYTES_ONLY_BATCH, params.merge(max_bytes: max_bytes), &block)
      end

      # fetch_no_wait pulls a batch of messages, taking what the server
      # delivers at once, like FetchNoWait of nats.go.
      # @param batch [Integer] Most messages to take.
      # @param params [Hash] Options of {PullSubscription#fetch}.
      # @yieldparam msg [NATS::Msg] Each message, as it comes.
      # @return [Array<NATS::Msg>] What the server delivered, maybe none.
      def fetch_no_wait(batch = 1, params = {}, &block)
        psub.fetch(batch, params.merge(no_wait: true), &block)
      end

      # next fetches one message, like Next of nats.go.
      # @param params [Hash] Options of {PullSubscription#fetch}.
      # @return [NATS::Msg]
      # @raise [NATS::Timeout] When no message came before the timeout.
      def next(params = {})
        msg = fetch(1, params).first
        raise ::NATS::Timeout.new("nats: fetch timeout") if msg.nil?

        msg
      end

      # consume passes the messages of the consumer to the block, pulling
      # them continuously, like {PullSubscription#consume}.
      # @param params [Hash] Options of {PullSubscription#consume}.
      # @yieldparam msg [NATS::Msg]
      # @return [NATS::JetStream::ConsumeContext]
      # @raise [NATS::JetStream::Error::HandlerRequired] When there is no block.
      def consume(params = {}, &block)
        psub.consume(params, &block)
      end

      # messages returns an iterator over the messages of the consumer,
      # which it pulls continuously, like {PullSubscription#messages}.
      # @param params [Hash] Options of {PullSubscription#messages}.
      # @return [NATS::JetStream::MessagesContext]
      def messages(params = {})
        psub.messages(params)
      end

      private

      # psub is the pull subscription bound to the consumer, which the
      # handle makes when first used.
      def psub
        @lock.synchronize do
          @psub ||= @js.send(:bind_pull_subscription, @stream, @name)
        end
      end
    end

    # PushConsumer is a handle to a JetStream push consumer, like the
    # PushConsumer of the nats.go jetstream package, which
    # js.push_consumer and the push consumer methods of a {Stream} return.
    # It keeps the info of the consumer from when it was got, or last
    # refreshed with info, as cached_info. Its messages are read with
    # consume, or with {JetStream#subscribe}.
    #
    # @example Consume the messages of a push consumer.
    #
    #   consumer = js.push_consumer("ORDERS", "dispatcher")
    #   cc = consumer.consume(error_handler: ->(err) { warn err }) do |msg|
    #     msg.ack
    #   end
    #   cc.stop
    #
    # @!visibility public
    class PushConsumer
      # @return [String] Name of the stream of the consumer.
      attr_reader :stream

      # @return [String] Name of the consumer.
      attr_reader :name

      # @!visibility private
      def initialize(js, stream, info)
        @js = js
        @stream = stream
        @name = info.name
        @info = info
        @lock = Mutex.new
        @consuming = nil
      end

      # info gets the current info of the consumer, and caches it.
      # @param params [Hash] Options to customize API request.
      # @option params [Float] :timeout Time to wait for response.
      # @return [JetStream::API::ConsumerInfo]
      def info(params = {})
        @info = @js.consumer_info(@stream, @name, params)
      end

      # cached_info is the info of the consumer from when the handle was
      # made, or info was last called, without asking the server.
      # @return [JetStream::API::ConsumerInfo]
      def cached_info
        @info
      end

      # consume subscribes to the deliver subject of the consumer, in its
      # deliver group if it has one, and passes each message it delivers to
      # the block, like Consume of a PushConsumer of nats.go. It answers the
      # flow control requests of the consumer, and reports a NoHeartbeat
      # when the consumer has idle heartbeats and nothing came for two of
      # them. The block acks the messages, as the consumer needs. A handle
      # consumes once at a time, as in nats.go: until the consumption
      # stopped, consume raises ConsumerAlreadyConsuming.
      #
      # @param params [Hash] Options to customize the consumption.
      # @option params [Proc] :error_handler Called with the errors met while
      #   consuming, like ConsumeErrHandler of nats.go: missing heartbeats, a
      #   deleted consumer, which stops the consumption, and those raised by
      #   the block; the error callback of the connection by default.
      # @yieldparam msg [NATS::Msg]
      # @return [NATS::JetStream::PushConsumeContext]
      # @raise [NATS::JetStream::Error::HandlerRequired] When there is no block.
      # @raise [NATS::JetStream::Error::ConsumerAlreadyConsuming] When the
      #   handle is consuming already.
      def consume(params = {}, &handler)
        raise Error::HandlerRequired unless handler

        @lock.synchronize do
          if @consuming && !@consuming.closed?
            raise Error::ConsumerAlreadyConsuming.new("nats: consumer is already consuming")
          end

          @consuming = PushConsumeContext.new(@js, @stream, @info, params, handler)
        end
      end
    end
  end
end
