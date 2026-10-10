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
    # OrderedConsumer reads the messages of a stream in order, like the
    # OrderedConsumer of the nats.go jetstream package. It pulls from an
    # ephemeral consumer that does not ack, keeps its state in memory and
    # has a single replica, which is cheap for the server. Whenever it
    # misses a message, or the consumer is gone, as when the heartbeats of
    # its pulls stop, after a reconnect or once the consumer is deleted,
    # it creates the consumer again from the next stream sequence it
    # expects.
    #
    # It reads either with fetch and next, or with consume or messages,
    # but not both. A fetch creates the consumer again for each fetch
    # but the first, so consume and messages read faster.
    #
    # @example Read a stream in order.
    #
    #   oc = js.ordered_consumer("ORDERS", filter_subjects: ["orders.eu.>"])
    #   oc.messages.each do |msg|
    #     process(msg)
    #   end
    #
    # @!visibility public
    class OrderedConsumer
      # Seconds after which the server deletes an unused consumer, by default.
      DEFAULT_INACTIVE_THRESHOLD = 300
      # Deliver policies an ordered consumer can start with.
      DELIVER_POLICIES = %w[all last new by_start_sequence by_start_time last_per_subject].freeze
      # Seconds to wait before trying to create the consumer again, at most.
      MAX_RESET_INTERVAL = 10

      # @return [String] Name of the stream.
      attr_reader :stream

      # @!visibility private
      def initialize(js, stream, params = {})
        raise Error::InvalidStreamName.new("nats: invalid stream name") if stream.nil? || stream.empty?

        @js = js
        @stream = stream
        @cfg = ordered_config(params)
        @prefix = params[:name_prefix] || NATS::NUID.new.next
        @lock = Monitor.new
        @reset_cond = @lock.new_cond
        @serial = 0
        @stream_seq = 0
        @deliver_seq = 0
        @name = nil
        @psub = nil
        @mode = nil
        @fetching = false
        @used = false
        @active = nil
        create_consumer(1)
      end

      # fetch pulls a batch of messages, like {PullSubscription#fetch}, with
      # the same options, and returns those that come in order. Unless it is
      # the first, it first creates the consumer again, from the next stream
      # sequence it expects.
      #
      # @param batch [Integer] Number of messages to pull.
      # @param params [Hash] Options of {PullSubscription#fetch}.
      # @yieldparam msg [NATS::Msg] Each message, as it comes.
      # @return [Array<NATS::Msg>]
      # @raise [NATS::JetStream::Error::OrderedConsumerUsedAsConsume] When it was
      #   read with consume or messages.
      # @raise [NATS::JetStream::Error::OrderedConsumerConcurrentRequests] When
      #   another fetch runs.
      # @raise [NATS::Timeout] When no message came before the timeout.
      def fetch(batch = 1, params = {}, &block)
        @lock.synchronize do
          raise Error::OrderedConsumerUsedAsConsume.new("nats: ordered consumer initialized as consume") if @mode == :consume
          raise Error::OrderedConsumerConcurrentRequests.new("nats: cannot run concurrent processing using ordered consumer") if @fetching

          @mode = :fetch
          @fetching = true
        end
        begin
          # A fetch tries once: the next fetch tries again.
          reset_consumer(1) if @used || @psub.nil?
          @used = true
          taken = []
          gap = false
          @psub.fetch(batch, params) do |msg|
            next if gap
            next gap = true unless accept(msg) == :ok

            taken << msg
            block&.call(msg)
          end
          taken
        ensure
          @lock.synchronize { @fetching = false }
        end
      end

      # next fetches one message, like fetch(1).
      # @param params [Hash] Options of {PullSubscription#fetch}.
      # @return [NATS::Msg]
      # @raise [NATS::Timeout] When no message came before the timeout.
      def next(params = {})
        msg = fetch(1, params).first
        raise ::NATS::Timeout.new("nats: fetch timeout") if msg.nil?

        msg
      end

      # consume passes each message to the block, in order, in a thread of
      # its own, like {PullSubscription#consume}, with the same options.
      # The error handler also gets the errors after which it creates the
      # consumer again, such as NoHeartbeat and ConsumerDeleted.
      #
      # @param params [Hash] Options of {PullSubscription#consume}. The heartbeat is
      #   5 seconds by default, or half of :expires when that is less than 10 seconds.
      # @yieldparam msg [NATS::Msg]
      # @return [NATS::JetStream::ConsumeContext]
      # @raise [NATS::JetStream::Error::OrderedConsumerUsedAsFetch] When it was read with fetch.
      # @raise [NATS::JetStream::Error::OrderedConsumerConcurrentRequests] When
      #   consume or messages still run.
      def consume(params = {}, &block)
        raise ArgumentError.new("nats: consume needs a block") unless block

        ConsumeContext.new(messages(params), @js.nc, params, block)
      end

      # messages returns an iterator over the messages, in order, like
      # {PullSubscription#messages}, with the same options.
      #
      # @param params [Hash] Options of {PullSubscription#messages}. The heartbeat is
      #   5 seconds by default, or half of :expires when that is less than 10 seconds.
      # @return [NATS::JetStream::OrderedMessagesContext]
      # @raise [NATS::JetStream::Error::OrderedConsumerUsedAsFetch] When it was read with fetch.
      # @raise [NATS::JetStream::Error::OrderedConsumerConcurrentRequests] When
      #   consume or messages still run.
      def messages(params = {})
        params = params.dup
        params[:heartbeat] ||= begin
          expires = params[:expires] || MessagesContext::DEFAULT_EXPIRES
          (expires.is_a?(Numeric) && expires < 10) ? expires / 2.0 : 5
        end
        MessagesContext.consume_opts(params)

        @lock.synchronize do
          raise Error::OrderedConsumerUsedAsFetch.new("nats: ordered consumer initialized as fetch") if @mode == :fetch
          if @active && !@active.closed?
            raise Error::OrderedConsumerConcurrentRequests.new("nats: cannot run concurrent processing using ordered consumer")
          end

          @mode = :consume
          # Start again after what was taken.
          reset_consumer(1) if @used || @psub.nil?
          @used = true
          @active = OrderedMessagesContext.new(self, params)
        end
      end

      # consumer_info retrieves the current status of the consumer that the
      # ordered consumer reads from now, which it may delete at any time.
      # @param params [Hash] Options to customize API request.
      # @return [JetStream::API::ConsumerInfo]
      # @raise [NATS::JetStream::Error::OrderedConsumerNotCreated] When there is
      #   no consumer, as creating it again failed.
      def consumer_info(params = {})
        name = @lock.synchronize { @name }
        raise Error::OrderedConsumerNotCreated.new("nats: consumer instance not yet created") unless name

        @js.consumer_info(@stream, name, params)
      end

      # @return [String, nil] Name of the consumer it reads from now.
      def consumer_name
        @lock.synchronize { @name }
      end

      # @!visibility private
      def psub
        @lock.synchronize { @psub }
      end

      # accept checks that a message comes in order, from the current
      # consumer, and moves past it: :ok when it does, :skip when it comes
      # from an earlier consumer, and :gap when the consumer missed one.
      # @!visibility private
      def accept(msg)
        meta = msg.metadata
        @lock.synchronize do
          return :skip if meta.consumer != @name
          return :gap if meta.sequence.consumer != @deliver_seq + 1

          @deliver_seq = meta.sequence.consumer
          @stream_seq = meta.sequence.stream
          :ok
        end
      end

      # reset_consumer drops the current consumer, and creates it again from
      # the next stream sequence it expects. It tries as many times as given,
      # or max_reset_attempts, waiting longer each time, unless cancelled.
      # @!visibility private
      def reset_consumer(attempts = nil, cancelled = nil)
        attempts ||= @cfg[:max_reset_attempts]
        old_psub, old_name = @lock.synchronize do
          olds = [@psub, @name]
          @psub = nil
          @name = nil
          @deliver_seq = 0
          olds
        end
        begin
          old_psub&.unsubscribe
        rescue NATS::IO::Error
          # The connection closed, which removed the subscription too.
        end
        if old_name
          Thread.new do
            @js.delete_consumer(@stream, old_name)
          rescue NATS::IO::Error
            # It goes once inactive.
          end
        end
        create_consumer(attempts, cancelled)
      end

      # wake_reset wakes a reset that waits to try again, to be cancelled.
      # @!visibility private
      def wake_reset
        @lock.synchronize { @reset_cond.broadcast }
      end

      private

      def create_consumer(attempts, cancelled = nil)
        interval = 1
        tries = 0
        begin
          tries += 1
          config = @lock.synchronize do
            @serial += 1
            consumer_config
          end
          @js.add_consumer(@stream, config)
        rescue NATS::IO::Error
          raise if attempts.positive? && tries >= attempts

          @lock.synchronize { @reset_cond.wait(interval) unless cancelled&.call }
          raise Error::MsgIteratorClosed.new("nats: messages iterator closed") if cancelled&.call

          interval = [interval * 2, MAX_RESET_INTERVAL].min
          retry
        end
        psub = @js.send(:bind_pull_subscription, @stream, config.name)
        @lock.synchronize do
          @name = config.name
          @psub = psub
        end
      end

      # consumer_config is the config of the next consumer: it starts after
      # the last message taken, or, before any, as configured.
      def consumer_config
        cfg = {
          name: "#{@prefix}_#{@serial}",
          deliver_policy: "by_start_sequence",
          opt_start_seq: @stream_seq + 1,
          ack_policy: "none",
          inactive_threshold: @cfg[:inactive_threshold] || DEFAULT_INACTIVE_THRESHOLD,
          num_replicas: 1,
          mem_storage: true,
          headers_only: (true if @cfg[:headers_only]),
          replay_policy: @cfg[:replay_policy],
          metadata: @cfg[:metadata]
        }
        filters = @cfg[:filter_subjects]
        if filters.size == 1
          cfg[:filter_subject] = filters.first
        elsif filters.size > 1
          cfg[:filter_subjects] = filters
        end

        if @stream_seq.zero?
          policy = @cfg[:deliver_policy]
          cfg[:deliver_policy] = policy
          cfg[:opt_start_seq] = (@cfg[:opt_start_seq] if policy == "by_start_sequence")
          cfg[:opt_start_time] = @cfg[:opt_start_time] if policy == "by_start_time"
          cfg[:filter_subjects] = [">"] if policy == "last_per_subject" && filters.empty?
        end
        JetStream::API::ConsumerConfig.new(cfg.compact)
      end

      def ordered_config(params)
        filters = Array(params[:filter_subjects] || params[:filter_subject])
        unless filters.all? { |f| f.is_a?(String) && !f.empty? }
          raise ArgumentError.new("nats: filter subjects should be non-empty Strings")
        end

        policy = (params[:deliver_policy] || "all").to_s
        raise ArgumentError.new("nats: invalid deliver policy #{policy.inspect}") unless DELIVER_POLICIES.include?(policy)

        start_seq = params[:opt_start_seq]
        if policy == "by_start_sequence" && !(start_seq.is_a?(Integer) && start_seq >= 1)
          raise ArgumentError.new("nats: deliver policy by_start_sequence needs an opt_start_seq of at least 1")
        end

        start_time = params[:opt_start_time]
        start_time = start_time.getutc.iso8601(9) if start_time.is_a?(Time)
        if policy == "by_start_time" && !(start_time.is_a?(String) && !start_time.empty?)
          raise ArgumentError.new("nats: deliver policy by_start_time needs an opt_start_time")
        end

        threshold = params[:inactive_threshold]
        if threshold && !(threshold.is_a?(Numeric) && threshold.real? && threshold.finite? && threshold.positive?)
          raise ArgumentError.new("nats: inactive_threshold should be a positive number of seconds")
        end

        attempts = params[:max_reset_attempts] || 0
        raise ArgumentError.new("nats: max_reset_attempts should be an Integer") unless attempts.is_a?(Integer)

        {
          filter_subjects: filters,
          deliver_policy: policy,
          opt_start_seq: start_seq,
          opt_start_time: start_time,
          replay_policy: params[:replay_policy]&.to_s,
          inactive_threshold: threshold,
          headers_only: params[:headers_only],
          metadata: params[:metadata],
          # 0 or less: for good.
          max_reset_attempts: attempts
        }
      end
    end

    # OrderedMessagesContext iterates over the messages of an ordered
    # consumer, in order, like {MessagesContext}. When the consumer misses
    # a message, or is gone, it creates the consumer again and goes on.
    #
    # @!visibility public
    class OrderedMessagesContext
      include Enumerable

      # @!visibility private
      attr_accessor :on_error

      # @!visibility private
      def initialize(consumer, params)
        @consumer = consumer
        @params = params
        @lock = Monitor.new
        @next_lock = Mutex.new
        @closed = nil
        @draining = false
        @on_error = nil
        # Messages returned so far, for stop_after, which counts them across
        # the consumers.
        @delivered = 0
        @ctx = messages_context
      end

      # next waits for the next message, in order, and returns it.
      #
      # @param timeout [Float] How long to wait for a message, for good by default.
      # @return [NATS::Msg]
      # @raise [NATS::Timeout] When no message came before the timeout.
      # @raise [NATS::JetStream::Error::MsgIteratorClosed] When the iterator was
      #   stopped, or drained and has no more messages, or the connection closed.
      # @raise [NATS::JetStream::Error] When creating the consumer again failed
      #   max_reset_attempts times, which closes the iterator.
      def next(timeout: nil)
        if timeout && !(timeout.is_a?(Numeric) && timeout.positive?)
          raise ArgumentError.new("nats: timeout should be a positive number")
        end
        deadline = MonotonicTime.now + timeout if timeout

        @next_lock.synchronize { next_in_order(deadline) }
      end

      # each yields each message as it comes, in order, until the iterator
      # is stopped or drained.
      # @yieldparam msg [NATS::Msg]
      def each
        return enum_for(:each) unless block_given?

        loop do
          yield self.next
        rescue Error::MsgIteratorClosed
          break
        end
        self
      end

      # stop stops reading, as {MessagesContext#stop} does.
      def stop
        ctx = @lock.synchronize do
          @closed ||= :stopped
          @ctx
        end
        @consumer.wake_reset
        ctx&.stop
      end

      # drain stops pulling, and lets next return the messages already
      # received, as {MessagesContext#drain} does.
      def drain
        ctx = @lock.synchronize do
          return if @closed

          @draining = true
          @ctx
        end
        ctx&.drain
      end

      # closed? tells whether the iterator was stopped, drained of all its
      # messages, or closed by an error or with the connection.
      # @return [Boolean]
      def closed?
        @lock.synchronize { !@closed.nil? || (@ctx.nil? || @ctx.closed?) }
      end

      # @!visibility private
      def closed_reason
        @lock.synchronize { @closed || @ctx&.closed_reason }
      end

      private

      def messages_context
        psub = @consumer.psub
        return if psub.nil?

        params = @params
        params = params.merge(stop_after: params[:stop_after] - @delivered) if params[:stop_after]
        ctx = MessagesContext.new(psub, params)
        ctx.notify_reconnect = true
        ctx
      end

      def next_in_order(deadline)
        loop do
          ctx = @lock.synchronize do
            raise Error::MsgIteratorClosed.new("nats: messages iterator closed") if @closed == :stopped || @ctx.nil?

            @ctx
          end
          remaining = deadline - MonotonicTime.now if deadline
          raise ::NATS::Timeout.new("nats: timeout") if remaining && remaining <= 0

          begin
            msg = ctx.next(timeout: remaining)
          rescue ::NATS::Timeout, Error::MsgIteratorClosed
            raise
          rescue MessagesContext::Reconnected
            reset
            next
          rescue Error => e
            # NoHeartbeat, ConsumerDeleted, or a pull turned away.
            report(e)
            reset
            next
          end

          case @consumer.accept(msg)
          when :ok then return taken(msg, ctx)
          when :gap then reset
          end
        end
      end

      # reset creates the consumer again, from the next stream sequence it
      # expects, and pulls from it.
      def reset
        @lock.synchronize do
          raise Error::MsgIteratorClosed.new("nats: messages iterator closed") if @draining || @closed
        end
        @ctx.stop
        begin
          @consumer.reset_consumer(nil, -> { @lock.synchronize { !@closed.nil? } })
        rescue Error::MsgIteratorClosed
          raise
        rescue NATS::IO::Error => e
          @lock.synchronize { @closed = e }
          raise
        end
        @lock.synchronize do
          @ctx = messages_context
          @ctx.stop if @closed
        end
      end

      # taken counts a message returned, and stops after the last one to
      # take with stop_after.
      def taken(msg, ctx)
        @delivered += 1
        stop_after = @params[:stop_after]
        if stop_after && @delivered >= stop_after
          @lock.synchronize { @closed ||= :stopped }
          ctx.stop
        end
        msg
      end

      def report(err)
        @on_error&.call(err)
      end
    end
  end
end
