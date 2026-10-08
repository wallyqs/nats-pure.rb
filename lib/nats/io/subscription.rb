# frozen_string_literal: true

# Copyright 2016-2021 The NATS Authors
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

module NATS
  # A Subscription represents interest in a given subject.
  #
  # @example Create NATS subscription with callback.
  #   require 'nats/client'
  #
  #   nc = NATS.connect("demo.nats.io")
  #   sub = nc.subscribe("foo") do |msg|
  #     puts "Received [#{msg.subject}]: #{}"
  #   end
  #
  class Subscription
    include MonitorMixin

    attr_accessor :subject, :queue, :future, :callback, :response, :received, :max, :sid
    attr_writer :pending
    attr_accessor :pending_queue, :pending_size, :wait_for_msgs_cond
    attr_reader :pending_msgs_limit, :pending_bytes_limit
    attr_accessor :nc
    attr_accessor :jsi
    attr_accessor :closed, :drained
    alias_method :delivered, :received

    # @private
    # A barrier of nc.barrier, which runs its block once every subscription
    # it was added to passed it.
    class Barrier
      def initialize(subs, nc, block)
        @left = subs
        @nc = nc
        @block = block
        @mutex = Mutex.new
      end

      def pass
        return unless @mutex.synchronize { (@left -= 1).zero? }

        @block.call
      rescue => e
        @nc.send(:err_cb_call, @nc, e, nil)
      end
    end

    # The max of the pending queue for pending limits that are negative,
    # which do not limit.
    UNLIMITED_PENDING = 1 << 62
    private_constant :UNLIMITED_PENDING

    class << self
      # @private
      # Checks pending limits like SetPendingLimits of nats.go: zero is
      # not allowed, and a negative limit does not limit.
      def check_pending_limits!(msgs_limit, bytes_limit)
        [msgs_limit, bytes_limit].each do |limit|
          next if limit.is_a?(Integer) && !limit.zero?

          raise ArgumentError, "nats: invalid argument: pending limits must be non-zero Integers"
        end
      end
    end

    def initialize(**opts)
      super() # required to initialize monitor
      @subject = ""
      @queue = nil
      @future = nil
      @callback = nil
      @response = nil
      @received = 0
      @max = nil
      @pending = nil
      @sid = nil
      @nc = nil
      @closed = nil
      @drained = false

      # State from async subscriber messages delivery
      @pending_queue = nil
      @pending_size = 0
      @pending_msgs_limit = nil
      @pending_bytes_limit = nil

      # Sync subscriber
      @wait_for_msgs_cond = nil

      # Async subscriber: the messages handed to pending_queue and taken
      # from it so far, those being processed, and the barriers that wait
      # for the messages handed before them to be processed.
      @enqueued = 0
      @dequeued = 0
      @processing = {}
      @barriers = []

      # Messages dropped as the subscription was a slow consumer, and the
      # most messages and bytes that were pending.
      @dropped = 0
      @max_pending_msgs = 0
      @max_pending_bytes = 0

      # Called with the subject once the subscription is closed.
      @closed_cb = nil

      # To limit number of concurrent messages being processed (1 to only allow sequential processing)
      @processing_concurrency = opts.fetch(:processing_concurrency, NATS::IO::DEFAULT_SINGLE_SUB_CONCURRENCY)
    end

    # Concurrency of message processing for a single subscription.
    # 1 means sequential processing
    # 2+ allow processed concurrently and possibly out of order.
    def processing_concurrency=(value)
      raise ArgumentError, "nats: subscription processing concurrency must be positive integer" unless value.positive?
      return if @processing_concurrency == value

      @processing_concurrency = value
      @concurrency_semaphore = Concurrent::Semaphore.new(value)
    end

    def concurrency_semaphore
      @concurrency_semaphore ||= Concurrent::Semaphore.new(@processing_concurrency)
    end

    # Whether the subscription is still active, like IsValid of nats.go:
    # false once it was unsubscribed, got its max messages or was drained,
    # or its connection was closed.
    # @return [Boolean]
    def valid?
      !!@nc&.send(:subscribed?, self)
    end

    # The messages and bytes received for the subscription that wait to be
    # processed by its callback or taken by next_msg, like Pending of
    # nats.go. These are what its pending limits limit.
    # @return [Array(Integer, Integer)] The messages and the bytes.
    # @raise [NATS::IO::BadSubscription] When the subscription is not valid.
    def pending
      raise NATS::IO::BadSubscription.new("nats: invalid subscription") unless valid?

      synchronize { [@pending_queue.size, @pending_size] }
    end

    # The messages that wait, like QueuedMsgs of nats.go; see pending.
    # @return [Integer]
    # @raise [NATS::IO::BadSubscription] When the subscription is not valid.
    def queued_msgs
      pending.first
    end

    # Sets the most messages that may be pending, also once subscribed; a
    # negative limit does not limit. See set_pending_limits.
    def pending_msgs_limit=(limit)
      Subscription.check_pending_limits!(limit, 1)
      synchronize do
        @pending_msgs_limit = limit
        @pending_queue&.max = pending_queue_max
      end
    end

    # Sets the most bytes that may be pending, also once subscribed; a
    # negative limit does not limit. See set_pending_limits.
    def pending_bytes_limit=(limit)
      Subscription.check_pending_limits!(1, limit)
      synchronize { @pending_bytes_limit = limit }
    end

    # The most messages and bytes that may be pending for the subscription,
    # like PendingLimits of nats.go; a negative limit does not limit.
    # @return [Array(Integer, Integer)] The messages and the bytes.
    # @raise [NATS::IO::BadSubscription] When the subscription is closed.
    def pending_limits
      synchronize do
        raise NATS::IO::BadSubscription.new("nats: invalid subscription") if @closed

        [@pending_msgs_limit, @pending_bytes_limit]
      end
    end

    # Sets the most messages and bytes that may be pending for the
    # subscription, like SetPendingLimits of nats.go. Messages that come
    # beyond them are dropped, as for a slow consumer. They take effect at
    # once, also when lower than the messages already pending, which stay.
    # @param msgs_limit [Integer] The messages, negative to not limit them.
    # @param bytes_limit [Integer] The bytes, negative to not limit them.
    # @raise [ArgumentError] When a limit is zero, like ErrInvalidArg.
    # @raise [NATS::IO::BadSubscription] When the subscription is closed.
    def set_pending_limits(msgs_limit, bytes_limit)
      Subscription.check_pending_limits!(msgs_limit, bytes_limit)
      synchronize do
        raise NATS::IO::BadSubscription.new("nats: invalid subscription") if @closed

        @pending_msgs_limit = msgs_limit
        @pending_bytes_limit = bytes_limit
        @pending_queue&.max = pending_queue_max
      end
      nil
    end

    # Auto unsubscribes the server by sending UNSUB command and throws away
    # subscription in case already present and has received enough messages.
    def unsubscribe(opt_max = nil)
      @nc.send(:unsubscribe, self, opt_max)
    end

    # Drains the subscription, like Drain of nats.go: unsubscribes, and lets
    # the messages that were received until the server confirms that, and
    # those still pending, be processed before the subscription is closed,
    # in the background. Use on_close to know when it is done. It takes at
    # most the drain_timeout of the connection, after which on_error gets a
    # NATS::IO::DrainTimeoutError.
    # @raise [NATS::IO::BadSubscription] When the subscription is closed.
    # @raise [NATS::IO::ConnectionClosedError] When the connection is closed.
    # @raise [NATS::IO::ConnectionDrainingError] When the connection drains.
    def drain
      @nc.send(:drain_subscription, self)
    end

    # Whether the subscription is draining, like IsDraining of nats.go;
    # false once the drain is done.
    def draining?
      synchronize { !!@drained && !@closed }
    end

    # The number of messages dropped as the subscription had as many
    # pending as its pending limits allow, like Dropped of nats.go.
    # @return [Integer]
    def dropped
      synchronize { @dropped }
    end

    # The most messages and bytes that were pending at once for a
    # subscription with a callback, like MaxPending of nats.go.
    # @return [Array(Integer, Integer)] The messages and the bytes.
    def max_pending
      synchronize { [@max_pending_msgs, @max_pending_bytes] }
    end

    # Resets max_pending, like ClearMaxPending of nats.go.
    def clear_max_pending
      synchronize do
        @max_pending_msgs = 0
        @max_pending_bytes = 0
      end
      nil
    end

    # Sets the callback called with the subject of a subscription with a
    # callback once it is closed, like SetClosedHandler of nats.go: once it
    # is unsubscribed, or reached its max messages, and the messages it got
    # were processed; once its drain is done; or when the connection closes.
    def on_close(&callback)
      synchronize { @closed_cb = callback }
    end

    # next_msg blocks and waiting for the next message to be received.
    # The messages already received are returned first, and then, like
    # NextMsg of nats.go, it raises when no more can come.
    # @raise [NATS::IO::SyncSubRequired] For a subscription with a callback,
    #   whose messages go to the callback, like ErrSyncSubRequired of nats.go.
    # @raise [NATS::IO::MaxMessages] When the subscription got its max
    #   messages, like ErrMaxMessages.
    # @raise [NATS::IO::BadSubscription] When it was unsubscribed or drained,
    #   like ErrBadSubscription.
    # @raise [NATS::IO::ConnectionClosedError] When the connection is closed.
    # @raise [NATS::Timeout] When no message comes within the timeout.
    def next_msg(opts = {})
      unless wait_for_msgs_cond
        raise NATS::IO::SyncSubRequired.new("nats: illegal call on an async subscription")
      end

      timeout = opts[:timeout] ||= 0.5
      synchronize do
        if @pending_queue.empty?
          check_next_msg!

          # Wait for a bit until getting a signal.
          MonotonicTime.with_nats_timeout(timeout) do
            wait_for_msgs_cond.wait(timeout)
          end

          if @pending_queue.empty?
            check_next_msg!
            raise NATS::Timeout
          end
        end

        # Decrease pending size since consumed already
        msg = @pending_queue.pop
        self.pending_size -= msg.data.size
        msg
      end
    end

    def inspect
      "#<NATS::Subscription(subject: \"#{@subject}\", queue: \"#{@queue}\", sid: #{@sid})>"
    end

    def dispatch(msg)
      synchronize do
        pending_queue << msg
        self.pending_size += msg.data.size
        @enqueued += 1
        @max_pending_msgs = pending_queue.size if pending_queue.size > @max_pending_msgs
        @max_pending_bytes = pending_size if pending_size > @max_pending_bytes
      end

      # For async subscribers, send message for processing to the thread pool.
      enqueue_processing(@nc.subscription_executor) if callback

      # For sync subscribers, signal that there is a new message.
      wait_for_msgs_cond&.signal
    end

    def process(msg)
      return unless callback

      # Decrease pending size since consumed already
      synchronize { self.pending_size -= msg.data.size }

      nc.reloader.call do
        # Note: Keep some of the alternative arity versions to slightly
        # improve backwards compatibility.  Eventually fine to deprecate
        # since recommended version would be arity of 1 to get a NATS::Msg.
        case callback.arity
        when 0 then callback.call
        when 1 then callback.call(msg)
        when 2 then callback.call(msg.data, msg.reply)
        when 3 then callback.call(msg.data, msg.reply, msg.subject)
        else callback.call(msg.data, msg.reply, msg.subject, msg.header)
        end
      rescue => e
        synchronize { nc.send(:err_cb_call, nc, e, self) }
      end
    end

    # Send a message for its processing to a separate thread
    def enqueue_processing(executor)
      concurrency_semaphore.try_acquire || return # Previous message is being executed, let it finish and enqueue next one.
      executor.post do
        seq = nil
        msg = synchronize do
          pending_queue.pop(true).tap do
            seq = (@dequeued += 1)
            @processing[seq] = true
          end
        end
        process(msg)
      rescue ThreadError # queue is empty
        # No release here: the ensure below releases the permit; a second
        # release would grow the semaphore beyond processing_concurrency.
      ensure
        processed(seq) if seq
        concurrency_semaphore.release
        [concurrency_semaphore.available_permits, pending_queue.size].min.times do
          enqueue_processing(executor)
        end
      end
    rescue Concurrent::RejectedExecutionError
      # The executor is being shut down (the connection is closing,
      # draining or reconnecting). Release the permit so the
      # subscription can process messages again after a reconnect;
      # the message stays in pending_queue.
      concurrency_semaphore.release
    end

    private

    # The max of the pending queue: the messages limit, unless it does not
    # limit. The lock is held.
    def pending_queue_max
      @pending_msgs_limit.positive? ? @pending_msgs_limit : UNLIMITED_PENDING
    end

    # Whether as many messages or bytes are pending as the limits allow, so
    # that a message that comes is dropped. The lock is held.
    def pending_limits_reached?
      (@pending_msgs_limit.positive? && @pending_queue.size >= @pending_msgs_limit) ||
        (@pending_bytes_limit.positive? && @pending_size >= @pending_bytes_limit)
    end

    # Raises when no more messages can come for next_msg. The lock is held.
    def check_next_msg!
      raise NATS::IO::ConnectionClosedError.new("nats: connection closed") if @nc.closed?
      if @max
        raise NATS::IO::MaxMessages.new("nats: maximum messages delivered") if @received >= @max
        # Unsubscribed with a max that was not reached, unless drained.
        return unless @drained
      end
      raise NATS::IO::BadSubscription.new("nats: invalid subscription") if @closed
    end

    # Called by the client for a message it dropped. The lock is held.
    def dropped!
      @dropped += 1
    end

    # Whether no message is pending or being processed.
    def idle?
      synchronize { pending_queue.nil? || (pending_queue.empty? && @processing.empty?) }
    end

    # Called by the client once the subscription is gone. Runs the closed
    # handler, once, after the messages dispatched so far were processed,
    # unless told not to wait, as when the connection is closed.
    def closed!(wait: true)
      handler = synchronize do
        # Wakes up next_msg, as no more messages come.
        wait_for_msgs_cond&.broadcast
        next unless callback

        @closed_cb.tap { @closed_cb = nil }
      end
      return unless handler

      barrier = Barrier.new(1, @nc, proc { handler.call(subject) })
      wait ? add_barrier(barrier) : barrier.pass
    end

    # Called by the client for a barrier, which is passed once the messages
    # dispatched so far have been processed, even when processed
    # concurrently, out of order.
    def add_barrier(barrier)
      passed = synchronize do
        @barriers << [@enqueued, barrier]
        passed_barriers
      end
      passed.each(&:pass)
    end

    # Called once message seq is processed.
    def processed(seq)
      passed = synchronize do
        @processing.delete(seq)
        passed_barriers
      end
      passed.each(&:pass)
    end

    # Takes the barriers whose messages have all been processed: all taken
    # from pending_queue, and none of them still being processed. The
    # messages being processed are in the order they were taken, so the
    # first one is the oldest. The lock is held.
    def passed_barriers
      return [] if @barriers.empty?

      oldest = @processing.first&.first
      passed, @barriers = @barriers.partition do |last, _|
        @dequeued >= last && (oldest.nil? || oldest > last)
      end
      passed.map(&:last)
    end
  end
end
