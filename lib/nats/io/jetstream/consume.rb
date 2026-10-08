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

require_relative "errors"

module NATS
  class JetStream
    # MessagesContext iterates over the messages of a pull consumer, which
    # it pulls continuously, like Messages of the nats.go jetstream package:
    # it keeps up to max_messages (or max_bytes) asked for, and pulls for
    # more once fewer than the threshold remain. Each pull expires after
    # expires seconds, and the server sends idle heartbeats to it, which
    # tell it that the server is still there. After a reconnect, or when
    # the heartbeats stop, it pulls again; next raises NoHeartbeat for the
    # heartbeats that stopped, unless err_on_missing_heartbeat is false. With
    # stop_after, it stops once it returned that many messages.
    #
    # @example Iterate over the messages of a pull subscription.
    #
    #   psub = js.pull_subscribe("foo", "bar")
    #   msgs = psub.messages(max_messages: 100)
    #   msgs.each do |msg|
    #     msg.ack
    #   end
    #
    # @!visibility public
    class MessagesContext
      include Enumerable

      # How many messages to keep asked for by default.
      DEFAULT_MAX_MESSAGES = 500
      # How long a pull waits, in seconds, by default.
      DEFAULT_EXPIRES = 30
      # The batch of the pulls that ask for bytes only.
      BYTES_ONLY_BATCH = 1_000_000
      # How long, in seconds, a wait for messages lasts at most, before it
      # checks for a reconnect.
      POLL_INTERVAL = 0.5

      # The options given, with their defaults.
      # @return [Hash]
      attr_reader :opts

      # Raised by next after a reconnect, when asked to: an ordered consumer
      # then creates its consumer again.
      # @!visibility private
      class Reconnected < StandardError; end

      # @!visibility private
      attr_accessor :on_error, :notify_reconnect

      # @param psub [NATS::JetStream::PullSubscription] The subscription of the consumer.
      # @param params [Hash] See {PullSubscription#messages}.
      # @!visibility private
      def initialize(psub, params = {})
        @opts = self.class.consume_opts(params)
        @psub = psub
        @nc = psub.nc
        @sub = @nc.subscribe(@nc.new_inbox)
        @pending_msgs = 0
        @pending_bytes = 0
        # Messages returned so far, for stop_after.
        @delivered = 0
        @reconnects = @nc.stats[:reconnects]
        @closed = nil
        @draining = false
        @flushed = false
        @pin_sent = nil
        @next_lock = Mutex.new
        # Called with the errors that do not end the iteration.
        @on_error = nil
        @notify_reconnect = false
      end

      # next waits for the next message and returns it.
      #
      # @param timeout [Float] How long to wait for a message, for good by default.
      # @return [NATS::Msg]
      # @raise [NATS::Timeout] When no message came before the timeout.
      # @raise [NATS::JetStream::Error::MsgIteratorClosed] When the iterator was
      #   stopped, or drained and has no more messages, or the connection closed.
      # @raise [NATS::JetStream::Error::NoHeartbeat] When no heartbeat came for
      #   two of them, unless :err_on_missing_heartbeat is false. The iterator
      #   pulls again, and next can be called again.
      # @raise [NATS::JetStream::Error::ConsumerDeleted] When the consumer was
      #   deleted, which closes the iterator.
      # @raise [NATS::JetStream::Error::APIError] When the server turned a pull
      #   away as invalid, which closes the iterator.
      def next(timeout: nil)
        if timeout && !(timeout.is_a?(Numeric) && timeout.positive?)
          raise ArgumentError.new("nats: timeout should be a positive number")
        end
        deadline = MonotonicTime.now + timeout if timeout

        @next_lock.synchronize { next_msg(deadline) }
      end

      # each yields each message as it comes, until the iterator is
      # stopped or drained. Other errors, as of {#next}, are raised.
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

      # stop stops pulling, and drops the messages already received, which
      # the server delivers again after the ack_wait of the consumer. Next
      # then raises MsgIteratorClosed.
      def stop
        close(:stopped)
      end

      # drain stops pulling, and lets next return the messages already
      # received, and those still on their way, before it raises
      # MsgIteratorClosed.
      def drain
        @sub.synchronize do
          return if @closed || @draining

          @draining = true
          @sub.wait_for_msgs_cond.broadcast
        end
        begin
          @nc.send(:drain_sub, @sub)
        rescue NATS::IO::ConnectionClosedError
          close(:connection_closed)
        end
      end

      # closed? tells whether the iterator was stopped, drained of all its
      # messages, or closed by an error or with the connection.
      # @return [Boolean]
      def closed?
        @sub.synchronize { !@closed.nil? }
      end

      # The reason the iterator closed: :stopped, :drained,
      # :connection_closed, or the error that closed it.
      # @!visibility private
      def closed_reason
        @sub.synchronize { @closed }
      end

      class << self
        # consume_opts validates the options of a continuous pull, and adds
        # their defaults, as nats.go does.
        # @!visibility private
        def consume_opts(params)
          max_messages = params[:max_messages]
          max_bytes = params[:max_bytes]
          %i[max_messages max_bytes bytes_limit threshold_messages threshold_bytes stop_after].each do |name|
            value = params[name]
            next if value.nil? || (value.is_a?(Integer) && value >= 1)

            raise ArgumentError.new("nats: #{name} should be an integer of at least 1")
          end
          raise ArgumentError.new("nats: only one of max_messages and max_bytes can be given") if max_messages && max_bytes
          raise ArgumentError.new("nats: only one of max_bytes and bytes_limit can be given") if max_bytes && params[:bytes_limit]

          max_messages = max_bytes ? BYTES_ONLY_BATCH : (max_messages || DEFAULT_MAX_MESSAGES)
          expires = params[:expires] || DEFAULT_EXPIRES
          unless expires.is_a?(Numeric) && expires.finite? && expires >= 1
            raise ArgumentError.new("nats: expires should be at least 1 second")
          end

          heartbeat = params[:heartbeat] || [expires / 2.0, 30].min
          unless heartbeat.is_a?(Numeric) && heartbeat.between?(0.5, 30)
            raise ArgumentError.new("nats: heartbeat should be from 0.5 to 30 seconds")
          end
          raise ArgumentError.new("nats: heartbeat should be at most half of expires") if heartbeat > expires / 2.0

          err_on_missing_heartbeat = params.fetch(:err_on_missing_heartbeat, true)
          unless [true, false].include?(err_on_missing_heartbeat)
            raise ArgumentError.new("nats: err_on_missing_heartbeat should be true or false")
          end

          {
            max_messages: max_messages,
            max_bytes: max_bytes,
            expires: expires,
            heartbeat: heartbeat,
            threshold_messages: params[:threshold_messages] || (max_messages / 2.0).ceil,
            threshold_bytes: params[:threshold_bytes] || (max_bytes && (max_bytes / 2.0).ceil),
            bytes_limit: params[:bytes_limit],
            stop_after: params[:stop_after],
            err_on_missing_heartbeat: err_on_missing_heartbeat,
            **params.slice(:group, :min_pending, :min_ack_pending, :priority)
          }
        end
      end

      private

      def next_msg(deadline)
        heard = MonotonicTime.now
        loop do
          check_closed!
          if reconnected?
            raise Reconnected if @notify_reconnect

            # The pulls that waited on the server are gone.
            heard = MonotonicTime.now
          elsif @nc.reconnecting?
            # Heartbeats do not come while disconnected.
            heard = MonotonicTime.now
          end
          check_pending

          silent = heard + 2 * @opts[:heartbeat]
          msg = wait_msg([deadline, silent, MonotonicTime.now + POLL_INTERVAL].compact.min)
          next flush_drained if msg == :drained
          now = MonotonicTime.now
          if msg.nil?
            raise ::NATS::Timeout.new("nats: timeout") if deadline && now >= deadline
            next unless now >= silent && !draining?

            # Pull again, as the server may have lost the pulls.
            heard = now
            reset_pending
            next unless @opts[:err_on_missing_heartbeat]

            raise Error::NoHeartbeat.new("nats: no heartbeat received")
          end

          heard = now
          next handle_status(msg) if JS.is_status_msg(msg)

          @psub.send(:track_pin, msg)
          msg.sub = @psub
          done = @sub.synchronize do
            @pending_msgs -= 1
            @pending_bytes -= JS.msg_size(msg) if @opts[:max_bytes]
            @delivered += 1
            @opts[:stop_after] && @delivered >= @opts[:stop_after]
          end
          # The last message to take: stop pulling, and close once it is returned.
          close(:stopped) if done
          return msg
        end
      end

      # check_closed! raises once the iterator is closed, or drained of all
      # its messages.
      def check_closed!
        close(:connection_closed) if @nc.closed?
        @sub.synchronize do
          if @draining && @flushed && @sub.pending_queue.empty?
            @closed ||= :drained
            @draining = false
          end
          reason = @closed
          return if reason.nil?

          detail = ": connection closed" if reason == :connection_closed
          raise Error::MsgIteratorClosed.new("nats: messages iterator closed#{detail}")
        end
      end

      def draining?
        @sub.synchronize { @draining }
      end

      # reconnected? tells whether the connection reconnected since it last
      # looked, in which case it pulls for all again.
      def reconnected?
        reconnects = @nc.stats[:reconnects]
        return false if reconnects == @reconnects

        @reconnects = reconnects
        reset_pending
        true
      end

      def reset_pending
        @sub.synchronize do
          @pending_msgs = 0
          @pending_bytes = 0
        end
      end

      # check_pending pulls again once fewer messages or bytes than the
      # thresholds remain asked for.
      def check_pending
        req = @sub.synchronize do
          next if @closed || @draining

          below = @pending_msgs < @opts[:threshold_messages] ||
            (@opts[:max_bytes] && @pending_bytes < @opts[:threshold_bytes])
          next unless below

          req = {
            batch: @opts[:max_messages] - @pending_msgs,
            expires: (@opts[:expires] * 1_000_000_000).to_i,
            idle_heartbeat: (@opts[:heartbeat] * 1_000_000_000).to_i,
            **@opts.slice(:group, :min_pending, :min_ack_pending, :priority)
          }
          if @opts[:max_bytes]
            req[:batch] = @opts[:max_messages]
            req[:max_bytes] = @opts[:max_bytes] - @pending_bytes
          elsif @opts[:bytes_limit]
            # Each pull takes at most these bytes, which are not counted.
            req[:max_bytes] = @opts[:bytes_limit]
          end
          # Ask for no more than the messages left to take.
          req[:batch] = [req[:batch], @opts[:stop_after] - @delivered - @pending_msgs].min if @opts[:stop_after]
          next if req[:batch] <= 0

          # With stop_after, a pull can ask for fewer: count what it asks for.
          @pending_msgs = @opts[:stop_after] ? @pending_msgs + req[:batch] : @opts[:max_messages]
          @pending_bytes = @opts[:max_bytes] || 0
          req
        end
        return unless req

        begin
          pin_id = @psub.send(:pull, req, @sub.subject)
          @sub.synchronize { @pin_sent = pin_id }
        rescue NATS::IO::ConnectionClosedError
          close(:connection_closed)
        end
      end

      # wait_msg takes the next message of the subscription, waiting for one
      # until the deadline; nil when none came, or when the iterator closed,
      # and :drained when draining took all that came.
      def wait_msg(deadline)
        @sub.synchronize do
          loop do
            return if @closed
            unless @sub.pending_queue.empty?
              msg = @sub.pending_queue.pop
              @sub.pending_size -= msg.data.size
              return msg
            end
            return :drained if @draining

            remaining = deadline - MonotonicTime.now
            return if remaining <= 0

            @sub.wait_for_msgs_cond.wait(remaining)
          end
        end
      end

      # flush_drained waits, while draining, for the messages still on their
      # way, then removes the subscription. Once flushed, the iterator closes
      # when it has returned what came.
      def flush_drained
        return if @sub.synchronize { @flushed }

        begin
          @nc.flush(1)
        rescue NATS::IO::Timeout, NATS::IO::ConnectionClosedError
          # What did not come in time is delivered again.
        end
        @nc.synchronize { @nc.send(:delete_sid, @sub.sid) }
        @sub.synchronize do
          @flushed = true
          @sub.closed = true
        end
      end

      # handle_status deals with a status that came to the pulls. Those that
      # end a pull leave fewer messages asked for; an invalid pull or a
      # deleted consumer close the iterator; other errors are reported.
      def handle_status(msg)
        status = msg.header[JS::Header::Status]
        desc = msg.header[JS::Header::Desc].to_s.downcase
        case status
        when JS::Status::CtrlMsg
          nil
        when JS::Status::NoMsgs, JS::Status::RequestTimeout
          pull_ended(msg)
        when JS::Status::Conflict
          if desc.include?("batch completed") || desc.include?("message size exceeds maxbytes")
            pull_ended(msg)
          elsif desc.include?("consumer deleted")
            fail_with(Error::ConsumerDeleted.new({description: msg.header[JS::Header::Desc]}))
          else
            reset_pending if desc.include?("leadership change")
            report(JS.from_msg(msg))
          end
        when "400"
          fail_with(JS.from_msg(msg))
        when JS::Status::PinIdMismatch
          @psub.send(:forget_pin, @sub.synchronize { @pin_sent })
          reset_pending
          report(JS.from_msg(msg))
        else
          report(JS.from_msg(msg))
        end
      end

      # pull_ended takes the messages and bytes that a pull left undelivered
      # off those asked for.
      def pull_ended(msg)
        msgs = msg.header["Nats-Pending-Messages"].to_i
        bytes = msg.header["Nats-Pending-Bytes"].to_i
        @sub.synchronize do
          @pending_msgs = [@pending_msgs - msgs, 0].max
          @pending_bytes = [@pending_bytes - bytes, 0].max if @opts[:max_bytes]
        end
      end

      def report(err)
        @on_error&.call(err)
      end

      # fail_with closes the iterator for an error, and raises it. Next then
      # raises MsgIteratorClosed.
      def fail_with(err)
        close(err)
        raise err
      end

      # close closes the iterator for the reason given, and unsubscribes.
      def close(reason)
        @sub.synchronize do
          return if @closed

          @closed = reason
          @draining = false
          @flushed = true
          @sub.pending_queue.clear
          @sub.pending_size = 0
          @sub.wait_for_msgs_cond.broadcast
        end
        begin
          @sub.unsubscribe unless @sub.closed
        rescue NATS::IO::ConnectionClosedError, NATS::IO::BadSubscription
          # The connection closed, which removed the subscription too.
        end
      end
    end

    # ConsumeContext runs the consumption of a pull consumer, which pulls
    # its messages continuously and passes each to a block in a thread of
    # its own, like Consume of the nats.go jetstream package. See
    # {PullSubscription#consume}.
    #
    # @!visibility public
    class ConsumeContext
      # @param messages [MessagesContext, OrderedMessagesContext] The messages to consume.
      # @!visibility private
      def initialize(messages, nc, params, handler)
        @handler = handler
        @error_handler = params[:error_handler]
        @messages = messages
        @messages.on_error = ->(err) { report(err) }
        @nc = nc
        @done = false
        @lock = Monitor.new
        @done_cond = @lock.new_cond
        @thread = Thread.new { run }
      end

      # The options given, with their defaults.
      # @return [Hash]
      def opts
        @messages.opts
      end

      # stop stops pulling and passing messages to the block, once it
      # returns, if it runs. The messages already received are dropped,
      # and the server delivers them again after the ack_wait of the
      # consumer.
      def stop
        @messages.stop
      end

      # drain stops pulling, and passes the messages already received, and
      # those still on their way, to the block before it stops.
      def drain
        @messages.drain
      end

      # closed? tells whether the consumption stopped: it was stopped, or
      # drained of all its messages, or an error stopped it.
      # @return [Boolean]
      def closed?
        @lock.synchronize { @done }
      end

      # wait_closed waits until the consumption stopped.
      # @param timeout [Float] How long to wait, for good by default.
      # @return [Boolean] Whether it stopped.
      def wait_closed(timeout = nil)
        deadline = MonotonicTime.now + timeout if timeout
        @lock.synchronize do
          until @done
            remaining = deadline && deadline - MonotonicTime.now
            return false if remaining && remaining <= 0

            @done_cond.wait(remaining)
          end
          true
        end
      end

      # @!visibility private
      def messages_context
        @messages
      end

      # takes_context? tells whether an error handler takes two arguments,
      # the context and the error, rather than the error only: whether it
      # requires two, or more with optional ones.
      # @!visibility private
      def self.takes_context?(handler)
        arity = handler.respond_to?(:arity) ? handler.arity : handler.method(:call).arity
        arity == 2 || arity <= -3
      end

      private

      def run
        loop do
          begin
            msg = @messages.next
          rescue Error::MsgIteratorClosed
            report(NATS::IO::ConnectionClosedError.new("nats: connection closed")) if @messages.closed_reason == :connection_closed
            break
          rescue Error::NoHeartbeat => e
            report(e)
            next
          rescue => e
            # A deleted consumer or invalid pull closed the iterator.
            report(e)
            break if @messages.closed?
            next
          end

          begin
            @handler.call(msg)
          rescue => e
            report(e)
          end
        end
      ensure
        @lock.synchronize do
          @done = true
          @done_cond.broadcast
        end
      end

      # report passes an error to the error handler, or else to the error
      # callback of the connection. A handler that takes two arguments gets
      # the context too, like ConsumeErrHandlerFunc of nats.go.
      def report(err)
        if @error_handler
          if ConsumeContext.takes_context?(@error_handler)
            @error_handler.call(self, err)
          else
            @error_handler.call(err)
          end
        else
          @nc.synchronize { @nc.send(:err_cb_call, @nc, err, nil) }
        end
      rescue => e
        e
      end
    end

    # PushConsumeContext runs the consumption of a push consumer, which
    # passes each message that the consumer delivers to a block, like
    # Consume of a PushConsumer of the nats.go jetstream package. It takes
    # the control messages of the consumer as the subscriptions of
    # {JetStream#subscribe} do: it answers the flow control requests, and,
    # when the consumer has idle heartbeats, reports a
    # NATS::JetStream::Error::NoHeartbeat whenever nothing came for two of
    # them. As in nats.go, the messages are not acked for the block. See
    # {PushConsumer#consume}.
    #
    # @!visibility public
    class PushConsumeContext < ConsumeContext
      # @param js [NATS::JetStream] The context of the consumer.
      # @param stream [String] Name of the stream of the consumer.
      # @param info [JetStream::API::ConsumerInfo] Info of the consumer.
      # @!visibility private
      def initialize(js, stream, info, params, handler)
        @handler = handler
        @error_handler = params[:error_handler]
        unless @error_handler.nil? || @error_handler.respond_to?(:call)
          raise ArgumentError.new("nats: invalid error_handler #{@error_handler.inspect}, expected a callable")
        end

        @opts = params.slice(:error_handler)
        @nc = js.nc
        @done = false
        @closing = false
        @stopped = false
        @lock = Monitor.new
        @done_cond = @lock.new_cond
        config = info.config
        @sub = @nc.subscribe(config.deliver_subject, queue: config.deliver_group) { |msg| deliver(msg) }
        @sub.on_close { |_| closed! }
        @sub.extend(PushSubscription)
        @sub.jsi = JS::Sub.new(js: js, stream: stream, consumer: info.name)
        @sub.send(:start_control, config.idle_heartbeat, on_error: ->(err) { report(control_error(err)) })
      end

      # The options given.
      # @return [Hash]
      attr_reader :opts

      # stop unsubscribes, and stops passing messages to the block, once
      # it returns, if it runs. The messages already received are dropped,
      # and the server delivers them again after the ack_wait of the
      # consumer.
      def stop
        return unless closing!(stopped: true)

        @sub.unsubscribe
      rescue NATS::IO::Error
        # The connection closed, which closed the subscription too.
      end

      # drain unsubscribes, and passes the messages already received to the
      # block before it stops.
      def drain
        return unless closing!(stopped: false)

        @sub.drain
      rescue NATS::IO::Error
        # The connection closed, which closed the subscription too.
      end

      # @!visibility private
      def messages_context
        nil
      end

      private

      # closing! marks the consumption as stopping, once, and stops checking
      # for heartbeats, which no longer come.
      def closing!(stopped:)
        @lock.synchronize do
          return false if @closing

          @closing = true
          @stopped = stopped
        end
        @sub.send(:stop_control)
        true
      end

      # deliver passes a message to the block, unless stopped, and deals
      # with the statuses of the consumer as nats.go does: a deleted
      # consumer stops the consumption.
      def deliver(msg)
        return if @lock.synchronize { @stopped }

        if JS.is_status_msg(msg)
          return unless msg.header[JS::Header::Status] == JS::Status::Conflict

          err = JS.from_msg(msg)
          report(err)
          stop if err.is_a?(Error::ConsumerDeleted)
          return
        end

        @handler.call(msg)
      rescue => e
        report(e)
      end

      # control_error is the error to report for one of the subscription:
      # its consumer not being active means that the heartbeats stopped.
      def control_error(err)
        return err unless err.is_a?(Error::ConsumerNotActive)

        Error::NoHeartbeat.new("nats: no heartbeat received")
      end

      # closed! is called once the subscription is closed: unsubscribed,
      # drained, or closed with the connection.
      def closed!
        @sub.send(:stop_control)
        @lock.synchronize do
          @done = true
          @done_cond.broadcast
        end
      end
    end
  end
end
