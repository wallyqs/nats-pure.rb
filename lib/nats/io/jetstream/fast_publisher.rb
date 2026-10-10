# frozen_string_literal: true

# Copyright 2026 The NATS Authors
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

require "json"
require "monitor"

module NATS
  class JetStream
    # FastPubAck is what FastPublisher#add returns, like the FastPubAck of
    # orbit.go jetstreamext.
    #
    # @!attribute [batch_seq] batch_seq
    #   @return [Integer] Sequence of the message in the batch.
    # @!attribute [ack_seq] ack_seq
    #   @return [Integer] Highest sequence of the batch that the server
    #     acknowledged. Without continue_on_gap, the stream stored every
    #     message up to it.
    FastPubAck = Struct.new(:batch_seq, :ack_seq, keyword_init: true)

    # FastPublisher publishes a fast-ingest batch of messages to a stream,
    # like the FastPublisher of orbit.go jetstreamext, and on the same wire.
    # Unlike an atomic batch, the stream stores the messages as they come,
    # and acknowledges them every so many messages, which the server adjusts.
    # The publisher waits for the ack of the first message, and stalls when
    # more than max_outstanding_acks acks are outstanding. The batch ends
    # with commit, commit_msg or close. The stream needs allow_batched
    # (requires nats-server v2.14.0).
    #
    # The messages take the options of the messages of a BatchPublisher.
    #
    # A FastPublisher is not meant to be used from several threads at once.
    #
    # @example
    #   fast = js.new_fast_publisher(error_handler: ->(e) { warn e.message })
    #   1000.times { |i| fast.add("metrics.cpu", i.to_s) }
    #   ack = fast.close
    #   ack.count # => 1000
    class FastPublisher
      include MonitorMixin

      DEFAULT_FLOW = 100
      DEFAULT_MAX_OUTSTANDING_ACKS = 2

      # The operations that the reply subject of a message tells the server.
      OP_START = 0
      OP_APPEND = 1
      OP_COMMIT = 2
      OP_COMMIT_EOB = 3
      OP_PING = 4
      private_constant :OP_START, :OP_APPEND, :OP_COMMIT, :OP_COMMIT_EOB, :OP_PING

      # The suffix of the reply subject of a fast batch message.
      SUFFIX = "$FI"
      private_constant :SUFFIX

      # @return [String] The ID of the batch.
      attr_reader :id

      # @param js [NATS::JetStream] The JetStream context.
      # @param flow [Integer] The number of messages after which the server
      #   first acknowledges them, from 1 to 65535, 100 by default. The
      #   server adjusts it, up to this value.
      # @param max_outstanding_acks [Integer] The number of acks that can be
      #   outstanding before add waits for one, from 1 to 65535, 2 by
      #   default.
      # @param ack_timeout [Float] Seconds to wait for an ack, by default the
      #   timeout of the JetStream context. While it waits, the publisher
      #   pings the server every third of it, which resends the last ack.
      # @param continue_on_gap [Boolean] Whether the batch goes on when the
      #   server finds that messages did not reach it, which are then lost,
      #   instead of ending, as by default.
      # @param error_handler [#call] Called with the errors that the server
      #   reports out of band: a NATS::JetStream::Error::FastBatchGapDetected,
      #   the NATS::JetStream::Error::APIError for a message the stream did
      #   not store, with seq set to its batch sequence, and the error of a
      #   batch that ended while no call waited for it.
      def initialize(js, flow: DEFAULT_FLOW, max_outstanding_acks: DEFAULT_MAX_OUTSTANDING_ACKS,
        ack_timeout: nil, continue_on_gap: false, error_handler: nil)
        super()
        check_uint16(:flow, flow)
        check_uint16(:max_outstanding_acks, max_outstanding_acks)
        if !ack_timeout.nil? && !(ack_timeout.is_a?(Numeric) && ack_timeout.positive?)
          raise ArgumentError.new("nats: invalid ack_timeout #{ack_timeout.inspect}, expected seconds above 0")
        end
        unless [true, false].include?(continue_on_gap)
          raise ArgumentError.new("nats: invalid continue_on_gap #{continue_on_gap.inspect}, expected true or false")
        end
        if error_handler && !error_handler.respond_to?(:call)
          raise ArgumentError.new("nats: invalid error_handler #{error_handler.inspect}, expected a callable")
        end

        @js = js
        @nc = js.nc
        @flow = flow
        @max_outstanding_acks = max_outstanding_acks
        @ack_timeout = ack_timeout || js.opts[:timeout]
        @error_handler = error_handler
        @inbox = @nc.new_inbox
        # The server takes the last token of the inbox as the batch ID.
        @id = @inbox.split(".").last
        # Fixed when the publisher is made, like orbit.go, even once the
        # server changes the flow.
        @reply_prefix = "#{@inbox}.#{flow}.#{continue_on_gap ? "ok" : "fail"}."
        @cond = new_cond

        @sequence = 0
        @ack_sequence = 0
        @subject = nil
        @closed = false
        @sub = nil
        @first = nil
        @commit = nil
      end

      # Publishes a message of the batch. The first waits for the server to
      # accept the batch; the others wait only while too many acks are
      # outstanding.
      #
      # @param subject [String] The subject of the message.
      # @param data [String] The payload of the message.
      # @param header [Hash] The headers of the message.
      # @param opts [Hash] The options of the message, see BatchPublisher.
      # @return [NATS::JetStream::FastPubAck]
      # @raise [NATS::JetStream::Error::BatchClosed] When the batch ended.
      # @raise [NATS::JetStream::Error::APIError] When the server refuses
      #   the first message, as for a stream without allow_batched, with a
      #   NATS::JetStream::Error::FastBatchNotEnabled.
      # @raise [NATS::Timeout] When an ack does not come in time, which ends
      #   the batch.
      def add(subject, data = "", header: nil, **opts)
        add_msg(NATS::Msg.new(subject: subject, data: data, header: header), **opts)
      end

      # Publishes a message of the batch, like add. The message is not
      # changed.
      def add_msg(msg, **opts)
        synchronize do
          raise Error::BatchClosed if @closed

          out = fast_msg(msg, opts)
          @sequence += 1
          (@sequence == 1) ? add_first(out) : add_next(out)
        end
      end

      # Publishes the last message of the batch, which ends it.
      #
      # @param subject [String] The subject of the message.
      # @param data [String] The payload of the message.
      # @param header [Hash] The headers of the message.
      # @param timeout [Float] Seconds to wait for the ack, by default the
      #   ack_timeout of the publisher.
      # @param opts [Hash] The options of the message, see BatchPublisher.
      # @return [NATS::JetStream::BatchAck]
      # @raise [NATS::JetStream::Error::APIError] When the server refuses
      #   the batch.
      # @raise [NATS::JetStream::Error::InvalidBatchAck] When the ack is not
      #   the ack of a stream.
      # @raise [NATS::Timeout] When the ack does not come in time.
      def commit(subject, data = "", header: nil, timeout: nil, **opts)
        commit_msg(NATS::Msg.new(subject: subject, data: data, header: header), timeout: timeout, **opts)
      end

      # Publishes the last message of the batch, which ends it, like commit.
      # The message is not changed.
      def commit_msg(msg, timeout: nil, **opts)
        synchronize do
          raise Error::BatchClosed if @closed

          end_batch(fast_msg(msg, opts), OP_COMMIT, timeout)
        end
      end

      # Ends the batch without another message, with an end-of-batch marker
      # that the stream does not store.
      #
      # @param timeout [Float] Seconds to wait for the ack, by default the
      #   ack_timeout of the publisher.
      # @return [NATS::JetStream::BatchAck]
      # @raise [NATS::JetStream::Error::EmptyBatch] When no message was added.
      def close(timeout: nil)
        synchronize do
          raise Error::EmptyBatch if @sequence.zero?
          raise Error::BatchClosed if @closed

          end_batch(NATS::Msg.new(subject: @subject, data: ""), OP_COMMIT_EOB, timeout)
        end
      end

      # @return [Boolean] Whether the batch ended.
      def closed?
        synchronize { @closed }
      end

      private

      def check_uint16(name, value)
        return if value.is_a?(Integer) && value.between?(1, 65_535)

        raise ArgumentError.new("nats: invalid #{name} #{value.inspect}, expected an Integer from 1 to 65535")
      end

      # The reply subject of a message of the batch:
      # <inbox>.<flow>.<gap mode>.<batch sequence>.<operation>.$FI
      def reply_subject(seq, op)
        "#{@reply_prefix}#{seq}.#{op}.#{SUFFIX}"
      end

      # A copy of msg with the headers of the options.
      def fast_msg(msg, opts)
        raise TypeError, "nats: expected NATS::Msg, got #{msg.class.name}" unless msg.is_a?(NATS::Msg)

        header = msg.header
        unless opts.empty?
          options = BatchPublisher.msg_header(@js, **opts)
          header = (header || {}).merge(options) unless options.empty?
        end
        NATS::Msg.new(subject: msg.subject, data: msg.data || "", header: header)
      end

      def subscribe
        @sub ||= @nc.subscribe("#{@inbox}.>") { |msg| handle_reply(msg) }
      end

      def unsubscribe
        sub = @sub
        @sub = nil
        sub&.unsubscribe
      rescue NATS::IO::Error
        nil
      end

      # Publishes the first message and waits for the server to accept it.
      def add_first(out)
        out.reply = reply_subject(1, OP_START)
        subscribe
        @first = {}
        begin
          @nc.publish_msg(out)
        rescue
          finish
          raise
        end

        deadline = MonotonicTime.now + @ack_timeout
        @cond.wait(deadline - MonotonicTime.now) while @first.empty? && MonotonicTime.now < deadline
        first = @first
        @first = nil

        if first.key?(:ack)
          @subject = out.subject
          return FastPubAck.new(batch_seq: 1, ack_seq: first[:ack])
        end

        finish
        raise first[:error] if first.key?(:error)
        raise NATS::Timeout.new("nats: batch message 1 ack timeout")
      end

      # Publishes a message after the first, and waits while too many acks
      # are outstanding.
      def add_next(out)
        seq = @sequence
        out.reply = reply_subject(seq, OP_APPEND)
        @nc.publish_msg(out)

        if must_wait?
          unless wait_for(@ack_timeout) { !must_wait? || @closed }
            finish
            raise NATS::Timeout.new("nats: batch message #{seq} ack timeout; current ack sequence: #{@ack_sequence}")
          end
          # The server ended the batch while the message waited, as after a gap.
          raise Error::BatchClosed if @closed
        end

        FastPubAck.new(batch_seq: seq, ack_seq: @ack_sequence)
      end

      def must_wait?
        @ack_sequence + @flow * @max_outstanding_acks <= @sequence
      end

      # Publishes the message that ends the batch and waits for its ack.
      def end_batch(out, op, timeout)
        @sequence += 1
        out.reply = reply_subject(@sequence, op)
        subscribe
        @commit = {}
        @nc.publish_msg(out)

        done = wait_for(timeout || @ack_timeout) { !@commit.empty? }
        commit = @commit
        finish
        raise NATS::Timeout.new("nats: batch commit ack timeout") unless done

        result = commit[:ack]
        raise JS.from_error(result[:error]) if result[:error]
        raise Error::InvalidBatchAck if result[:stream].to_s.empty?

        BatchAck.new(result)
      end

      # Waits, holding the lock between waits, until the block is true, and
      # pings the server every third of the timeout to recover lost acks.
      # Returns whether the block became true in time.
      def wait_for(timeout)
        deadline = MonotonicTime.now + timeout
        interval = timeout / 3.0
        next_ping = MonotonicTime.now + interval
        loop do
          return true if yield

          now = MonotonicTime.now
          return false if now >= deadline

          if now >= next_ping
            ping
            next_ping = now + interval
          end
          @cond.wait([deadline, next_ping].min - now)
        end
      end

      # A ping resends the last ack of the batch.
      def ping
        return unless @subject

        @nc.publish(@subject, "", reply_subject(@sequence, OP_PING))
      end

      def finish
        @closed = true
        @first = nil
        @commit = nil
        unsubscribe
      end

      # Handles what the server sends to the reply subjects of the batch.
      def handle_reply(msg)
        handled = []
        synchronize do
          reply = begin
            JSON.parse(msg.data, symbolize_names: true)
          rescue JSON::ParserError
            handled << Error::InvalidBatchAck.new
            nil
          end
          next unless reply.is_a?(Hash)

          case reply[:type]
          when "gap"
            handled << Error::FastBatchGapDetected.new(reply[:last_seq], reply[:seq])
          when "ack"
            @flow = reply[:msgs] if reply[:msgs].is_a?(Integer) && reply[:msgs].positive?
            @ack_sequence = reply[:seq].to_i
            @first[:ack] = @ack_sequence if @first && @first.empty?
            @cond.broadcast
          when "err"
            error = JS.from_error(reply[:error] || {})
            error.seq = reply[:seq] if error.respond_to?(:seq=)
            handled << error
          else
            # Without a type, the reply is the ack of the end of the batch.
            @closed = true
            if @commit
              @commit[:ack] = reply
            elsif @first
              # The server refused the first message.
              @first[:error] = reply[:error] ? JS.from_error(reply[:error]) : Error::InvalidBatchAck.new
            else
              # The batch ended while no call waited for it, as after a gap.
              unsubscribe
              handled << JS.from_error(reply[:error]) if reply[:error]
            end
            @cond.broadcast
          end
        end
        report(handled)
      end

      def report(errors)
        return unless @error_handler

        errors.each { |error| @error_handler.call(error) }
      end
    end

    # Returns a FastPublisher, which publishes a fast-ingest batch of
    # messages to a stream with allow_batched (requires nats-server
    # v2.14.0), like NewFastPublisher of orbit.go jetstreamext.
    #
    # @param opts [Hash] :flow, :max_outstanding_acks, :ack_timeout,
    #   :continue_on_gap and :error_handler, see FastPublisher#initialize.
    # @return [NATS::JetStream::FastPublisher]
    def new_fast_publisher(**opts)
      FastPublisher.new(self, **opts)
    end
  end
end
