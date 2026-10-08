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
    # BatchAck is the API response from a committed atomic batch, like the
    # BatchAck of orbit.go jetstreamext.
    #
    # @!attribute [stream] stream
    #   @return [String] Name of the stream that stored the batch.
    # @!attribute [seq] seq
    #   @return [Integer] Stream sequence of the last message of the batch.
    # @!attribute [domain] domain
    #   @return [String] JetStream Domain that processed the batch.
    # @!attribute [val] val
    #   @return [String] Value of the counter, for a stream with allow_msg_counter.
    # @!attribute [batch] batch
    #   @return [String] ID of the batch.
    # @!attribute [count] count
    #   @return [Integer] Number of messages the batch stored.
    BatchAck = Struct.new(:stream, :seq, :domain, :val, :batch, :count,
      keyword_init: true) do
      # Fields added by newer servers are ignored.
      def initialize(opts = {})
        super(**opts.slice(*members))
      end
    end

    # BatchPublisher publishes an atomic batch of messages to a stream, like
    # the BatchPublisher of orbit.go jetstreamext: the stream stores all the
    # messages of the batch once it is committed, or none of them. The
    # stream needs allow_atomic (requires nats-server v2.12.0).
    #
    # Each message is published as it is added, with the batch headers. The
    # batch is committed with a last message (commit), or without one
    # (close, requires nats-server v2.14.0), and abandoned with discard,
    # after which the server drops what it got once the batch times out.
    #
    # Messages take these options:
    # - :ttl, the whole seconds after which the stream removes the message,
    #   or :never, like the ttl option of JetStream#publish;
    # - :stream, the stream that is expected to store the message;
    # - :msg_id, the Nats-Msg-Id of the message, which no other message of
    #   the batch can have;
    # - :expected_last_seq, the sequence that the last message of the
    #   stream is expected to have;
    # - :expected_last_subject_seq, the one that the last message on the
    #   subject of the message is expected to have, or on
    #   :expected_last_subject when that is given too.
    # An invalid option raises ArgumentError before anything is sent.
    #
    # @example
    #   batch = js.new_batch_publisher
    #   batch.add("orders.1", "one")
    #   batch.add("orders.2", "two")
    #   ack = batch.commit("orders.3", "three")
    #   ack.count # => 3
    class BatchPublisher
      include MonitorMixin

      # The value of Header::BATCH_COMMIT that commits a batch without
      # storing the message that carries it (requires nats-server v2.14.0),
      # like BatchCommitEOB of orbit.go.
      BATCH_COMMIT_EOB = "eob"

      # @return [String] The ID of the batch.
      attr_reader :id

      # @param js [NATS::JetStream] The JetStream context.
      # @param ack_first [Boolean] Whether to wait for the server to accept
      #   the first message, as by default, before adding more.
      # @param ack_every [Integer] Waits for the server to accept every so
      #   many messages, or never with 0, the default.
      # @param ack_timeout [Float] Seconds to wait for each of those acks,
      #   by default the timeout of the JetStream context.
      def initialize(js, ack_first: true, ack_every: 0, ack_timeout: nil)
        super()
        @js = js
        @nc = js.nc
        @flow = BatchPublisher.flow_control(js, ack_first, ack_every, ack_timeout)
        @id = NATS::NUID.next
        @sequence = 0
        @subject = nil
        @closed = false
      end

      # Publishes a message of the batch.
      #
      # @param subject [String] The subject of the message.
      # @param data [String] The payload of the message.
      # @param header [Hash] The headers of the message.
      # @param opts [Hash] The options of the message, see BatchPublisher.
      # @raise [NATS::JetStream::Error::BatchClosed] When the batch was
      #   committed or discarded.
      # @raise [NATS::JetStream::Error::APIError] When the server refuses a
      #   message whose ack it waits for.
      def add(subject, data = "", header: nil, **opts)
        add_msg(NATS::Msg.new(subject: subject, data: data, header: header), **opts)
      end

      # Publishes a message of the batch, like add. The message is not
      # changed.
      def add_msg(msg, **opts)
        synchronize do
          raise Error::BatchClosed if @closed

          out = batch_msg(msg, opts, @sequence + 1)
          @sequence += 1
          @subject ||= out.subject

          if needs_ack?(@sequence)
            BatchPublisher.flow_request(@nc, out, @flow[:ack_timeout])
          else
            @nc.publish_msg(out)
          end
          nil
        end
      end

      # Publishes the last message of the batch, which commits it.
      #
      # @param subject [String] The subject of the message.
      # @param data [String] The payload of the message.
      # @param header [Hash] The headers of the message.
      # @param timeout [Float] Seconds to wait for the ack, by default the
      #   timeout of the JetStream context.
      # @param opts [Hash] The options of the message, see BatchPublisher.
      # @return [NATS::JetStream::BatchAck]
      # @raise [NATS::JetStream::Error::APIError] When the server refuses
      #   the batch, for example with a
      #   NATS::JetStream::Error::BatchPublishIncomplete.
      # @raise [NATS::JetStream::Error::InvalidBatchAck] When the ack is not
      #   the ack of the batch.
      # @raise [NATS::Timeout] When the ack does not come in time, after
      #   which the batch stays open.
      def commit(subject, data = "", header: nil, timeout: nil, **opts)
        commit_msg(NATS::Msg.new(subject: subject, data: data, header: header), timeout: timeout, **opts)
      end

      # Publishes the last message of the batch, which commits it, like
      # commit. The message is not changed.
      def commit_msg(msg, timeout: nil, **opts)
        synchronize do
          raise Error::BatchClosed if @closed

          out = batch_msg(msg, opts, @sequence + 1, "1")
          @sequence += 1
          request_ack(out, timeout, @sequence)
        end
      end

      # Commits the batch without another message: the server commits the
      # messages added so far, without storing the end-of-batch marker
      # that close publishes (requires nats-server v2.14.0).
      #
      # @param timeout [Float] Seconds to wait for the ack, by default the
      #   timeout of the JetStream context.
      # @return [NATS::JetStream::BatchAck]
      # @raise [NATS::JetStream::Error::EmptyBatch] When no message was added.
      def close(timeout: nil)
        synchronize do
          raise Error::BatchClosed if @closed
          raise Error::EmptyBatch if @sequence.zero?

          out = NATS::Msg.new(subject: @subject, data: "", header: {
            Header::BATCH_ID => @id,
            Header::BATCH_SEQUENCE => (@sequence + 1).to_s,
            Header::BATCH_COMMIT => BATCH_COMMIT_EOB
          })
          request_ack(out, timeout, @sequence)
        end
      end

      # Abandons the batch without committing it. The server drops the
      # messages it got once the batch times out.
      #
      # @raise [NATS::JetStream::Error::BatchClosed] When the batch was
      #   already committed or discarded.
      def discard
        synchronize do
          raise Error::BatchClosed if @closed

          @closed = true
          nil
        end
      end

      # @return [Integer] The number of messages added to the batch.
      def size
        synchronize { @sequence }
      end

      # @return [Boolean] Whether the batch was committed or discarded.
      def closed?
        synchronize { @closed }
      end

      class << self
        # @api private
        def flow_control(js, ack_first, ack_every, ack_timeout)
          unless [true, false].include?(ack_first)
            raise ArgumentError.new("nats: invalid ack_first #{ack_first.inspect}, expected true or false")
          end
          unless ack_every.is_a?(Integer) && ack_every >= 0
            raise ArgumentError.new("nats: invalid ack_every #{ack_every.inspect}, expected an Integer from 0")
          end
          if !ack_timeout.nil? && !(ack_timeout.is_a?(Numeric) && ack_timeout.positive?)
            raise ArgumentError.new("nats: invalid ack_timeout #{ack_timeout.inspect}, expected seconds above 0")
          end

          {ack_first: ack_first, ack_every: ack_every, ack_timeout: ack_timeout || js.opts[:timeout]}
        end

        # Sends a message of a batch and waits for the server to accept it.
        # @api private
        def flow_request(nc, msg, timeout)
          resp = request(nc, msg, timeout)
          return if resp.data.to_s.empty?

          result = begin
            JSON.parse(resp.data, symbolize_names: true)
          rescue JSON::ParserError
            raise Error::InvalidBatchAck
          end
          raise JS.from_error(result[:error]) if result.is_a?(Hash) && result[:error]
        end

        # @api private
        def request(nc, msg, timeout)
          nc.request_msg(msg, timeout: timeout)
        rescue NATS::IO::NoRespondersError
          raise Error::NoStreamResponse.new("nats: no response from stream")
        end

        # Decodes the ack of a committed batch.
        # @api private
        def batch_ack(resp, id, count)
          result = begin
            JSON.parse(resp.data, symbolize_names: true)
          rescue JSON::ParserError
            raise Error::InvalidBatchAck
          end
          raise Error::InvalidBatchAck unless result.is_a?(Hash)
          raise JS.from_error(result[:error]) if result[:error]

          ack = BatchAck.new(result)
          raise Error::InvalidBatchAck if ack.stream.to_s.empty? || ack.batch != id || ack.count != count

          ack
        end

        # The headers of the options of a batch message.
        # @api private
        def msg_header(js, ttl: nil, stream: nil, msg_id: nil, expected_last_seq: nil,
          expected_last_subject_seq: nil, expected_last_subject: nil)
          header = {}
          header[Header::MSG_TTL] = js.send(:msg_ttl, ttl) unless ttl.nil?
          header[Header::EXPECTED_STREAM] = option_string(:stream, stream) unless stream.nil?
          header[Header::MSG_ID] = option_string(:msg_id, msg_id) unless msg_id.nil?
          header[Header::EXPECTED_LAST_SEQUENCE] = option_seq(:expected_last_seq, expected_last_seq) unless expected_last_seq.nil?
          unless expected_last_subject.nil?
            if expected_last_subject_seq.nil?
              raise ArgumentError.new("nats: expected_last_subject needs expected_last_subject_seq")
            end

            header[Header::EXPECTED_LAST_SUBJECT_SEQUENCE_SUBJECT] = option_string(:expected_last_subject, expected_last_subject)
          end
          unless expected_last_subject_seq.nil?
            header[Header::EXPECTED_LAST_SUBJECT_SEQUENCE] = option_seq(:expected_last_subject_seq, expected_last_subject_seq)
          end
          header
        end

        def option_string(name, value)
          return value if value.is_a?(String) && !value.empty?

          raise ArgumentError.new("nats: invalid #{name} #{value.inspect}, expected a non-empty String")
        end

        def option_seq(name, value)
          return value.to_s if value.is_a?(Integer) && value >= 0

          raise ArgumentError.new("nats: invalid #{name} #{value.inspect}, expected an Integer from 0")
        end
      end

      private

      def needs_ack?(seq)
        (@flow[:ack_first] && seq == 1) ||
          (@flow[:ack_every].positive? && (seq % @flow[:ack_every]).zero?)
      end

      def request_ack(msg, timeout, count)
        resp = BatchPublisher.request(@nc, msg, timeout || @js.opts[:timeout])
        # Whatever the server answered, it ended the batch.
        @closed = true
        BatchPublisher.batch_ack(resp, @id, count)
      end

      # A copy of msg with the headers of the batch and of the options.
      def batch_msg(msg, opts, seq, commit = nil)
        raise TypeError, "nats: expected NATS::Msg, got #{msg.class.name}" unless msg.is_a?(NATS::Msg)

        header = (msg.header || {}).merge(BatchPublisher.msg_header(@js, **opts))
        header.delete(Header::BATCH_COMMIT)
        header[Header::BATCH_ID] = @id
        header[Header::BATCH_SEQUENCE] = seq.to_s
        header[Header::BATCH_COMMIT] = commit if commit

        NATS::Msg.new(subject: msg.subject, data: msg.data || "", header: header)
      end
    end

    # Returns a BatchPublisher, which publishes an atomic batch of messages
    # to a stream, like NewBatchPublisher of orbit.go jetstreamext.
    #
    # @param opts [Hash] The flow control: :ack_first, :ack_every and
    #   :ack_timeout, see BatchPublisher#initialize.
    # @return [NATS::JetStream::BatchPublisher]
    def new_batch_publisher(**opts)
      BatchPublisher.new(self, **opts)
    end

    # Publishes messages as an atomic batch, the last of which commits it,
    # like PublishMsgBatch of orbit.go jetstreamext. The messages are not
    # changed. The stream needs allow_atomic (requires nats-server v2.12.0).
    #
    # @param messages [Array<NATS::Msg>] The messages of the batch.
    # @param timeout [Float] Seconds to wait for the ack of the commit, by
    #   default the timeout of the JetStream context.
    # @param opts [Hash] The flow control: :ack_first, :ack_every and
    #   :ack_timeout, see BatchPublisher#initialize.
    # @return [NATS::JetStream::BatchAck]
    # @raise [NATS::JetStream::Error::EmptyBatch] When there are no messages.
    def publish_msg_batch(messages, timeout: nil, **opts)
      messages = Array(messages)
      raise Error::EmptyBatch if messages.empty?

      batch = BatchPublisher.new(self, **opts)
      messages[0...-1].each { |msg| batch.add_msg(msg) }
      batch.commit_msg(messages.last, timeout: timeout)
    end
  end
end
