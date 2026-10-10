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
require "time"

module NATS
  class JetStream
    module Manager
      # The header with the number of messages that a batched direct get
      # has yet to send.
      NUM_PENDING_HEADER = "Nats-Num-Pending"

      # get_batch gets up to batch messages of a stream at once, with a
      # batched direct get, like GetBatch of orbit.go jetstreamext. The
      # stream needs allow_direct (requires nats-server v2.11.0).
      #
      # The messages come from the first one of the stream on, or from
      # seq or start_time, optionally only those on subject, and up to
      # max_bytes. They are yielded as the server sends them, until it
      # ends the batch; without a block they are returned.
      #
      # @example
      #   js.get_batch("ORDERS", 10, subject: "orders.new").each do |msg|
      #     puts "#{msg.seq}: #{msg.data}"
      #   end
      #
      # @param stream [String] The name of the stream.
      # @param batch [Integer] The most messages to get.
      # @param seq [Integer] The stream sequence to start from, 1 unless
      #   start_time is given.
      # @param subject [String] Gets only the messages on this subject,
      #   which can have wildcards.
      # @param start_time [Time, String] Starts from the first message
      #   stored from this time on.
      # @param max_bytes [Integer] The most bytes to get; the server ends
      #   the batch once the messages it sent reached them.
      # @param timeout [Float] Seconds to wait for each message, by default
      #   the timeout of the JetStream context.
      # @yield [msg] Each message, if a block is given.
      # @return [Array<JetStream::API::RawStreamMsg>, nil] The messages,
      #   with their seq as an Integer, or nil with a block.
      # @raise [ArgumentError] For an invalid option, like ErrInvalidOption
      #   of orbit.go, before anything is sent.
      # @raise [NATS::JetStream::Error::NoMessages] When there is no
      #   message to get.
      # @raise [NATS::JetStream::Error::BatchUnsupported] When the server
      #   does not get messages in batches.
      # @raise [NATS::JetStream::Error::ServiceUnavailable] When the stream
      #   does not exist or does not have allow_direct.
      # @raise [NATS::Timeout] When the server does not end the batch in time.
      def get_batch(stream, batch, seq: nil, subject: nil, start_time: nil, max_bytes: nil, timeout: nil, &block)
        check_direct_stream(stream)
        batch_option(:batch, batch)
        batch_option(:seq, seq) unless seq.nil?
        batch_option(:max_bytes, max_bytes) unless max_bytes.nil?
        if seq && start_time
          raise ArgumentError.new("nats: invalid option: cannot set both start time and sequence number")
        end

        req = {
          seq: seq || (1 if start_time.nil?),
          next_by_subj: subject,
          batch: batch,
          max_bytes: max_bytes,
          start_time: (rfc3339(start_time) unless start_time.nil?)
        }
        direct_get_batch(stream, req.compact, timeout, &block)
      end

      # get_last_msgs_for gets the last message on each of subjects of a
      # stream, with a batched direct get, like GetLastMsgsFor of orbit.go
      # jetstreamext. The stream needs allow_direct (requires nats-server
      # v2.11.0).
      #
      # The messages are those that were the last ones up to the stream
      # sequence up_to_seq, or up to up_to_time, and come in the order of
      # the stream. They are yielded as the server sends them, until it
      # ends the batch; without a block they are returned.
      #
      # @example
      #   js.get_last_msgs_for("ORDERS", ["orders.new", "orders.paid"]).map(&:data)
      #
      # @param stream [String] The name of the stream.
      # @param subjects [Array<String>] The subjects, which can have
      #   wildcards.
      # @param up_to_seq [Integer] The last stream sequence to look at.
      # @param up_to_time [Time, String] Looks at the messages stored before
      #   this time.
      # @param batch [Integer] The most messages to get.
      # @param timeout [Float] Seconds to wait for each message, by default
      #   the timeout of the JetStream context.
      # @yield [msg] Each message, if a block is given.
      # @return [Array<JetStream::API::RawStreamMsg>, nil] The messages,
      #   with their seq as an Integer, or nil with a block.
      # @raise [ArgumentError] Without subjects (ErrSubjectRequired of
      #   orbit.go) or for an invalid option (ErrInvalidOption), before
      #   anything is sent.
      # @raise [NATS::JetStream::Error::NoMessages] When there is no
      #   message to get.
      def get_last_msgs_for(stream, subjects, up_to_seq: nil, up_to_time: nil, batch: nil, timeout: nil, &block)
        check_direct_stream(stream)
        subjects = Array(subjects)
        raise ArgumentError.new("nats: at least one subject is required") if subjects.empty?
        unless subjects.all? { |subj| subj.is_a?(String) && !subj.empty? }
          raise ArgumentError.new("nats: invalid option: subjects must be non-empty Strings")
        end
        batch_option(:up_to_seq, up_to_seq) unless up_to_seq.nil?
        batch_option(:batch, batch) unless batch.nil?
        if up_to_seq && up_to_time
          raise ArgumentError.new("nats: invalid option: cannot set both up to sequence and up to time")
        end

        req = {
          multi_last: subjects,
          batch: batch,
          up_to_seq: up_to_seq,
          up_to_time: (rfc3339(up_to_time) unless up_to_time.nil?)
        }
        direct_get_batch(stream, req.compact, timeout, &block)
      end

      private

      def check_direct_stream(stream)
        return unless stream.nil? || !stream.is_a?(String) || stream.empty? || stream.match?(/[.*> \t\r\n]/)

        raise JetStream::Error::InvalidStreamName.new("nats: invalid stream name")
      end

      def batch_option(name, value)
        return if value.is_a?(Integer) && value.positive?

        raise ArgumentError.new("nats: invalid option: #{name} has to be an Integer greater than 0, got #{value.inspect}")
      end

      # Requests a batch from the direct get API of the stream and reads
      # the messages from its own inbox, until the end-of-batch status.
      def direct_get_batch(stream, req, timeout)
        timeout ||= @opts[:timeout]
        msgs = [] unless block_given?
        sub = @nc.subscribe(@nc.new_inbox)
        @nc.publish("#{@prefix}.DIRECT.GET.#{stream}", req.to_json, sub.subject)

        loop do
          msg = sub.next_msg(timeout: timeout)
          break if end_of_batch?(msg)

          raw_msg = batch_get_msg(msg)
          block_given? ? yield(raw_msg) : msgs << raw_msg
        end
        msgs
      ensure
        begin
          sub&.unsubscribe
        rescue NATS::IO::Error
          nil
        end
      end

      # The end of a batch is a status 204 with the description EOB.
      def end_of_batch?(msg)
        msg.data.to_s.empty? && batch_header(msg, JS::Header::Status) == "204" &&
          batch_header(msg, JS::Header::Desc) == "EOB"
      end

      # A message of a batch, like orbit.go's convertDirectGetMsgResponseToMsg.
      def batch_get_msg(msg)
        status = batch_header(msg, JS::Header::Status)
        if status && msg.data.to_s.empty?
          raise JetStream::Error::NoMessages if status == "404"

          # A request the server refuses, such as a 408 Bad Request.
          raise JS.from_msg(msg)
        end
        if msg.header.nil? || msg.header.empty?
          raise JetStream::Error::InvalidStreamResponse.new("nats: invalid stream response: response should have headers")
        end
        raise JetStream::Error::BatchUnsupported unless batch_header(msg, NUM_PENDING_HEADER)

        required_batch_header(msg, Header::STREAM, "stream")
        subject = required_batch_header(msg, Header::SUBJECT, "subject")
        seq = required_batch_header(msg, Header::SEQUENCE, "sequence")
        seq = Integer(seq, 10, exception: false)
        raise JetStream::Error::InvalidStreamResponse.new("nats: invalid stream response: invalid sequence header") unless seq

        begin
          Time.iso8601(required_batch_header(msg, Header::TIME_STAMP, "timestamp"))
        rescue ArgumentError
          raise JetStream::Error::InvalidStreamResponse.new("nats: invalid stream response: invalid timestamp header")
        end

        raw_msg = JetStream::API::RawStreamMsg.new(subject: subject, seq: seq, headers: msg.header)
        raw_msg.data = msg.data
        raw_msg
      end

      def required_batch_header(msg, name, what)
        value = batch_header(msg, name)
        return value unless value.nil? || value.empty?

        raise JetStream::Error::InvalidStreamResponse.new("nats: invalid stream response: missing #{what} header")
      end

      # The first value of a header, which a message can repeat.
      def batch_header(msg, name)
        return nil if msg.header.nil?

        value = msg.header[name]
        value.is_a?(Array) ? value.first : value
      end
    end
  end
end
