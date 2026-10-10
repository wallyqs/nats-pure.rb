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

module NATS
  class Msg
    # header is a Hash of the header names to their values, a String, or
    # an Array of Strings for a name that the message has more than once,
    # like the http.Header based headers of nats.go. Publishing takes both.
    attr_accessor :subject, :reply, :data, :header
    attr_accessor :nc, :sub

    class << self
      # @private
      # Adds a value of a header that was received: a name that comes
      # again gets an Array of its values, others keep a String.
      def add_header_value(hdr, key, value)
        hdr[key] = if !hdr.key?(key)
          value
        elsif hdr[key].is_a?(Array)
          hdr[key] + [value]
        else
          [hdr[key], value]
        end
      end

      # @private
      # The "Name: value" lines of a header, one for each value of a name
      # that has an Array of them.
      def header_lines(header)
        header.flat_map do |key, value|
          (value.is_a?(Array) ? value : [value]).map { |v| "#{key}: #{v}\r\n" }
        end
      end
    end

    def initialize(opts = {})
      @subject = opts[:subject]
      @reply = opts[:reply]
      @data = opts[:data]
      @header = opts[:header]
      @nc = opts[:nc]
      @sub = opts[:sub]

      # JS related
      @ackd = false
      @meta = nil

      # The size of a received message as it came, see size.
      @wire_size = nil
    end

    # Whether msg has the same subject, reply, header and data, like Equal
    # of nats.go; the connection and the subscription are not compared. A
    # nil reply, header or data is the same as an empty one, and a header
    # value String the same as an Array of just that value.
    # @param other [Object] The message to compare with.
    # @return [Boolean]
    def ==(other)
      return true if equal?(other)
      return false unless other.is_a?(NATS::Msg)

      @subject.to_s == other.subject.to_s && @reply.to_s == other.reply.to_s &&
        @data.to_s.b == other.data.to_s.b && header_values == other.send(:header_values)
    end
    alias_method :eql?, :==

    def hash
      [NATS::Msg, @subject.to_s, @reply.to_s, @data.to_s.b, header_values].hash
    end

    # The size of the message in bytes, like Size of nats.go: those of its
    # subject, reply, header and data, as the server counts them against
    # the max_bytes of a pull. That of a received message is that of the
    # message as it came.
    # @return [Integer]
    def size
      return @wire_size if @wire_size

      @subject.to_s.bytesize + @reply.to_s.bytesize + header_bytesize + @data.to_s.bytesize
    end

    # Responds to the message with data, published to its reply subject,
    # like Respond of nats.go: without the headers of the message.
    # @param data [String] The data of the response.
    # @raise [NATS::IO::MsgNotBound] When the message did not come from a
    #   connection.
    # @raise [NATS::IO::MsgNoReply] When the message has no reply subject.
    def respond(data = "")
      check_respond!

      @nc.publish(reply, data)
    end

    # Responds to the message with msg, which may have headers, like
    # RespondMsg of nats.go: msg is published to the reply subject of the
    # message, which becomes its subject.
    # @param msg [NATS::Msg] The response.
    # @raise [NATS::IO::InvalidMsg] When msg is not a NATS::Msg.
    # @raise [NATS::IO::MsgNotBound] When the message did not come from a
    #   connection.
    # @raise [NATS::IO::MsgNoReply] When the message has no reply subject.
    def respond_msg(msg)
      raise NATS::IO::InvalidMsg, "nats: expected NATS::Msg, got #{msg.class.name}" unless msg.is_a?(Msg)
      check_respond!

      msg.subject = reply
      @nc.publish_msg(msg)
    end

    def inspect
      hdr = ", header=#{@header}" if @header
      dot = "..." if @data.length > 10
      dat = "#{data.slice(0, 10)}#{dot}"
      "#<NATS::Msg(subject: \"#{@subject}\", reply: \"#{@reply}\", data: #{dat.inspect}#{hdr})>"
    end

    private

    def check_respond!
      raise NATS::IO::MsgNotBound, "nats: message is not bound to subscription/connection" unless @nc
      raise NATS::IO::MsgNoReply, "nats: message does not have a reply" if reply.to_s.empty?
    end

    # Called by the client with the size of a received message.
    attr_writer :wire_size

    # The header, its names and values as Strings, each name with an Array
    # of its values.
    def header_values
      return {} unless @header

      @header.each_with_object({}) do |(key, value), values|
        values[key.to_s] = Array(value).map(&:to_s)
      end
    end

    # The size of the header as it is published.
    def header_bytesize
      return 0 if @header.nil? || @header.empty?

      NATS::Client::NATS_HDR_LINE.bytesize + Msg.header_lines(@header).sum(&:bytesize) + NATS::Client::CR_LF_SIZE
    end
  end
end
