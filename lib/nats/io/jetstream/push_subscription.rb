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

module NATS
  class JetStream
    # PushSubscription is included into NATS::Subscription so that it
    #
    # @example Create a push subscription using JetStream context.
    #
    #   require 'nats/client'
    #
    #   nc = NATS.connect
    #   js = nc.jetstream
    #   sub = js.subscribe("foo", "bar")
    #   msg = sub.next_msg
    #   msg.ack
    #   sub.unsubscribe
    #
    # Like the subscriptions of js.Subscribe of nats.go, it takes the
    # control messages of the consumer, which are not delivered: it answers
    # the flow control requests once the messages that came before them
    # were delivered, and, when the consumer has idle heartbeats, reports a
    # NATS::JetStream::Error::ConsumerNotActive to the error callback of the
    # connection whenever nothing came for two of them. When an idle
    # heartbeat tells that the consumer delivered up to another sequence
    # than the last message that came, it reports a
    # NATS::JetStream::Error::ConsumerSequenceMismatch to the error callback,
    # like ErrConsumerSequenceMismatch of nats.go.
    #
    # @!visibility public
    module PushSubscription
      # How many idle heartbeats may be missed before the consumer is
      # reported as not active, like hbcThresh of nats.go.
      HEARTBEAT_THRESHOLD = 2

      # consumer_info retrieves the current status of the pull subscription consumer.
      # @param params [Hash] Options to customize API request.
      # @option params [Float] :timeout Time to wait for response.
      # @return [JetStream::API::ConsumerInfo] The latest ConsumerInfo of the consumer.
      def consumer_info(params = {})
        @jsi.js.consumer_info(@jsi.stream, @jsi.consumer, params)
      end

      # unsubscribe unsubscribes, as for any subscription, and stops
      # checking that the consumer is active.
      def unsubscribe(opt_max = nil)
        super
      ensure
        @js_hb_task&.shutdown unless opt_max
      end

      # @!visibility private
      def dispatch(msg)
        return super unless @js_ctrl
        return handle_control_msg(msg) if control_msg?(msg)

        synchronize do
          @js_received += 1
          @js_active = true
          # Kept to check the sequences against the next idle heartbeat.
          @js_last_msg = msg
        end
        super
      end

      # @!visibility private
      def process(msg)
        super
      ensure
        delivered! if @js_ctrl
      end

      # next_msg waits for the next message, as for any subscription,
      # skipping the control messages of the consumer.
      def next_msg(opts = {})
        msg = super
        delivered! if @js_ctrl
        msg
      end

      private

      # Starts taking the control messages of the consumer, and, with idle
      # heartbeats every heartbeat seconds, checks that the consumer is
      # active. The errors go to on_error when given, or else to the error
      # callback of the connection.
      def start_control(heartbeat, on_error: nil)
        synchronize do
          @js_on_error = on_error
          @js_ctrl = true
          @js_received = 0
          @js_delivered = 0
          @js_fc_reply = nil
          @js_fc_seq = 0
          @js_active = true
          @js_last_msg = nil
        end
        return unless heartbeat.is_a?(Numeric) && heartbeat.positive?

        interval = heartbeat * HEARTBEAT_THRESHOLD
        @js_hb_task = Concurrent::TimerTask.new(execution_interval: interval) do |task|
          check_active(task)
        end
        @js_hb_task.execute
      end

      # stop_control stops checking that the consumer is active.
      def stop_control
        @js_hb_task&.shutdown
      end

      # js_report passes an error to on_error, or else to the error callback
      # of the connection.
      def js_report(err)
        on_error = synchronize { @js_on_error }
        return on_error.call(err) if on_error

        @nc.synchronize { @nc.send(:err_cb_call, @nc, err, self) }
      end

      # A control message has an empty body and status 100: an idle
      # heartbeat, or, with a reply, a flow control request.
      def control_msg?(msg)
        msg.data.to_s.empty? && !msg.header.nil? && msg.header[JS::Header::Status] == JS::Status::CtrlMsg
      end

      def handle_control_msg(msg)
        heartbeat = msg.reply.to_s.empty?
        reply = synchronize do
          @js_active = true
          if !msg.reply.to_s.empty?
            # A flow control request, answered once the messages that came
            # before it were delivered.
            next msg.reply if @js_delivered >= @js_received

            @js_fc_reply = msg.reply
            @js_fc_seq = @js_received
            nil
          else
            # An idle heartbeat, which may tell that the consumer stalled
            # waiting for the answer to a flow control request.
            msg.header[JS::Header::ConsumerStalled]
          end
        end
        respond_flow_control(reply)
        check_sequence(msg) if heartbeat
      end

      # check_sequence compares the last consumer sequence that an idle
      # heartbeat carries with the one of the last message that came, and
      # reports a mismatch, telling from where the consumer could resume,
      # like checkForSequenceMismatch of nats.go. The members of a queue
      # group each get only some of the messages, so are not checked.
      def check_sequence(heartbeat)
        last = synchronize { @js_last_msg }
        return if last.nil? || !queue.to_s.empty?

        meta = begin
          last.metadata
        rescue JetStream::Error::NotJSMessage
          return
        end
        return if meta.nil?

        ldseq = heartbeat.header[JS::Header::LastConsumerSeq].to_s
        return if ldseq == meta.sequence.consumer.to_s

        err = JetStream::Error::ConsumerSequenceMismatch.new(
          stream_resume_sequence: meta.sequence.stream,
          consumer_sequence: meta.sequence.consumer,
          last_consumer_sequence: ldseq.to_i
        )
        js_report(err)
      end

      # delivered! counts a message handed to the callback or returned by
      # next_msg, and answers a flow control request that waited for it.
      def delivered!
        reply = synchronize do
          @js_delivered += 1
          @js_active = true
          next unless @js_fc_reply && @js_delivered >= @js_fc_seq

          @js_fc_reply.tap { @js_fc_reply = nil }
        end
        respond_flow_control(reply)
      end

      def respond_flow_control(reply)
        return if reply.nil? || reply.empty?

        @nc.publish(reply)
      rescue NATS::IO::Error
        # The connection closed; the server asks again.
      end

      # check_active reports the consumer as not active when nothing came
      # since the last check, like the activity check of nats.go.
      def check_active(task)
        if @nc.closed? || synchronize { closed }
          task.shutdown
          return
        end

        active = synchronize { @js_active.tap { @js_active = false } }
        return if active

        js_report(JetStream::Error::ConsumerNotActive.new("nats: consumer not active"))
      rescue => e
        e
      end
    end
    private_constant :PushSubscription
  end
end
