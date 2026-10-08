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
    # PubAckFuture is the outcome of a message published with publish_async,
    # like PubAckFuture of nats.go: the PubAck of the stream, or the error
    # that the publish ended with, once there is one.
    #
    # @example
    #   future = js.publish_async("orders.new", "data")
    #   ack = future.wait(5)
    class PubAckFuture
      # @return [NATS::Msg] The message that was published, like Msg of nats.go.
      attr_reader :msg

      # @private
      # How many times, and how long apart, the message is published again
      # when no stream responds, and the seconds after which it times out.
      attr_reader :retry_attempts, :retry_wait, :timeout

      # @private
      # The retries made, when the next one is due and when the future times out.
      attr_accessor :retries, :retry_at, :deadline

      # @private
      def initialize(msg, retry_attempts: 0, retry_wait: 0, timeout: nil)
        @msg = msg
        @retry_attempts = retry_attempts
        @retry_wait = retry_wait
        @timeout = timeout
        @retries = 0
        @retry_at = nil
        @deadline = nil
        @ack = nil
        @err = nil
        @done = false
        @mu = Mutex.new
        @cond = ConditionVariable.new
      end

      # ack is the PubAck of the stream, like Ok of nats.go, once the stream
      # acked the message; nil until then, and when the publish failed.
      # @return [JetStream::PubAck, nil]
      def ack
        @mu.synchronize { @ack }
      end

      # err is the error that the publish ended with, like Err of nats.go,
      # once it failed; nil until then, and when the stream acked the message.
      # @return [StandardError, nil]
      def err
        @mu.synchronize { @err }
      end

      # done? tells whether the publish ended, with an ack or an error.
      # @return [Boolean]
      def done?
        @mu.synchronize { @done }
      end

      # wait waits for the publish to end, and returns the PubAck of the
      # stream, or raises the error that the publish ended with.
      # @param timeout [Float, nil] Seconds to wait, or nil to wait for as long as it takes.
      # @return [JetStream::PubAck]
      # @raise [NATS::Timeout] When the publish did not end within the timeout.
      def wait(timeout = nil)
        @mu.synchronize do
          deadline = MonotonicTime.now + timeout if timeout
          until @done
            remaining = deadline - MonotonicTime.now if deadline
            raise NATS::Timeout.new("nats: timeout waiting for the ack") if remaining && remaining <= 0

            @cond.wait(@mu, remaining)
          end
          raise @err if @err

          @ack
        end
      end

      # @private
      # resolve ends the publish with an ack or an error, unless it ended.
      def resolve(ack: nil, err: nil)
        @mu.synchronize do
          return false if @done

          @ack = ack
          @err = err
          @done = true
          @cond.broadcast
        end
        true
      end
    end
  end
end
