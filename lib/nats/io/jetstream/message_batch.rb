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
    # MessageBatch is what a fetch returns: the messages it got, as an
    # Array, and the error that ended it after some messages came, like
    # MessageBatch of the nats.go jetstream package. A fetch that got no
    # messages raises that error instead.
    #
    # @example Check how a fetch ended.
    #
    #   msgs = psub.fetch(10, heartbeat: 1, timeout: 5)
    #   msgs.each(&:ack)
    #   warn "fetch ended early: #{msgs.error}" if msgs.error
    #
    # @!visibility public
    class MessageBatch < Array
      # @return [NATS::JetStream::Error, nil] The error that ended the fetch
      #   after some messages came, as NoHeartbeat, ConsumerDeleted, PinIdMismatch
      #   or another status of the server but those that only end a pull (no
      #   messages, an expired pull, a completed batch or max_bytes reached);
      #   nil when it ended without one, like Error of nats.go MessageBatch.
      attr_accessor :error
    end
  end
end
