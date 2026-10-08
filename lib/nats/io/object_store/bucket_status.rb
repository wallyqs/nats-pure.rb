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
#

module NATS
  class ObjectStore
    # BucketStatus is the status of an object store, like ObjectBucketStatus of nats.go.
    class BucketStatus
      attr_reader :bucket, :stream_info

      def initialize(info, bucket)
        @stream_info = info
        @bucket = bucket
      end

      def description
        @stream_info.config.description
      end

      # Seconds after which objects expire, or 0 when they do not.
      def ttl
        (@stream_info.config.max_age || 0) / ::NATS::NANOSECONDS
      end

      def storage
        @stream_info.config.storage
      end

      def replicas
        @stream_info.config.num_replicas
      end

      # Whether the object store is sealed, so that it cannot change.
      def sealed?
        @stream_info.config.sealed == true
      end

      # The size of the object store, including the meta information, in bytes.
      def size
        @stream_info.state.bytes
      end

      def backing_store
        "JetStream"
      end

      def metadata
        @stream_info.config.metadata
      end

      def compressed?
        compression = @stream_info.config.compression
        !compression.nil? && compression != "none"
      end
    end
  end
end
