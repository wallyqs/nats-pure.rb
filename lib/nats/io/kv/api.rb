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
  class KeyValue
    module API
      KeyValueConfig = Struct.new(
        :bucket,
        :description,
        :max_value_size,
        :history,
        :ttl,
        :max_bytes,
        :storage,
        :replicas,
        # Placement of the bucket's stream in a cluster, as `{cluster:, tags:}`.
        :placement,
        :republish,
        :direct,
        # Keys are validated, like in nats.go, unless this is false.
        :validate_keys,
        # Compress the bucket's stream with S2 (requires nats-server v2.10.0).
        :compression,
        # Freeform metadata of the bucket (requires nats-server v2.10.0).
        :metadata,
        # Seconds to keep the markers that the server leaves when a TTL
        # removes a key, which per-key TTLs need (requires nats-server v2.11.0).
        :limit_marker_ttl,
        # Makes the bucket a read-only mirror of another bucket, like Mirror
        # of nats.go: a stream source as a Hash, such as `{name: "ORIGIN"}`,
        # whose name is that of the bucket or of its stream. A `domain:`
        # mirrors a bucket of another JetStream domain. Writes to the mirror
        # go to the origin bucket.
        :mirror,
        # Makes the bucket take the keys of other buckets, like Sources of
        # nats.go: stream sources as Hashes, such as `[{name: "A"}]`. Their
        # keys are mapped to this bucket, unless a source has its own
        # `subject_transforms:`, which then takes the full stream name.
        :sources,
        keyword_init: true
      ) do
        def initialize(opts = {})
          rem = opts.keys - members
          opts.delete_if { |k| rem.include?(k) }
          super
        end
      end
    end
  end
end
