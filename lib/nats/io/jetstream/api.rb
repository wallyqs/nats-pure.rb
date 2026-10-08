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
require "base64"
require "time"

module NATS
  class JetStream
    # JetStream::API are the types used to interact with the JetStream API.
    module API
      # When the server responds with an error from the JetStream API.
      Error = ::NATS::JetStream::Error::APIError

      # The times that the server sends stay RFC 3339 Strings in the
      # attributes that have always had them. Each has a reader that parses
      # it into a Time, named after it with _time in place of a _ts suffix,
      # or else after it: StreamState#first_time and #last_time,
      # SequenceInfo#last_active_time, ClusterInfo#leader_since_time and
      # DesiredClusterInfo#created_time, like the time.Time fields of
      # nats.go. They return nil for a time the server left out, or sent as
      # Go's zero time, as for an empty stream.

      # SequenceInfo is a pair of consumer and stream sequence and last activity.
      # @!attribute consumer_seq
      #   @return [Integer] The consumer sequence.
      # @!attribute stream_seq
      #   @return [Integer] The stream sequence.
      # @!attribute last_active
      #   @return [String, nil] When the last message was delivered or acked,
      #     as the server sent it.
      SequenceInfo = Struct.new(:consumer_seq, :stream_seq, :last_active,
        keyword_init: true) do
        def initialize(opts = {})
          # Filter unrecognized fields and freeze.
          rem = opts.keys - members
          opts.delete_if { |k| rem.include?(k) }
          super
          freeze
        end

        # @return [Time, nil] last_active as a Time, like LastActive of nats.go.
        def last_active_time
          JS.parse_time(last_active)
        end
      end

      # ClusterInfo is the cluster of a stream or a consumer, as the server
      # sends it: a Hash with Symbol keys, such as :leader and :replicas,
      # whose times and durations are those of the server. When the cluster
      # is changing, :desired has a DesiredClusterInfo.
      class ClusterInfo < Hash
        # @!visibility private
        def self.decode(cluster)
          return cluster unless cluster.is_a?(Hash)

          info = self[cluster]
          info[:desired] = DesiredClusterInfo[info[:desired]] if info[:desired].is_a?(Hash)
          info
        end

        # @return [Time, nil] When the leader was elected (requires
        #   nats-server v2.12.0), like LeaderSince of nats.go.
        def leader_since_time
          JS.parse_time(self[:leader_since])
        end
      end

      # DesiredClusterInfo is the cluster that a stream or consumer is
      # changing to, as the server sends it: a Hash with Symbol keys, such
      # as :created, :replicas and :status.
      class DesiredClusterInfo < Hash
        # @return [Time, nil] When the change started, like Created of nats.go.
        def created_time
          JS.parse_time(self[:created])
        end
      end

      # PriorityGroupState is the state of a priority group of a consumer
      # (requires nats-server v2.11.0).
      #
      # @!attribute group
      #   @return [String] Name of the group.
      # @!attribute pinned_client_id
      #   @return [String, nil] With the pinned_client priority policy, the
      #     pin id of the subscription that the group is pinned to.
      # @!attribute pinned_ts
      #   @return [Time, nil] When the group was pinned.
      PriorityGroupState = Struct.new(:group, :pinned_client_id, :pinned_ts,
        keyword_init: true) do
        def initialize(opts = {})
          opts[:pinned_ts] = JS.parse_time(opts[:pinned_ts])
          rem = opts.keys - members
          opts.delete_if { |k| rem.include?(k) }
          super
          freeze
        end
      end

      # ConsumerInfo is the current status of a JetStream consumer.
      #
      # @!attribute stream_name
      #   @return [String] name of the stream to which the consumer belongs.
      # @!attribute name
      #   @return [String] name of the consumer.
      # @!attribute created
      #   @return [String] time when the consumer was created.
      # @!attribute config
      #   @return [ConsumerConfig] consumer configuration.
      # @!attribute delivered
      #   @return [SequenceInfo]
      # @!attribute ack_floor
      #   @return [SequenceInfo]
      # @!attribute num_ack_pending
      #   @return [Integer]
      # @!attribute num_redelivered
      #   @return [Integer]
      # @!attribute num_waiting
      #   @return [Integer]
      # @!attribute num_pending
      #   @return [Integer]
      # @!attribute cluster
      #   The cluster of a clustered consumer, such as its leader, its
      #   replicas and, as leader_since, when the leader was elected
      #   (requires nats-server v2.12.0); nil on a standalone server. The
      #   values are the server's: leader_since is a String, which
      #   leader_since_time parses, and the active of the replicas is in
      #   nanoseconds.
      #   @return [ClusterInfo, nil]
      # @!attribute ts
      #   When the server reported this info (requires nats-server v2.10.0).
      #   @return [Time]
      # @!attribute paused
      #   True while the consumer is paused (requires nats-server v2.11.0).
      #   @return [Boolean, nil]
      # @!attribute pause_remaining
      #   Seconds until a paused consumer resumes, rounded down, so 0 in its
      #   last second (requires nats-server v2.11.0).
      #   @return [Integer, nil]
      # @!attribute priority_groups
      #   State of the consumer's priority groups (requires nats-server v2.11.0).
      #   @return [Array<PriorityGroupState>, nil]
      ConsumerInfo = Struct.new(:type, :stream_name, :name, :created,
        :config, :delivered, :ack_floor,
        :num_ack_pending, :num_redelivered, :num_waiting,
        :num_pending, :cluster, :push_bound, :ts,
        :paused, :pause_remaining, :priority_groups,
        keyword_init: true) do
        def initialize(opts = {})
          opts[:created] = Time.parse(opts[:created])
          opts[:ts] = Time.parse(opts[:ts]) if opts[:ts]
          opts[:pause_remaining] = opts[:pause_remaining] / ::NATS::NANOSECONDS if opts[:pause_remaining]
          opts[:priority_groups] = opts[:priority_groups].map { |state| PriorityGroupState.new(state) } if opts[:priority_groups]
          opts[:cluster] = ClusterInfo.decode(opts[:cluster])
          opts[:ack_floor] = SequenceInfo.new(opts[:ack_floor])
          opts[:delivered] = SequenceInfo.new(opts[:delivered])
          %i[ack_wait inactive_threshold idle_heartbeat priority_timeout].each do |key|
            opts[:config][key] = JS.seconds(opts[:config][key]) if opts[:config][key]
          end
          opts[:config] = ConsumerConfig.new(opts[:config])
          # Filter unrecognized fields just in case.
          rem = opts.keys - members
          opts.delete_if { |k| rem.include?(k) }
          super
          freeze
        end
      end

      # ConsumerConfig is the consumer configuration.
      #
      # The durations ack_wait, idle_heartbeat, inactive_threshold and
      # priority_timeout are in seconds, Integers or Floats such as 0.5,
      # which the server gets as exact nanoseconds. A fetched config has an
      # Integer for a whole number of seconds, and a Float only when the
      # server has a fraction of a second. backoff and max_expires stay in
      # nanoseconds, both ways.
      #
      # @!attribute durable_name
      #   @return [String]
      # @!attribute deliver_policy
      #   @return [String]
      # @!attribute opt_start_time
      #   Time to start at, with the "by_start_time" deliver policy, as a
      #   Time or as an RFC 3339 String; a fetched config has a String.
      #   @return [Time, String, nil]
      # @!attribute ack_policy
      #   @return [String]
      # @!attribute ack_wait
      #   Seconds; nil when the server omits it, as for consumers that do not ack.
      #   @return [Integer, Float, nil]
      # @!attribute max_deliver
      #   @return [Integer]
      # @!attribute backoff
      #   Nanoseconds to wait before each redelivery, instead of ack_wait.
      #   @return [Array<Integer>, nil]
      # @!attribute idle_heartbeat
      #   Seconds between the idle heartbeats of a push consumer.
      #   @return [Integer, Float, nil]
      # @!attribute max_expires
      #   Most nanoseconds a pull can wait.
      #   @return [Integer, nil]
      # @!attribute inactive_threshold
      #   Seconds after which the server deletes the consumer when unused.
      #   @return [Integer, Float, nil]
      # @!attribute replay_policy
      #   @return [String]
      # @!attribute max_waiting
      #   @return [Integer]
      # @!attribute max_ack_pending
      #   @return [Integer]
      # @!attribute pause_until
      #   Time until which the consumer delivers no messages, as a Time or
      #   as an RFC 3339 String; a fetched config has a String. The server
      #   takes it only when it creates the consumer: updates keep the pause,
      #   which pause_consumer and resume_consumer change. Requires
      #   nats-server v2.11.0; older ones create the consumer unpaused.
      #   @return [Time, String, nil]
      # @!attribute priority_policy
      #   How the consumer serves the pulls of its priority groups: "none",
      #   "overflow", "pinned_client", or "prioritized" (requires
      #   nats-server v2.11.0, and v2.12.0 for "prioritized").
      #   @return [String, nil]
      # @!attribute priority_groups
      #   Names of the consumer's priority groups, one of which each pull
      #   has to name (requires nats-server v2.11.0).
      #   @return [Array<String>, nil]
      # @!attribute priority_timeout
      #   With the pinned_client priority policy, seconds after which a
      #   pinned subscription that stops pulling is unpinned
      #   (requires nats-server v2.11.0).
      #   @return [Integer, Float, nil]
      ConsumerConfig = Struct.new(:name, :durable_name, :description,
        :deliver_policy, :opt_start_seq, :opt_start_time,
        :ack_policy, :ack_wait, :max_deliver, :backoff,
        :filter_subject, :replay_policy, :rate_limit_bps,
        :sample_freq, :max_waiting, :max_ack_pending,
        :flow_control, :idle_heartbeat, :headers_only,
        # Pull based options
        :max_batch, :max_expires,
        # Push based consumers
        :deliver_subject, :deliver_group,
        # Ephemeral inactivity threshold
        :inactive_threshold,
        # Generally inherited by parent stream and other markers,
        # now can be configured directly.
        :num_replicas,
        # Force memory storage
        :mem_storage,
        # NATS v2.10 features
        :metadata, :filter_subjects, :max_bytes,
        # NATS v2.11 features
        :pause_until, :priority_policy, :priority_groups, :priority_timeout,
        keyword_init: true) do
        def initialize(opts = {})
          # Filter unrecognized fields just in case.
          rem = opts.keys - members
          opts.delete_if { |k| rem.include?(k) }
          super
        end
      end

      # ConsumerPauseResponse is the result of pausing or resuming a consumer
      # (requires nats-server v2.11.0).
      #
      # @!attribute paused
      #   @return [Boolean] Whether the consumer is paused.
      # @!attribute pause_until
      #   @return [Time, nil] When the consumer resumes; nil once resumed. A time
      #     in the past does not pause the consumer, and paused is then false.
      # @!attribute pause_remaining
      #   @return [Integer, nil] Seconds until the consumer resumes, rounded down,
      #     so 0 in its last second; nil when it is not paused.
      ConsumerPauseResponse = Struct.new(:paused, :pause_until, :pause_remaining,
        keyword_init: true) do
        def initialize(opts = {})
          opts[:pause_until] = JS.parse_time(opts[:pause_until])
          opts[:pause_remaining] = opts[:pause_remaining] / ::NATS::NANOSECONDS if opts[:pause_remaining]
          rem = opts.keys - members
          opts.delete_if { |k| rem.include?(k) }
          super
          freeze
        end
      end

      # ConsumerResetResponse is the result of resetting a consumer
      # (requires nats-server v2.14.0).
      #
      # @!attribute info
      #   @return [ConsumerInfo] The consumer after the reset.
      # @!attribute reset_seq
      #   @return [Integer] Stream sequence the consumer delivers from. The next
      #     message it delivers can come later, as the first one from there that
      #     matches its filter.
      ConsumerResetResponse = Struct.new(:info, :reset_seq,
        keyword_init: true) do
        def initialize(opts = {})
          reset_seq = opts[:reset_seq]
          super(info: ConsumerInfo.new(opts), reset_seq: reset_seq)
          freeze
        end
      end

      # HashAccess lets the Structs of a response that was a Hash, with
      # Symbol keys, still be read as that Hash: with [], dig and to_h.
      # @!visibility private
      module HashAccess
        # [] returns nil for a key that is not a member, as a Hash does.
        def [](key)
          return nil if (key.is_a?(Symbol) || key.is_a?(String)) && !members.include?(key.to_sym)

          super
        end

        # to_h returns the Hash that the response was, with the nested
        # Structs as Hashes too, and without what the server left out.
        def to_h(&block)
          return super if block

          each_pair.with_object({}) do |(key, value), hash|
            hash[key] = HashAccess.plain(value) unless value.nil?
          end
        end

        # @!visibility private
        def self.plain(value)
          case value
          when HashAccess then value.to_h
          when Hash then value.to_h { |key, val| [key.to_sym, plain(val)] }
          else value
          end
        end

        # @!visibility private
        def self.filter(opts, members)
          opts.slice(*members)
        end
      end

      # AccountLimits are the JetStream limits of an account, or of one of
      # its tiers, like AccountLimits of nats.go; -1 is no limit.
      #
      # @!attribute max_memory
      #   @return [Integer] Most bytes of memory storage.
      # @!attribute max_storage
      #   @return [Integer] Most bytes of file storage.
      # @!attribute max_streams
      #   @return [Integer] Most streams.
      # @!attribute max_consumers
      #   @return [Integer] Most consumers.
      # @!attribute max_ack_pending
      #   @return [Integer] Most messages that a consumer may have awaiting acks.
      # @!attribute memory_max_stream_bytes
      #   @return [Integer] Most bytes of a memory stream.
      # @!attribute storage_max_stream_bytes
      #   @return [Integer] Most bytes of a file stream.
      # @!attribute max_bytes_required
      #   @return [Boolean] Whether streams have to set max_bytes.
      AccountLimits = Struct.new(:max_memory, :max_storage, :max_streams,
        :max_consumers, :max_ack_pending, :memory_max_stream_bytes,
        :storage_max_stream_bytes, :max_bytes_required,
        keyword_init: true) do
        include HashAccess

        def initialize(opts = {})
          super(**HashAccess.filter(opts, members))
          freeze
        end
      end

      # APIStats are the stats of the JetStream API of the server, like
      # APIStats of nats.go.
      #
      # @!attribute level
      #   @return [Integer] The API level of the server (nats-server v2.11.0 and later).
      # @!attribute total
      #   @return [Integer] API requests received.
      # @!attribute errors
      #   @return [Integer] API requests that got an error response.
      # @!attribute inflight
      #   @return [Integer, nil] API requests being served.
      APIStats = Struct.new(:level, :total, :errors, :inflight,
        keyword_init: true) do
        include HashAccess

        def initialize(opts = {})
          super(**HashAccess.filter(opts, members))
          freeze
        end
      end

      # Tier is the JetStream usage and limits of an account in one tier,
      # such as that of the streams with 3 replicas, like Tier of nats.go.
      #
      # @!attribute memory
      #   @return [Integer] Bytes of memory storage used.
      # @!attribute storage
      #   @return [Integer] Bytes of file storage used.
      # @!attribute reserved_memory
      #   @return [Integer] Bytes of memory storage reserved by the max_bytes of streams.
      # @!attribute reserved_storage
      #   @return [Integer] Bytes of file storage reserved by the max_bytes of streams.
      # @!attribute streams
      #   @return [Integer] Number of streams.
      # @!attribute consumers
      #   @return [Integer] Number of consumers.
      # @!attribute limits
      #   @return [AccountLimits]
      Tier = Struct.new(:memory, :storage, :reserved_memory, :reserved_storage,
        :streams, :consumers, :limits,
        keyword_init: true) do
        include HashAccess

        def initialize(opts = {})
          opts = HashAccess.filter(opts, members)
          opts[:limits] = AccountLimits.new(opts[:limits]) if opts[:limits].is_a?(Hash)
          super(**opts)
          freeze
        end
      end

      # AccountInfo is the JetStream usage and limits of the account, like
      # AccountInfo of nats.go. It reads as the Hash that account_info
      # returned before, too: account_info[:limits][:max_streams],
      # account_info.dig(:api, :level) and account_info.to_h work.
      #
      # @!attribute type
      #   @return [String]
      # @!attribute memory
      #   @return [Integer] Bytes of memory storage used.
      # @!attribute storage
      #   @return [Integer] Bytes of file storage used.
      # @!attribute reserved_memory
      #   @return [Integer] Bytes of memory storage reserved by the max_bytes of streams.
      # @!attribute reserved_storage
      #   @return [Integer] Bytes of file storage reserved by the max_bytes of streams.
      # @!attribute streams
      #   @return [Integer] Number of streams.
      # @!attribute consumers
      #   @return [Integer] Number of consumers.
      # @!attribute limits
      #   The limits of the account; with tiers, those are in the tiers.
      #   @return [AccountLimits]
      # @!attribute domain
      #   @return [String, nil] JetStream domain of the server.
      # @!attribute api
      #   @return [APIStats]
      # @!attribute tiers
      #   Usage and limits per tier, by name, such as "R1" and "R3", with
      #   tiered limits only. Symbols work as names too.
      #   @return [Hash{String => Tier}, nil]
      AccountInfo = Struct.new(:type, :memory, :storage, :reserved_memory,
        :reserved_storage, :streams, :consumers, :limits, :domain, :api, :tiers,
        keyword_init: true) do
        include HashAccess

        def initialize(opts = {})
          opts = HashAccess.filter(opts, members)
          opts[:limits] = AccountLimits.new(opts[:limits]) if opts[:limits].is_a?(Hash)
          opts[:api] = APIStats.new(opts[:api]) if opts[:api].is_a?(Hash)
          if opts[:tiers].is_a?(Hash)
            # The names are keys of a JSON object, which come as Symbols.
            tiers = Hash.new { |hash, name| hash.fetch(name.to_s, nil) if name.is_a?(Symbol) }
            opts[:tiers].each { |name, tier| tiers[name.to_s] = Tier.new(tier) }
            opts[:tiers] = tiers.freeze
          end
          super(**opts)
          freeze
        end
      end

      # StreamConfig represents the configuration of a stream from JetStream.
      #
      # Settings left nil are not sent, and neither are the settings of
      # nats-server 2.11 to 2.14 left at their defaults, such as false.
      # Servers since v2.12.0, and v2.11 ones in strict mode, refuse the
      # settings that they do not know.
      #
      # @!attribute type
      #   @return [String]
      # @!attribute config
      #   @return [Hash]
      # @!attribute created
      #   @return [String]
      # @!attribute state
      #   @return [StreamState]
      # @!attribute did_create
      #   @return [Boolean]
      # @!attribute name
      #   @return [String]
      # @!attribute subjects
      #   @return [Array]
      # @!attribute retention
      #   @return [String]
      # @!attribute max_consumers
      #   @return [Integer]
      # @!attribute max_msgs
      #   @return [Integer]
      # @!attribute max_bytes
      #   @return [Integer]
      # @!attribute max_age
      #   @return [Integer]
      # @!attribute max_msgs_per_subject
      #   @return [Integer]
      # @!attribute max_msg_size
      #   @return [Integer]
      # @!attribute discard
      #   @return [String]
      # @!attribute discard_new_per_subject
      #   Whether a subject that holds max_msgs_per_subject messages refuses
      #   new ones, instead of discarding its oldest. Needs discard "new" and
      #   max_msgs_per_subject; the server reports false as nil.
      #   @return [Boolean, nil]
      # @!attribute mirror
      #   The stream that the stream mirrors, as `{name:, opt_start_seq:,
      #   opt_start_time:, filter_subject:, ...}`, where opt_start_time can
      #   be a Time.
      #   @return [Hash]
      # @!attribute sources
      #   The streams that the stream takes messages from, as Hashes like
      #   that of mirror.
      #   @return [Array<Hash>]
      # @!attribute storage
      #   @return [String]
      # @!attribute num_replicas
      #   @return [Integer]
      # @!attribute duplicate_window
      #   Nanoseconds within which the stream stores a message only once for
      #   each Header::MSG_ID. Unless set, it is 2 minutes, except that
      #   mirrors, and since nats-server v2.14.0 streams with sources, get
      #   none: the messages published to them are not deduplicated.
      #   @return [Integer]
      # @!attribute mirror
      #   The stream that the stream mirrors, as `{name:, ...}`. Given a
      #   `domain:`, it is the stream of the JetStream of that domain, as
      #   when it sets `external: {api: "$JS.<domain>.API"}`, like the
      #   Domain of a StreamSource of nats.go.
      #   @return [Hash]
      # @!attribute sources
      #   The streams that the stream sources, as Hashes like the mirror,
      #   which take a `domain:` too.
      #   @return [Array<Hash>]
      # @!attribute compression
      #   Storage compression of a file based stream, "s2" or "none"
      #   (requires nats-server v2.10.0).
      #   @return [String]
      # @!attribute first_seq
      #   The sequence of the first message stored in a new stream
      #   (requires nats-server v2.10.0).
      #   @return [Integer]
      # @!attribute subject_transform
      #   Transform applied to the subject of every message stored, as
      #   `{src:, dest:}` (requires nats-server v2.10.0).
      #   @return [Hash]
      # @!attribute consumer_limits
      #   Defaults and upper limits for the stream's consumers, as
      #   `{inactive_threshold:, max_ack_pending:}`. Like the other durations
      #   of a stream, inactive_threshold is in nanoseconds
      #   (requires nats-server v2.10.0).
      #   @return [Hash]
      # @!attribute allow_msg_ttl
      #   Whether messages can be published with a TTL of their own
      #   (requires nats-server v2.11.0). Once enabled, it cannot be
      #   disabled, and before v2.11.2 it cannot be enabled by an update.
      #   @return [Boolean]
      # @!attribute subject_delete_marker_ttl
      #   Nanoseconds to keep the marker that the server leaves when the last
      #   message of a subject expires, at least a second (requires
      #   nats-server v2.11.0). Before v2.11.2 it needs allow_msg_ttl. From
      #   v2.11.2 on, setting it enables allow_msg_ttl and allow_rollup_hdrs,
      #   and allows purges, so an update cannot set it on a stream that
      #   denies them.
      #   @return [Integer]
      # @!attribute allow_msg_counter
      #   Whether the stream holds counters, which cannot change later
      #   (requires nats-server v2.12.0).
      #   @return [Boolean]
      # @!attribute allow_atomic
      #   Whether messages can be published in atomic batches
      #   (requires nats-server v2.12.0).
      #   @return [Boolean]
      # @!attribute allow_msg_schedules
      #   Whether messages can schedule messages (requires nats-server
      #   v2.12.0). Once enabled, it cannot be disabled. Setting it enables
      #   allow_rollup_hdrs and allows purges, so an update cannot set it on
      #   a stream that denies them.
      #   @return [Boolean]
      # @!attribute persist_mode
      #   "async" to acknowledge messages before they are flushed to disk,
      #   or "default"; the server reports the default as nil. It cannot
      #   change later (requires nats-server v2.12.0).
      #   @return [String, nil]
      # @!attribute allow_batched
      #   Whether messages can be published in fast batches
      #   (requires nats-server v2.14.0).
      #   @return [Boolean]
      StreamConfig = Struct.new(
        :name,
        :description,
        :subjects,
        :retention,
        :max_consumers,
        :max_msgs,
        :max_bytes,
        :discard,
        :max_age,
        :max_msgs_per_subject,
        :max_msg_size,
        :storage,
        :num_replicas,
        :no_ack,
        :duplicate_window,
        :placement,
        :mirror,
        :sources,
        :sealed,
        :deny_delete,
        :deny_purge,
        :allow_rollup_hdrs,
        :republish,
        :allow_direct,
        :mirror_direct,
        :metadata,
        :compression,
        :first_seq,
        :subject_transform,
        :consumer_limits,
        :allow_msg_ttl,
        :subject_delete_marker_ttl,
        :allow_msg_counter,
        :allow_atomic,
        :allow_msg_schedules,
        :persist_mode,
        :allow_batched,
        :discard_new_per_subject,
        keyword_init: true
      ) do
        def initialize(opts = {})
          # Filter unrecognized fields just in case.
          rem = opts.keys - members
          opts.delete_if { |k| rem.include?(k) }
          super
        end
      end

      # StreamInfo is the info about a stream from JetStream.
      #
      # @!attribute type
      #   @return [String]
      # @!attribute config
      #   @return [Hash]
      # @!attribute created
      #   @return [String]
      # @!attribute state
      #   @return [Hash]
      # @!attribute domain
      #   @return [String]
      # @!attribute mirror
      #   State of the stream's mirror, such as its lag and subject
      #   transforms, as a Hash.
      #   @return [Hash]
      # @!attribute sources
      #   State of each of the stream's sources, such as its lag and subject
      #   transforms, as Hashes.
      #   @return [Array<Hash>]
      # @!attribute cluster
      #   The cluster of the stream, such as its leader, its replicas and,
      #   as leader_since, when the leader was elected (requires nats-server
      #   v2.12.0). A standalone server reports only itself, as the leader.
      #   The values are the server's: leader_since is a String, which
      #   leader_since_time parses, and the active of the replicas is in
      #   nanoseconds.
      #   @return [ClusterInfo]
      # @!attribute ts
      #   When the server reported this info (requires nats-server v2.10.0).
      #   @return [Time]
      StreamInfo = Struct.new(:type, :config, :created, :state, :domain,
        :mirror, :sources, :cluster, :ts,
        keyword_init: true) do
        def initialize(opts = {})
          opts[:config] = StreamConfig.new(opts[:config])
          opts[:state] = StreamState.new(opts[:state])
          opts[:created] = ::Time.parse(opts[:created])
          opts[:ts] = ::Time.parse(opts[:ts]) if opts[:ts]
          opts[:cluster] = ClusterInfo.decode(opts[:cluster])

          # Filter fields and freeze.
          rem = opts.keys - members
          opts.delete_if { |k| rem.include?(k) }
          super
          freeze
        end
      end

      # StreamState is the state of a stream.
      #
      # @!attribute messages
      #   @return [Integer]
      # @!attribute bytes
      #   @return [Integer]
      # @!attribute first_seq
      #   @return [Integer]
      # @!attribute first_ts
      #   @return [String] When the first message was stored, as the server sent it.
      # @!attribute last_seq
      #   @return [Integer]
      # @!attribute last_ts
      #   @return [String] When the last message was stored, as the server sent it.
      # @!attribute consumer_count
      #   @return [Integer]
      # @!attribute deleted
      #   Sequences of the messages deleted from within the stream, with
      #   the deleted_details option of stream_info only.
      #   @return [Array<Integer>, nil]
      # @!attribute num_deleted
      #   Number of messages deleted from within the stream, which leave
      #   gaps between its first and last sequence; nil for none.
      #   @return [Integer, nil]
      # @!attribute num_subjects
      #   Number of subjects that the stream has messages on; nil for none.
      #   @return [Integer, nil]
      # @!attribute subjects
      #   Number of messages of each subject that matches the
      #   subjects_filter option of stream_info, by subject.
      #   @return [Hash{String => Integer}, nil]
      # @!attribute lost
      #   Messages the server lost from the storage of the stream, as when
      #   its files were corrupt.
      #   @return [LostStreamData, nil]
      StreamState = Struct.new(:messages, :bytes, :first_seq, :first_ts,
        :last_seq, :last_ts, :consumer_count,
        :deleted, :num_deleted, :num_subjects, :subjects, :lost,
        keyword_init: true) do
        def initialize(opts = {})
          # The subjects are keys of a JSON object, which come as Symbols.
          opts[:subjects] = opts[:subjects].transform_keys(&:to_s) if opts[:subjects]
          opts[:lost] = LostStreamData.new(opts[:lost]) if opts[:lost].is_a?(Hash)
          rem = opts.keys - members
          opts.delete_if { |k| rem.include?(k) }
          super
        end

        # @return [Time, nil] first_ts as a Time, like FirstTime of nats.go;
        #   nil for an empty stream.
        def first_time
          JS.parse_time(first_ts)
        end

        # @return [Time, nil] last_ts as a Time, like LastTime of nats.go;
        #   nil for a stream that never had a message.
        def last_time
          JS.parse_time(last_ts)
        end
      end

      # LostStreamData are the messages that the server lost from the
      # storage of a stream.
      #
      # @!attribute msgs
      #   @return [Array<Integer>] Sequences of the messages lost.
      # @!attribute bytes
      #   @return [Integer] Bytes lost.
      LostStreamData = Struct.new(:msgs, :bytes, keyword_init: true) do
        def initialize(opts = {})
          rem = opts.keys - members
          opts.delete_if { |k| rem.include?(k) }
          super
          freeze
        end
      end

      # StreamCreateResponse is the response from the JetStream $JS.API.STREAM.CREATE API.
      #
      # @!attribute type
      #   @return [String]
      # @!attribute config
      #   @return [StreamConfig]
      # @!attribute created
      #   @return [String]
      # @!attribute state
      #   @return [StreamState]
      # @!attribute did_create
      #   @return [Boolean]
      StreamCreateResponse = Struct.new(:type, :config, :created, :state, :did_create,
        keyword_init: true) do
        def initialize(opts = {})
          rem = opts.keys - members
          opts.delete_if { |k| rem.include?(k) }
          opts[:config] = StreamConfig.new(opts[:config])
          opts[:state] = StreamState.new(opts[:state])
          super
          freeze
        end
      end

      # StreamPurgeResponse is the response from the JetStream $JS.API.STREAM.PURGE API.
      #
      # @!attribute success
      #   @return [Boolean]
      # @!attribute purged
      #   @return [Integer] The number of messages purged.
      StreamPurgeResponse = Struct.new(:success, :purged, keyword_init: true) do
        def initialize(opts = {})
          rem = opts.keys - members
          opts.delete_if { |k| rem.include?(k) }
          super
          freeze
        end
      end

      # RawStreamMsg is a message stored in a stream, as get_msg returns it.
      #
      # @!attribute subject
      #   @return [String]
      # @!attribute seq
      #   @return [Integer] The stream sequence of the message.
      # @!attribute data
      #   @return [String]
      # @!attribute headers
      #   The headers of the message, a String, or an Array of Strings for a
      #   name it has more than once; a direct get also has the headers of
      #   the server, such as Nats-Stream, Nats-Sequence and Nats-Time-Stamp.
      #   @return [Hash, nil]
      # @!attribute time
      #   @return [Time] When the message was stored, like Time of nats.go.
      RawStreamMsg = Struct.new(:subject, :seq, :data, :headers, :time, keyword_init: true) do
        def initialize(opts)
          opts[:data] = Base64.decode64(opts[:data]) if opts[:data]
          opts[:time] = JS.parse_time(opts[:time]) if opts[:time].is_a?(String)
          if opts[:hdrs]
            header = Base64.decode64(opts[:hdrs])
            hdr = {}
            lines = header.lines
            lines.slice(1, header.size).each do |line|
              line.rstrip!
              next if line.empty?
              key, value = line.strip.split(/\s*:\s*/, 2)
              NATS::Msg.add_header_value(hdr, key, value)
            end
            opts[:headers] = hdr
          end

          # Filter out members not present.
          rem = opts.keys - members
          opts.delete_if { |k| rem.include?(k) }
          super
        end

        def sequence
          seq
        end
      end
    end
  end
end
