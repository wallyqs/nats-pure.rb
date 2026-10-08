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
    module Manager
      # key_value binds to an existing bucket, like KeyValue of nats.go.
      # @param bucket [String] Name of the bucket.
      # @return [KeyValue]
      # @raise [KeyValue::InvalidBucketNameError] When the name is not that of a bucket.
      # @raise [KeyValue::BucketNotFoundError] When the bucket does not exist.
      def key_value(bucket, params = {})
        KeyValue.validate_bucket_name(bucket)
        stream = "KV_#{bucket}"
        begin
          si = stream_info(stream)
        rescue NATS::JetStream::Error::NotFound
          raise BucketNotFoundError.new("nats: bucket not found")
        end
        if si.config.max_msgs_per_subject < 1
          raise BadBucketError.new("nats: bad bucket")
        end

        key_value_for(si.config, params[:validate_keys])
      end

      # create_key_value creates a KeyValue bucket, like CreateKeyValue of nats.go.
      # @param config [KeyValue::API::KeyValueConfig, Hash, String] Configuration of the bucket, or its name.
      # @return [KeyValue]
      # @raise [KeyValue::BucketExistsError] When the bucket exists with another configuration.
      # @raise [KeyValue::InvalidBucketNameError] When the name is not that of a bucket.
      # @raise [KeyValue::KeyValueConfigRequiredError] When the config is nil.
      def create_key_value(config)
        stream = key_value_stream_config(config)
        si = begin
          add_stream(stream)
        rescue NATS::JetStream::Error::StreamNameAlreadyInUse => e
          raise KeyValue::BucketExistsError.new(
            code: e.code,
            err_code: e.err_code,
            description: e.description,
            bucket: stream.name.delete_prefix("KV_")
          )
        end
        key_value_for(si.config, config_validate_keys(config))
      end

      # update_key_value changes the configuration of an existing bucket,
      # like UpdateKeyValue of nats.go. The config replaces the bucket's, so
      # settings left out take their defaults.
      # @param config [KeyValue::API::KeyValueConfig, Hash] New configuration of the bucket.
      # @return [KeyValue]
      # @raise [KeyValue::BucketNotFoundError] When the bucket does not exist.
      def update_key_value(config)
        stream = key_value_stream_config(config)
        si = begin
          update_stream(stream)
        rescue NATS::JetStream::Error::StreamNotFound
          raise BucketNotFoundError.new("nats: bucket not found: #{stream.name.delete_prefix("KV_")}")
        end
        key_value_for(si.config, config_validate_keys(config))
      end

      # create_or_update_key_value creates a bucket, or changes the
      # configuration of the bucket if it exists, like
      # CreateOrUpdateKeyValue of nats.go.
      # @param config [KeyValue::API::KeyValueConfig, Hash] Configuration of the bucket.
      # @return [KeyValue]
      def create_or_update_key_value(config)
        stream = key_value_stream_config(config)
        si = begin
          update_stream(stream)
        rescue NATS::JetStream::Error::StreamNotFound
          add_stream(stream)
        end
        key_value_for(si.config, config_validate_keys(config))
      end

      # key_value_store_names returns the names of the KeyValue buckets,
      # like KeyValueStoreNames of nats.go: those of the streams named KV_*
      # that take the subjects of a bucket.
      # @return [Array<String>]
      def key_value_store_names
        bucket_stream_pages("#{@prefix}.STREAM.NAMES", "$KV.*.>").filter_map do |name|
          name.delete_prefix("KV_") if name.start_with?("KV_")
        end
      end

      # key_value_stores returns the status of each KeyValue bucket, like
      # KeyValueStores of nats.go.
      # @return [Array<KeyValue::BucketStatus>]
      def key_value_stores
        bucket_stream_pages("#{@prefix}.STREAM.LIST", "$KV.*.>").filter_map do |info|
          name = info[:config][:name]
          next unless name.start_with?("KV_")

          BucketStatus.new(JetStream::API::StreamInfo.new(info), name.delete_prefix("KV_"))
        end
      end

      # delete_key_value deletes a bucket, like DeleteKeyValue of nats.go.
      # @param bucket [String] Name of the bucket.
      # @return [Boolean]
      # @raise [KeyValue::InvalidBucketNameError] When the name is not that of a bucket.
      def delete_key_value(bucket)
        KeyValue.validate_bucket_name(bucket)
        delete_stream("KV_#{bucket}")
      end

      private

      # key_value_stream_config makes the config of the stream of a bucket.
      def key_value_stream_config(config)
        raise KeyValue::KeyValueConfigRequiredError if config.nil?

        config = if !config.is_a?(KeyValue::API::KeyValueConfig)
          config = {bucket: config} if config.is_a?(String)
          KeyValue::API::KeyValueConfig.new(config)
        else
          # Work on a copy, which the defaults below change.
          config.dup
        end
        KeyValue.validate_bucket_name(config.bucket)
        config.history ||= 1
        config.replicas ||= 1
        duplicate_window = 2 * 60 # 2 minutes
        if config.ttl
          if config.ttl < duplicate_window
            duplicate_window = config.ttl
          end
          config.ttl = config.ttl * ::NATS::NANOSECONDS
        end

        if config.history > KeyValue::KEY_VALUE_MAX_HISTORY
          raise NATS::KeyValue::KeyHistoryTooLargeError
        end

        unless [true, false, nil].include?(config.compression)
          raise ArgumentError.new("nats: compression must be true or false")
        end

        limit_marker_ttl = config.limit_marker_ttl
        limit_marker_ttl = nil if limit_marker_ttl == 0
        if limit_marker_ttl
          # Like nats.go, check that the server knows subject delete markers.
          raise NATS::KeyValue::LimitMarkerTTLNotSupportedError if account_info.dig(:api, :level).to_i < 1
        end

        subjects = ["$KV.#{config.bucket}.>"]
        mirror = nil
        sources = nil
        if config.mirror
          # Like nats.go, a mirror takes the keys of its origin as they are,
          # and so has no subjects of its own.
          mirror = key_value_source(config.mirror)
          mirror[:name] = "KV_#{mirror[:name]}" unless mirror[:name].start_with?("KV_")
          subjects = nil
        elsif config.sources && !config.sources.empty?
          sources = config.sources.map { |source| key_value_bucket_source(source, config.bucket) }
        end

        JetStream::API::StreamConfig.new(
          name: "KV_#{config.bucket}",
          description: config.description,
          subjects: subjects,
          mirror: mirror,
          sources: sources,
          # A mirror answers the direct gets of its origin, so it allows
          # direct gets itself unless told otherwise.
          allow_direct: (mirror && config.direct.nil?) ? true : config.direct,
          mirror_direct: mirror ? true : nil,
          allow_rollup_hdrs: true,
          deny_delete: true,
          discard: "new",
          duplicate_window: duplicate_window * ::NATS::NANOSECONDS,
          max_age: config.ttl,
          max_bytes: config.max_bytes,
          max_consumers: -1,
          max_msg_size: config.max_value_size,
          max_msgs: -1,
          max_msgs_per_subject: config.history,
          num_replicas: config.replicas,
          storage: config.storage,
          placement: config.placement,
          republish: config.republish,
          compression: config.compression ? "s2" : nil,
          metadata: config.metadata,
          allow_msg_ttl: limit_marker_ttl ? true : nil,
          subject_delete_marker_ttl: limit_marker_ttl && limit_marker_ttl * ::NATS::NANOSECONDS
        )
      end

      # key_value_source makes a stream source of a bucket's mirror or
      # sources, turning a domain into the external API prefix of the
      # domain, as nats.go does.
      def key_value_source(source)
        source = source.to_h.transform_keys(&:to_sym)
        domain = source.delete(:domain)
        if domain && !domain.empty?
          raise ArgumentError.new("nats: domain and external are both set") if source[:external]
          source[:external] = {api: "$JS.#{domain}.API"}
        end
        time = source[:opt_start_time]
        source[:opt_start_time] = time.utc.iso8601(9) if time.is_a?(Time)
        source
      end

      # key_value_bucket_source makes the stream source of a bucket that
      # another bucket takes the keys of, mapping its keys to that bucket.
      def key_value_bucket_source(source, bucket)
        source = key_value_source(source)
        # Like nats.go, a source with transforms of its own is taken as is,
        # even one that is not a bucket.
        transforms = source[:subject_transforms]
        return source if transforms && !transforms.empty?

        name = source[:name]
        source_bucket = name.delete_prefix("KV_")
        source[:name] = "KV_#{name}" unless name.start_with?("KV_")
        # A bucket of the same name in another domain has the same keys.
        if source[:external].nil? || source_bucket != bucket
          source[:subject_transforms] = [{src: "$KV.#{source_bucket}.>", dest: "$KV.#{bucket}.>"}]
        end
        source
      end

      def config_validate_keys(config)
        config.is_a?(String) ? nil : config[:validate_keys]
      end

      # key_value_for makes the KeyValue of the bucket of a stream.
      def key_value_for(stream_config, validate_keys)
        bucket = stream_config.name.delete_prefix("KV_")
        pre = "$KV.#{bucket}."
        # Like nats.go, the writes go through the API prefix of the context
        # unless it is the default $JS.API: one for a domain, which the server
        # maps to the subjects of the buckets ($JS.<domain>.API.$KV.> to
        # $KV.>), or one under which another account imports JetStream and
        # the subjects of its buckets.
        js_pre = (@prefix == "$JS.API") ? "" : "#{@prefix.chomp(".")}."
        put_pre = js_pre.empty? ? nil : "#{js_pre}#{pre}"
        if (mirror = stream_config.mirror)
          # A mirror holds the keys of its origin, to which the writes go, as
          # in nats.go. The writes to a bucket of another domain go through
          # the API prefix of that domain instead. Unlike nats.go, which looks
          # up the keys of a mirror in the same domain under the mirror's
          # name, and so does not find them, the reads take the origin's name
          # too.
          origin = mirror[:name].delete_prefix("KV_")
          pre = "$KV.#{origin}."
          api = mirror.dig(:external, :api)
          put_pre = (api.nil? || api.empty?) ? "#{js_pre}#{pre}" : "#{api}.#{pre}"
        end
        KeyValue.new(
          name: bucket,
          stream: stream_config.name,
          pre: pre,
          put_pre: put_pre,
          js: self,
          direct: stream_config.allow_direct,
          validate_keys: validate_keys
        )
      end

      # bucket_stream_pages pages through the names or infos of the streams
      # that take the subjects matching a filter, such as those of buckets.
      def bucket_stream_pages(req_subject, filter)
        items = []
        loop do
          req = {subject: filter, offset: items.size}
          result = api_request(req_subject, req.to_json)
          page = result[:streams] || []
          items.concat(page)
          break if page.empty? || items.size >= result[:total].to_i
        end
        items
      end
    end
  end
end
