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
      def key_value(bucket, params = {})
        stream = "KV_#{bucket}"
        begin
          si = stream_info(stream)
        rescue NATS::JetStream::Error::NotFound
          raise BucketNotFoundError.new("nats: bucket not found")
        end
        if si.config.max_msgs_per_subject < 1
          raise BadBucketError.new("nats: bad bucket")
        end

        KeyValue.new(
          name: bucket,
          stream: stream,
          pre: "$KV.#{bucket}.",
          js: self,
          direct: si.config.allow_direct,
          validate_keys: params[:validate_keys]
        )
      end

      # create_key_value creates a KeyValue bucket, like CreateKeyValue of nats.go.
      # @param config [KeyValue::API::KeyValueConfig, Hash, String] Configuration of the bucket, or its name.
      # @return [KeyValue]
      def create_key_value(config)
        stream = key_value_stream_config(config)
        si = add_stream(stream)
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
        kv_stream_pages("#{@prefix}.STREAM.NAMES").filter_map do |name|
          name.delete_prefix("KV_") if name.start_with?("KV_")
        end
      end

      # key_value_stores returns the status of each KeyValue bucket, like
      # KeyValueStores of nats.go.
      # @return [Array<KeyValue::BucketStatus>]
      def key_value_stores
        kv_stream_pages("#{@prefix}.STREAM.LIST").filter_map do |info|
          name = info[:config][:name]
          next unless name.start_with?("KV_")

          BucketStatus.new(JetStream::API::StreamInfo.new(info), name.delete_prefix("KV_"))
        end
      end

      def delete_key_value(bucket)
        delete_stream("KV_#{bucket}")
      end

      private

      # key_value_stream_config makes the config of the stream of a bucket.
      def key_value_stream_config(config)
        config = if !config.is_a?(KeyValue::API::KeyValueConfig)
          config = {bucket: config} if config.is_a?(String)
          KeyValue::API::KeyValueConfig.new(config)
        else
          # Work on a copy, which the defaults below change.
          config.dup
        end
        config.history ||= 1
        config.replicas ||= 1
        duplicate_window = 2 * 60 # 2 minutes
        if config.ttl
          if config.ttl < duplicate_window
            duplicate_window = config.ttl
          end
          config.ttl = config.ttl * ::NATS::NANOSECONDS
        end

        if config.history > 64
          raise NATS::KeyValue::KeyHistoryTooLargeError
        end

        unless [true, false, nil].include?(config.compression)
          raise ArgumentError.new("nats: compression must be true or false")
        end

        JetStream::API::StreamConfig.new(
          name: "KV_#{config.bucket}",
          description: config.description,
          subjects: ["$KV.#{config.bucket}.>"],
          allow_direct: config.direct,
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
          metadata: config.metadata
        )
      end

      def config_validate_keys(config)
        config.is_a?(String) ? nil : config[:validate_keys]
      end

      # key_value_for makes the KeyValue of the bucket of a stream.
      def key_value_for(stream_config, validate_keys)
        bucket = stream_config.name.delete_prefix("KV_")
        KeyValue.new(
          name: bucket,
          stream: stream_config.name,
          pre: "$KV.#{bucket}.",
          js: self,
          direct: stream_config.allow_direct,
          validate_keys: validate_keys
        )
      end

      # kv_stream_pages pages through the names or infos of the streams
      # that take the subjects of a bucket.
      def kv_stream_pages(req_subject)
        items = []
        loop do
          req = {subject: "$KV.*.>", offset: items.size}
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
