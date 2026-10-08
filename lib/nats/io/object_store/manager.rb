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
    # ObjectStore::Manager manages object stores, like ObjectStoreManager of nats.go.
    module Manager
      # object_store binds to an existing object store.
      # @param bucket [String] Name of the object store.
      # @return [ObjectStore]
      # @raise [ObjectStore::BucketNotFoundError] When the object store does not exist.
      def object_store(bucket)
        validate_object_store_name(bucket)
        si = begin
          stream_info("OBJ_#{bucket}")
        rescue NATS::JetStream::Error::StreamNotFound
          raise ObjectStore::BucketNotFoundError
        end
        object_store_for(si.config)
      end

      # create_object_store creates an object store, like CreateObjectStore of nats.go.
      # @param config [ObjectStore::API::ObjectStoreConfig, Hash, String] Configuration of the object store, or its name.
      # @return [ObjectStore]
      # @raise [ObjectStore::BucketExistsError] When the object store exists with another configuration.
      def create_object_store(config)
        stream = object_store_stream_config(config)
        si = begin
          add_stream(stream)
        rescue NATS::JetStream::Error::APIError => e
          raise e unless e.err_code == 10058

          raise ObjectStore::BucketExistsError.new("nats: bucket name already in use: #{stream.name.delete_prefix("OBJ_")}")
        end
        object_store_for(si.config)
      end

      # update_object_store changes the configuration of an existing object
      # store, like UpdateObjectStore of nats.go.
      # @param config [ObjectStore::API::ObjectStoreConfig, Hash] New configuration of the object store.
      # @return [ObjectStore]
      # @raise [ObjectStore::BucketNotFoundError] When the object store does not exist.
      def update_object_store(config)
        stream = object_store_stream_config(config)
        si = begin
          update_stream(stream)
        rescue NATS::JetStream::Error::StreamNotFound
          raise ObjectStore::BucketNotFoundError.new("nats: bucket not found: #{stream.name.delete_prefix("OBJ_")}")
        end
        object_store_for(si.config)
      end

      # create_or_update_object_store creates an object store, or changes its
      # configuration if it exists, like CreateOrUpdateObjectStore of nats.go.
      # @param config [ObjectStore::API::ObjectStoreConfig, Hash] Configuration of the object store.
      # @return [ObjectStore]
      def create_or_update_object_store(config)
        stream = object_store_stream_config(config)
        si = begin
          update_stream(stream)
        rescue NATS::JetStream::Error::StreamNotFound
          add_stream(stream)
        end
        object_store_for(si.config)
      end

      # delete_object_store deletes an object store and all its objects.
      # @param bucket [String] Name of the object store.
      # @return [Boolean]
      # @raise [ObjectStore::BucketNotFoundError] When the object store does not exist.
      def delete_object_store(bucket)
        validate_object_store_name(bucket)
        delete_stream("OBJ_#{bucket}")
      rescue NATS::JetStream::Error::StreamNotFound
        raise ObjectStore::BucketNotFoundError.new("nats: bucket not found: #{bucket}")
      end

      # object_store_names returns the names of the object stores, like
      # ObjectStoreNames of nats.go.
      # @return [Array<String>]
      def object_store_names
        bucket_stream_pages("#{@prefix}.STREAM.NAMES", "$O.*.C.>").filter_map do |name|
          name.delete_prefix("OBJ_") if name.start_with?("OBJ_")
        end
      end

      # object_stores returns the status of each object store, like
      # ObjectStores of nats.go.
      # @return [Array<ObjectStore::BucketStatus>]
      def object_stores
        bucket_stream_pages("#{@prefix}.STREAM.LIST", "$O.*.C.>").filter_map do |info|
          name = info[:config][:name]
          next unless name.start_with?("OBJ_")

          ObjectStore::BucketStatus.new(JetStream::API::StreamInfo.new(info), name.delete_prefix("OBJ_"))
        end
      end

      private

      def validate_object_store_name(bucket)
        raise ObjectStore::InvalidStoreNameError unless bucket.is_a?(String) && bucket.match?(ObjectStore::VALID_BUCKET_RE)
      end

      # object_store_stream_config makes the config of the stream of an
      # object store, as nats.go does.
      def object_store_stream_config(config)
        raise ObjectStore::ObjectConfigRequiredError if config.nil?

        config = if config.is_a?(ObjectStore::API::ObjectStoreConfig)
          config
        else
          config = {bucket: config} if config.is_a?(String)
          ObjectStore::API::ObjectStoreConfig.new(config)
        end
        validate_object_store_name(config.bucket)
        unless [true, false, nil].include?(config.compression)
          raise ArgumentError.new("nats: compression must be true or false")
        end

        bucket = config.bucket
        JetStream::API::StreamConfig.new(
          name: "OBJ_#{bucket}",
          description: config.description,
          subjects: ["$O.#{bucket}.C.>", "$O.#{bucket}.M.>"],
          max_age: config.ttl && config.ttl * ::NATS::NANOSECONDS,
          max_bytes: config.max_bytes,
          storage: config.storage,
          num_replicas: config.replicas || 1,
          placement: config.placement,
          discard: "new",
          allow_rollup_hdrs: true,
          allow_direct: true,
          metadata: config.metadata,
          compression: config.compression ? "s2" : nil
        )
      end

      # object_store_for makes the ObjectStore of a stream.
      def object_store_for(stream_config)
        ObjectStore.new(
          name: stream_config.name.delete_prefix("OBJ_"),
          stream: stream_config.name,
          js: self,
          direct: stream_config.allow_direct
        )
      end
    end
  end
end
