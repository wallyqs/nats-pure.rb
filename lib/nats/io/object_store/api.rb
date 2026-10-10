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

require "json"
require "time"

module NATS
  class ObjectStore
    # ObjectStore::API are the types of the object store, which mirror those
    # of nats.go, and the JSON of the meta information of objects.
    module API
      # normalize_headers makes the headers of an object Hash header names,
      # as Strings, to Arrays of their values, as nats.go has them.
      def self.normalize_headers(headers)
        return if headers.nil?

        headers.to_h { |key, value| [key.to_s, Array(value)] }
      end

      # ObjectStoreConfig is the configuration of an object store.
      #
      # @!attribute bucket
      #   @return [String] Name of the object store.
      # @!attribute description
      #   @return [String]
      # @!attribute ttl
      #   @return [Integer] Seconds after which objects expire; by default they do not.
      # @!attribute max_bytes
      #   @return [Integer] Maximum size of the object store.
      # @!attribute storage
      #   @return [String] "file", the default, or "memory".
      # @!attribute replicas
      #   @return [Integer]
      # @!attribute placement
      #   @return [Hash] Placement of the stream in a cluster, as `{cluster:, tags:}`.
      # @!attribute compression
      #   @return [Boolean] Compress the stream with S2 (requires nats-server v2.10.0).
      # @!attribute metadata
      #   @return [Hash] Freeform metadata of the object store (requires nats-server v2.10.0).
      ObjectStoreConfig = Struct.new(:bucket, :description, :ttl, :max_bytes,
        :storage, :replicas, :placement, :compression, :metadata,
        keyword_init: true) do
        def initialize(opts = {})
          super(**opts.slice(*members))
        end
      end

      # ObjectLink is the target of a link: an object, or a whole object
      # store when it has no name.
      #
      # @!attribute bucket
      #   @return [String]
      # @!attribute name
      #   @return [String, nil]
      ObjectLink = Struct.new(:bucket, :name, keyword_init: true) do
        def initialize(opts = {})
          super(**opts.transform_keys(&:to_sym).slice(*members))
        end

        def to_json_hash
          {bucket: bucket, name: (name if name && !name.empty?)}.compact
        end
      end

      # ObjectMetaOptions are the options of an object.
      #
      # @!attribute link
      #   @return [ObjectLink, nil] Set by add_link and add_bucket_link.
      # @!attribute max_chunk_size
      #   @return [Integer, nil] Size of the chunks of the object; 128 KiB by default.
      ObjectMetaOptions = Struct.new(:link, :max_chunk_size, keyword_init: true) do
        def initialize(opts = {})
          opts = opts.transform_keys(&:to_sym).slice(*members)
          opts[:link] = ObjectLink.new(opts[:link]) if opts[:link].is_a?(Hash)
          super(**opts)
        end

        def to_json_hash
          {
            link: link&.to_json_hash,
            max_chunk_size: (max_chunk_size if max_chunk_size && max_chunk_size > 0)
          }.compact
        end
      end

      # ObjectMeta is the information about an object given when putting it.
      #
      # @!attribute name
      #   @return [String] Name of the object, unique in the object store.
      # @!attribute description
      #   @return [String, nil]
      # @!attribute headers
      #   @return [Hash{String => Array<String>}, nil] Headers of the object, as
      #     header names to their values; a String value is taken as one value.
      # @!attribute metadata
      #   @return [Hash{String => String}, nil]
      # @!attribute options
      #   @return [ObjectMetaOptions, nil]
      ObjectMeta = Struct.new(:name, :description, :headers, :metadata, :options,
        keyword_init: true) do
        def initialize(opts = {})
          opts = opts.transform_keys(&:to_sym).slice(*members)
          opts[:options] = ObjectMetaOptions.new(opts[:options]) if opts[:options].is_a?(Hash)
          super(**opts)
        end
      end

      # ObjectInfo is the information about an object in an object store:
      # its ObjectMeta, and how it is stored.
      #
      # @!attribute name
      #   @return [String]
      # @!attribute description
      #   @return [String, nil]
      # @!attribute headers
      #   @return [Hash{String => Array<String>}, nil]
      # @!attribute metadata
      #   @return [Hash{String => String}, nil]
      # @!attribute options
      #   @return [ObjectMetaOptions, nil]
      # @!attribute bucket
      #   @return [String] Name of the object store.
      # @!attribute nuid
      #   @return [String] Unique id of the object, which names the subject of its chunks.
      # @!attribute size
      #   @return [Integer] Size of the data of the object.
      # @!attribute mtime
      #   @return [Time] When the server stored the meta information of the
      #     object; the client's clock on the info that put returns.
      # @!attribute chunks
      #   @return [Integer] Number of chunks of the data.
      # @!attribute digest
      #   @return [String, nil] "SHA-256=" and the base64url SHA-256 of the data.
      # @!attribute deleted
      #   @return [Boolean, nil]
      ObjectInfo = Struct.new(:name, :description, :headers, :metadata, :options,
        :bucket, :nuid, :size, :mtime, :chunks, :digest, :deleted,
        keyword_init: true) do
        def initialize(opts = {})
          opts = opts.transform_keys(&:to_sym).slice(*members)
          opts[:options] = ObjectMetaOptions.new(opts[:options]) if opts[:options].is_a?(Hash)
          opts[:mtime] = Time.parse(opts[:mtime]) if opts[:mtime].is_a?(String)
          opts[:headers] = API.normalize_headers(opts[:headers])
          super(**opts)
        end

        # Parses the JSON of the meta information of an object.
        def self.from_json(data)
          new(JSON.parse(data))
        end

        # Whether the object is a link to another object or object store.
        def link?
          !options.nil? && !options.link.nil?
        end

        def deleted?
          deleted == true
        end

        # The JSON of the meta information of the object, as nats.go writes it,
        # without a modification time, which is the time the server stores it.
        def to_json(*args)
          {
            name: name,
            description: (description if description && !description.empty?),
            headers: (API.normalize_headers(headers) if headers && !headers.empty?),
            metadata: (metadata if metadata && !metadata.empty?),
            options: options&.to_json_hash,
            bucket: bucket,
            nuid: nuid,
            size: size || 0,
            mtime: "0001-01-01T00:00:00Z",
            chunks: chunks || 0,
            digest: (digest if digest && !digest.empty?),
            deleted: (true if deleted)
          }.compact.to_json(*args)
        end
      end

      # ObjectResult is an object that get read: its info, and its data
      # unless get wrote it to an IO.
      #
      # @!attribute info
      #   @return [ObjectInfo]
      # @!attribute data
      #   @return [String, nil]
      ObjectResult = Struct.new(:info, :data, keyword_init: true)
    end
  end
end
