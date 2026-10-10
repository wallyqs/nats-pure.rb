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

require_relative "../errors"
require_relative "../jetstream/errors"

module NATS
  class KeyValue
    class Error < NATS::Error; end

    # When a key is not found.
    class KeyNotFoundError < Error
      attr_reader :entry, :op
      def initialize(params = {})
        @entry = params[:entry]
        @op = params[:op]
        @message = params[:message]
      end

      def to_s
        msg = "nats: key not found"
        msg = "#{msg}: #{@message}" if @message
        msg
      end
    end

    # When a key is not found because it was deleted.
    class KeyDeletedError < KeyNotFoundError
      def to_s
        "nats: key was deleted"
      end
    end

    # When there was no bucket present.
    class BucketNotFoundError < Error; end

    # When it is an invalid bucket.
    class BadBucketError < Error; end

    # Included in the errors of a revision that is not the latest of the
    # key, like ErrKeyRevisionMismatch of nats.go, which Update, Delete and
    # Purge return: KeyWrongLastSequenceError of update, and
    # KeyRevisionMismatchError of delete and purge with :last, so that
    # `rescue NATS::KeyValue::KeyRevisionMismatch` catches them all.
    module KeyRevisionMismatch; end

    # When the result is an unexpected sequence.
    class KeyWrongLastSequenceError < Error
      include KeyRevisionMismatch

      def initialize(msg)
        @msg = msg
      end

      def to_s
        "nats: #{@msg}"
      end
    end

    # When a key that create is to add exists, like ErrKeyExists of nats.go.
    # It is a KeyWrongLastSequenceError, which create raised before, with
    # the same message.
    class KeyExistsError < KeyWrongLastSequenceError; end

    # When delete or purge is given a :last revision that is not the latest
    # of the key, like ErrKeyRevisionMismatch of nats.go. It is the
    # NATS::JetStream::Error::WrongLastSequence that they raised before,
    # with its err_code, and a KeyRevisionMismatch like the
    # KeyWrongLastSequenceError of update.
    class KeyRevisionMismatchError < NATS::JetStream::Error::WrongLastSequence
      include KeyRevisionMismatch
    end

    # When a bucket name is invalid, like ErrInvalidBucketName of nats.go:
    # it is not made of letters, digits, "_" and "-". It is an
    # ArgumentError, as creating a bucket raised for most invalid names
    # before.
    class InvalidBucketNameError < ArgumentError
      def initialize(msg = "nats: invalid bucket name")
        super
      end
    end

    # When a bucket name is nil or empty, like ErrBucketRequired of nats.go.
    # It is an InvalidBucketNameError, which nats.go returns for one.
    class BucketRequiredError < InvalidBucketNameError
      def initialize(msg = "nats: bucket required")
        super
      end
    end

    # When there is no config for the bucket to create or update, like
    # ErrKeyValueConfigRequired of nats.go.
    class KeyValueConfigRequiredError < ArgumentError
      def initialize(msg = "nats: config required")
        super
      end
    end

    # When a bucket is created with the name of a bucket that has a
    # different configuration, like ErrBucketExists of nats.go. It is the
    # JetStream::Error::StreamNameAlreadyInUse of the bucket's stream, which
    # create_key_value raised before.
    class BucketExistsError < NATS::JetStream::Error::StreamNameAlreadyInUse
      # @return [String] The name of the bucket.
      attr_reader :bucket

      def initialize(params = {})
        super
        @bucket = params[:bucket]
      end

      def to_s
        "nats: bucket name already in use: #{@bucket}"
      end
    end

    # When there are no keys.
    class NoKeysFoundError < Error
      def to_s
        "nats: no keys found"
      end
    end

    # When history is too large.
    class KeyHistoryTooLargeError < Error
      def to_s
        "nats: history limited to a max of #{KEY_VALUE_MAX_HISTORY}"
      end
    end

    class InvalidKeyError < Error
      def to_s
        "nats: invalid key"
      end
    end

    # When delete is given a TTL, which only purge takes.
    class TTLOnDeleteNotSupportedError < Error
      def to_s
        "nats: TTL is not supported on delete"
      end
    end

    # When a bucket is created with a limit_marker_ttl on a server that does
    # not support it, before nats-server v2.11.0.
    class LimitMarkerTTLNotSupportedError < Error
      def to_s
        "nats: limit marker TTLs not supported by server"
      end
    end
  end
end
