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

require_relative "../errors"

module NATS
  class ObjectStore
    class Error < NATS::Error
      # The message of nats.go for the error.
      MESSAGE = nil

      def initialize(msg = nil)
        super(msg || "nats: #{self.class::MESSAGE}")
      end
    end

    # When the object store config is missing (ErrObjectConfigRequired).
    class ObjectConfigRequiredError < Error
      MESSAGE = "object-store config required"
    end

    # When the name of an object store is invalid (ErrInvalidStoreName).
    class InvalidStoreNameError < Error
      MESSAGE = "invalid object-store name"
    end

    # When an object store does not exist (ErrBucketNotFound).
    class BucketNotFoundError < Error
      MESSAGE = "bucket not found"
    end

    # When an object store exists with another config (ErrBucketExists).
    class BucketExistsError < Error
      MESSAGE = "bucket name already in use"
    end

    # When an object is missing or its meta information is invalid (ErrBadObjectMeta).
    class BadObjectMetaError < Error
      MESSAGE = "object-store meta information invalid"
    end

    # When an object does not exist, or was deleted (ErrObjectNotFound).
    class ObjectNotFoundError < Error
      MESSAGE = "object not found"
    end

    # When the data of an object does not match its digest (ErrDigestMismatch).
    class DigestMismatchError < Error
      MESSAGE = "received a corrupt object, digests do not match"
    end

    # When a digest is not "SHA-256=<base64url>" (ErrInvalidDigestFormat).
    class InvalidDigestFormatError < Error
      MESSAGE = "object digest hash has invalid format"
    end

    # When list finds no objects (ErrNoObjectsFound).
    class NoObjectsFoundError < Error
      MESSAGE = "no objects found"
    end

    # When an object, not a link, has the name (ErrObjectAlreadyExists).
    class ObjectAlreadyExistsError < Error
      MESSAGE = "an object already exists with that name"
    end

    # When a name is missing (ErrNameRequired).
    class NameRequiredError < Error
      MESSAGE = "name is required"
    end

    # When put is given a link, which add_link and add_bucket_link set (ErrLinkNotAllowed).
    class LinkNotAllowedError < Error
      MESSAGE = "link cannot be set when putting the object in bucket"
    end

    # When add_link is not given an object (ErrObjectRequired).
    class ObjectRequiredError < Error
      MESSAGE = "object required"
    end

    # When add_link is given a deleted object (ErrNoLinkToDeleted).
    class NoLinkToDeletedError < Error
      MESSAGE = "not allowed to link to a deleted object"
    end

    # When add_link is given a link (ErrNoLinkToLink).
    class NoLinkToLinkError < Error
      MESSAGE = "not allowed to link to another link"
    end

    # When get is given a link to an object store (ErrCantGetBucket).
    class CantGetBucketError < Error
      MESSAGE = "invalid Get, object is a link to a bucket"
    end

    # When add_bucket_link is not given an object store (ErrBucketRequired).
    class BucketRequiredError < Error
      MESSAGE = "bucket required"
    end

    # When add_bucket_link is given something else than an object store (ErrBucketMalformed).
    class BucketMalformedError < Error
      MESSAGE = "bucket malformed"
    end

    # When update_meta is given an object that does not exist (ErrUpdateMetaDeleted).
    class UpdateMetaDeletedError < Error
      MESSAGE = "cannot update meta for a deleted object"
    end
  end
end
