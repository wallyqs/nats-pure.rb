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
    # Error is any error that may arise when interacting with JetStream.
    class Error < NATS::IO::Error
      # When there is a NATS::IO::NoResponders error after making a publish request.
      class NoStreamResponse < Error; end

      # When an invalid durable or consumer name was attempted to be used.
      class InvalidDurableName < Error; end

      # When the response to a publish is not an ack of JetStream: not a
      # JSON object, or one without the stream.
      class InvalidJSAck < Error; end

      # When an ack has already been acked.
      class MsgAlreadyAckd < Error; end

      # When the delivered message does not behave as a message delivered by JetStream,
      # for example when the ack reply has unrecognizable fields.
      class NotJSMessage < Error; end

      # When the stream name is invalid.
      class InvalidStreamName < Error; end

      # When the consumer name is invalid.
      class InvalidConsumerName < Error; end

      # When the server does not confirm that it deleted a message.
      class MsgDeleteUnsuccessful < Error; end

      # When a pull subscription is bound to a push consumer, one with a
      # deliver subject.
      class NotPullConsumer < Error; end

      # When a push subscription is bound to a pull consumer, one without a
      # deliver subject.
      class NotPushConsumer < Error; end

      # When a message to be acked is not bound to a subscription, as it was
      # not delivered by one.
      class MsgNotBound < Error; end

      # When a message to be acked has no reply subject to send the ack to.
      class MsgNoReply < Error; end

      # When the response of the JetStream API is not a JSON object.
      class InvalidJetStreamResponse < Error; end

      # When publish_async stalls for longer than its stall wait, as too
      # many messages await their acks.
      class TooManyStalledMsgs < Error; end

      # When a message published with publish_async is not acked within
      # its timeout.
      class AsyncPublishTimeout < Error; end

      # When js.cleanup_publisher ends a message published with
      # publish_async that still awaited its ack, like
      # ErrJetStreamPublisherClosed of nats.go.
      class PublisherClosed < Error; end

      # When a pull that asked for idle heartbeats heard nothing for two of
      # them, as when the server is gone or the consumer was deleted.
      class NoHeartbeat < Error; end

      # When a push consumer with idle heartbeats sent nothing for two of
      # them, as when the server is gone or the consumer was deleted,
      # reported to the error callback of the connection.
      class ConsumerNotActive < Error; end

      # When an idle heartbeat of a push consumer tells that it delivered up
      # to another consumer sequence than the last message that came to the
      # subscription, reported to the error callback of the connection, like
      # ErrConsumerSequenceMismatch of nats.go. The consumer could resume
      # from stream_resume_sequence.
      class ConsumerSequenceMismatch < Error
        attr_reader :stream_resume_sequence, :consumer_sequence, :last_consumer_sequence

        def initialize(stream_resume_sequence: 0, consumer_sequence: 0, last_consumer_sequence: 0)
          @stream_resume_sequence = stream_resume_sequence
          @consumer_sequence = consumer_sequence
          @last_consumer_sequence = last_consumer_sequence
          super("nats: sequence mismatch for consumer at sequence #{consumer_sequence} " \
                "(#{last_consumer_sequence - consumer_sequence} sequences behind), " \
                "should restart consumer from stream sequence #{stream_resume_sequence}")
        end
      end

      # When the messages of a MessagesContext are read after it was stopped
      # or drained, or the connection closed.
      class MsgIteratorClosed < Error; end

      # When an ordered consumer that was read with fetch is read with
      # consume or messages.
      class OrderedConsumerUsedAsFetch < Error; end

      # When an ordered consumer that was read with consume or messages is
      # read with fetch.
      class OrderedConsumerUsedAsConsume < Error; end

      # When an ordered consumer is read by two fetches at once, or by
      # consume or messages while another still runs.
      class OrderedConsumerConcurrentRequests < Error; end

      # When the info of an ordered consumer is asked for while it has no
      # consumer, as creating it again failed.
      class OrderedConsumerNotCreated < Error; end

      # When a batched direct get finds no message to get, like
      # ErrNoMessages of orbit.go jetstreamext.
      class NoMessages < Error
        def initialize(msg = "nats: no messages")
          super
        end
      end

      # When the server answers a batched direct get with a single message,
      # as servers before v2.11.0 do, like ErrBatchUnsupported of orbit.go
      # jetstreamext.
      class BatchUnsupported < Error
        def initialize(msg = "nats: batch get not supported by server")
          super
        end
      end

      # When a message of a batched direct get lacks the headers of the
      # stream, like ErrInvalidResponse of orbit.go jetstreamext.
      class InvalidStreamResponse < Error
        def initialize(msg = "nats: invalid stream response")
          super
        end
      end

      # When the server created or updated a stream without its subject
      # transform, as servers before v2.10.0 do, like
      # ErrStreamSubjectTransformNotSupported of nats.go.
      class StreamSubjectTransformNotSupported < Error; end

      # When the server created or updated a stream without the subject
      # transforms of its sources, as servers before v2.10.0 do. nats.go
      # returns ErrStreamSubjectTransformNotSupported, which this is a
      # StreamSubjectTransformNotSupported like.
      class StreamSourceSubjectTransformNotSupported < StreamSubjectTransformNotSupported; end

      # When the server created or updated a stream without all of its
      # sources, as servers before v2.2.0 do, like
      # ErrStreamSourceNotSupported of nats.go.
      class StreamSourceNotSupported < Error; end

      # When the server created a consumer without its filter_subjects, as
      # servers before v2.10.0 do, like
      # ErrConsumerMultipleFilterSubjectsNotSupported of nats.go.
      class ConsumerMultipleFilterSubjectsNotSupported < Error; end

      # When the server responds with an error from the JetStream API.
      class APIError < Error
        attr_accessor :code, :err_code, :description, :stream, :consumer, :seq

        def initialize(params = {})
          @code = params[:code]
          @err_code = params[:err_code]
          @description = params[:description]
          @stream = params[:stream]
          @consumer = params[:consumer]
          @seq = params[:seq]
        end

        def to_s
          if @stream && @consumer
            "#{@description} (status_code=#{@code}, err_code=#{@err_code}, stream=#{@stream}, consumer=#{@consumer})"
          elsif @stream
            "#{@description} (status_code=#{@code}, err_code=#{@err_code}, stream=#{@stream})"
          else
            "#{@description} (status_code=#{@code}, err_code=#{@err_code})"
          end
        end
      end

      # When JetStream is not currently available, this could be due to JetStream
      # not being enabled or temporarily unavailable due to a leader election when
      # running in cluster mode.
      # This condition is represented with a message that has 503 status code header.
      class ServiceUnavailable < APIError
        def initialize(params = {})
          super
          @code ||= 503
        end
      end

      # When there is a hard failure in the JetStream.
      # This condition is represented with a message that has 500 status code header.
      class ServerError < APIError
        def initialize(params = {})
          super
          @code ||= 500
        end
      end

      # When a JetStream object was not found.
      # This condition is represented with a message that has 404 status code header.
      class NotFound < APIError
        def initialize(params = {})
          super
          @code ||= 404
        end
      end

      # When the stream does not have the message.
      class MsgNotFound < NotFound; end

      # When the stream is not found.
      class StreamNotFound < NotFound
        def initialize(params = {})
          super
        end
      end

      # When the consumer or durable is not found by name.
      class ConsumerNotFound < NotFound
        def initialize(params = {})
          super
        end
      end

      # When the JetStream client makes an invalid request.
      # This condition is represented with a message that has 400 status code header.
      class BadRequest < APIError
        def initialize(params = {})
          super
          @code ||= 400
        end
      end

      # When a stream is created with the name of a stream that has a
      # different configuration.
      class StreamNameAlreadyInUse < BadRequest; end

      # When a consumer is created with the name of a consumer that has a
      # different configuration, or with the API of servers before v2.10.0.
      class ConsumerNameAlreadyInUse < BadRequest; end

      # When a stream, or the account, has as many consumers as it may.
      class MaximumConsumersLimit < BadRequest; end

      # When a consumer config has both filter_subject and filter_subjects.
      class DuplicateFilterSubjects < BadRequest; end

      # When the filter_subjects of a consumer config overlap.
      class OverlappingFilterSubjects < BadRequest; end

      # When the filter_subjects of a consumer config have an empty subject.
      class EmptyFilter < BadRequest; end

      # When a publish expects another last sequence of the stream, or of the
      # subject, than the stream has.
      class WrongLastSequence < BadRequest; end

      # When a message schedule is published to a stream without
      # allow_msg_schedules.
      class MessageSchedulesDisabled < BadRequest; end

      # When the pattern of a message schedule is invalid.
      class SchedulePatternInvalid < BadRequest; end

      # When the target of a message schedule is invalid.
      class ScheduleTargetInvalid < BadRequest; end

      # When the TTL of a message schedule is invalid.
      class ScheduleTTLInvalid < BadRequest; end

      # When the rollup of a message schedule is invalid.
      class ScheduleRollupInvalid < BadRequest; end

      # When the source of a message schedule is invalid.
      class ScheduleSourceInvalid < BadRequest; end

      # When a mirror is configured to allow message schedules.
      class MirrorWithMsgSchedules < BadRequest; end

      # When a stream with sources is configured to allow message schedules.
      class SourceWithMsgSchedules < BadRequest; end

      # When create_consumer finds the consumer already exists with a
      # different configuration.
      class ConsumerAlreadyExists < BadRequest; end

      # When a durable push consumer is created again while it is still
      # active, as when another subscription is bound to it; the err_code
      # 10105 that nats.go names JSErrCodeConsumerAlreadyExists.
      class ConsumerExistingActive < BadRequest; end

      # When update_consumer finds no consumer to update. The server reports
      # it as a bad request, so unlike ConsumerNotFound it is not NotFound.
      class ConsumerDoesNotExist < BadRequest; end

      # When reset_consumer is given a sequence that the consumer cannot be
      # reset to: one before its start, or any for a consumer that does
      # not deliver all messages or from a start sequence or time.
      class ConsumerInvalidReset < BadRequest; end

      # When the server could not create a consumer.
      class ConsumerCreate < ServerError; end

      # When JetStream is not enabled on the server.
      class JetStreamNotEnabled < ServiceUnavailable; end

      # When JetStream is not enabled for the account.
      class JetStreamNotEnabledForAccount < ServiceUnavailable; end

      # When the consumer of a pull was deleted, which ends fetches and
      # consumption.
      # This condition is represented with a message that has 409 status code header.
      class ConsumerDeleted < APIError
        def initialize(params = {})
          super
          @code ||= "409"
        end
      end

      # When the consumer of a pull got another leader, which does not
      # have the pull.
      # This condition is represented with a message that has 409 status code header.
      class ConsumerLeadershipChanged < APIError; end

      # When the server of a pull shut down.
      # This condition is represented with a message that has 409 status code header.
      class ServerShutdown < APIError; end

      # When a batch publisher is used after it was committed or discarded,
      # like ErrBatchClosed of orbit.go jetstreamext.
      class BatchClosed < Error
        def initialize(msg = "nats: batch publisher closed")
          super
        end
      end

      # When a batch with no messages is closed or published, like
      # ErrEmptyBatch of orbit.go jetstreamext.
      class EmptyBatch < Error
        def initialize(msg = "nats: no messages in batch")
          super
        end
      end

      # When the ack of a batch is not one of the batch: of another batch,
      # with another number of messages or none of a stream, like
      # ErrInvalidBatchAck of orbit.go jetstreamext.
      class InvalidBatchAck < Error
        def initialize(msg = "nats: invalid jetstream batch publish response")
          super
        end
      end

      # The errors with which the server refuses an atomic batch publish
      # (nats-server v2.12.0), named as in orbit.go jetstreamext, with the
      # error codes of nats-server. Each class has its error code as
      # ERR_CODE.

      # When the stream does not have allow_atomic (orbit.go
      # ErrBatchPublishNotEnabled).
      class BatchPublishNotEnabled < BadRequest; ERR_CODE = 10174; end

      # When a message of a batch has no batch sequence (orbit.go
      # ErrBatchPublishMissingSeq).
      class BatchPublishMissingSeq < BadRequest; ERR_CODE = 10175; end

      # When a batch is missing messages, or was abandoned as it timed out
      # (orbit.go ErrBatchPublishIncomplete).
      class BatchPublishIncomplete < BadRequest; ERR_CODE = 10176; end

      # When a message of a batch has a header that batches do not support,
      # Nats-Expected-Last-Msg-Id (orbit.go ErrBatchPublishUnsupportedHeader).
      class BatchPublishUnsupportedHeader < BadRequest; ERR_CODE = 10177; end

      # When the batch ID is longer than 64 characters (orbit.go
      # ErrBatchPublishInvalidID).
      class BatchPublishInvalidID < BadRequest; ERR_CODE = 10179; end

      # When a stream that mirrors another is given allow_atomic.
      class MirrorWithAtomicPublish < BadRequest; ERR_CODE = 10198; end

      # When a batch has more messages than the server allows, 1000 by
      # default (orbit.go ErrBatchPublishExceedsLimit).
      class BatchPublishExceedsLimit < BadRequest; ERR_CODE = 10199; end

      # When the commit header of a batch has a value the server does not
      # know (orbit.go ErrBatchPublishInvalidCommit).
      class BatchPublishInvalidCommit < BadRequest; ERR_CODE = 10200; end

      # When two messages of a batch have the same Nats-Msg-Id (orbit.go
      # ErrBatchPublishDuplicateMsgID).
      class BatchPublishDuplicateMsgID < BadRequest; ERR_CODE = 10201; end

      # When the server has too many atomic batches in flight; its status
      # code is 429 (orbit.go ErrAtomicPublishTooManyInflight).
      class AtomicPublishTooManyInflight < BadRequest; ERR_CODE = 10210; end

      # The errors with which the server refuses a fast batch publish
      # (nats-server v2.14.0), also named as in orbit.go jetstreamext.

      # When the stream does not have allow_batched (orbit.go
      # ErrFastBatchNotEnabled).
      class FastBatchNotEnabled < BadRequest; ERR_CODE = 10205; end

      # When the reply subject of a fast batch message is not one of a fast
      # batch (orbit.go ErrFastBatchInvalidPattern).
      class FastBatchInvalidPattern < BadRequest; ERR_CODE = 10206; end

      # When the fast batch ID is longer than 64 characters (orbit.go
      # ErrFastBatchInvalidID).
      class FastBatchInvalidID < BadRequest; ERR_CODE = 10207; end

      # When the server does not know the fast batch of a message after the
      # first, as the batch ended (orbit.go ErrFastBatchUnknownID).
      class FastBatchUnknownID < BadRequest; ERR_CODE = 10208; end

      # When a stream that mirrors another is given allow_batched.
      class MirrorWithBatchPublish < BadRequest; ERR_CODE = 10209; end

      # When the server has too many fast batches in flight; its status
      # code is 429 (orbit.go ErrBatchPublishTooManyInflight).
      class BatchPublishTooManyInflight < BadRequest; ERR_CODE = 10211; end

      # Passed to the error handler of a FastPublisher when the server
      # reports that messages of the batch did not reach it, like
      # ErrFastBatchGapDetected of orbit.go jetstreamext. The messages from
      # expected_last_seq up to current_seq, which is not included, were
      # lost.
      class FastBatchGapDetected < Error
        attr_reader :expected_last_seq, :current_seq

        def initialize(expected_last_seq = nil, current_seq = nil)
          @expected_last_seq = expected_last_seq
          @current_seq = current_seq
          msg = "nats: fast batch gap detected"
          msg += ": expected last sequence #{expected_last_seq}; current sequence #{current_seq}" if current_seq
          super(msg)
        end
      end

      # The batch publish errors by error code.
      BATCH_PUBLISH_ERRORS = [
        BatchPublishNotEnabled, BatchPublishMissingSeq, BatchPublishIncomplete,
        BatchPublishUnsupportedHeader, BatchPublishInvalidID, MirrorWithAtomicPublish,
        BatchPublishExceedsLimit, BatchPublishInvalidCommit, BatchPublishDuplicateMsgID,
        FastBatchNotEnabled, FastBatchInvalidPattern, FastBatchInvalidID,
        FastBatchUnknownID, MirrorWithBatchPublish, AtomicPublishTooManyInflight,
        BatchPublishTooManyInflight
      ].to_h { |klass| [klass::ERR_CODE, klass] }.freeze

      # When a fetch from a consumer with the pinned_client priority policy
      # finds the subscription no longer pinned, as its pin expired or it
      # was unpinned. The subscription forgets its pin, so that its next
      # fetch can be pinned again.
      # This condition is represented with a message that has 423 status code header.
      class PinIdMismatch < APIError
        def initialize(params = {})
          super
          @code ||= 423
        end
      end

      # When the server ended the pull of a fetch with max_bytes before the
      # fetch got a message, as the next message would exceed max_bytes.
      # This condition is represented with a message that has 409 status code header.
      class MaxBytesExceeded < APIError
        def initialize(params = {})
          super
          @code ||= 409
        end
      end
    end
  end
end
