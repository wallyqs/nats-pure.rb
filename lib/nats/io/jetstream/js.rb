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

require_relative "js/config"
require_relative "js/header"
require_relative "js/status"
require_relative "js/sub"

module NATS
  class JetStream
    # Misc internal functions to support JS API.
    # @private
    module JS
      DefaultAPIPrefix = "$JS.API" # rubocop:disable Naming/ConstantName

      # The errors for the status codes of the JetStream API.
      STATUS_ERRORS = {
        400 => ::NATS::JetStream::Error::BadRequest,
        404 => ::NATS::JetStream::Error::NotFound,
        500 => ::NATS::JetStream::Error::ServerError,
        503 => ::NATS::JetStream::Error::ServiceUnavailable
      }.freeze

      # The errors for the err_codes of the JetStream API that nats.go
      # names, from errors.json of nats-server.
      ERR_CODE_ERRORS = {
        10012 => ::NATS::JetStream::Error::ConsumerCreate,
        10013 => ::NATS::JetStream::Error::ConsumerNameAlreadyInUse,
        10014 => ::NATS::JetStream::Error::ConsumerNotFound,
        10026 => ::NATS::JetStream::Error::MaximumConsumersLimit,
        10037 => ::NATS::JetStream::Error::MsgNotFound,
        10039 => ::NATS::JetStream::Error::JetStreamNotEnabledForAccount,
        10058 => ::NATS::JetStream::Error::StreamNameAlreadyInUse,
        10059 => ::NATS::JetStream::Error::StreamNotFound,
        10071 => ::NATS::JetStream::Error::WrongLastSequence,
        10076 => ::NATS::JetStream::Error::JetStreamNotEnabled,
        10136 => ::NATS::JetStream::Error::DuplicateFilterSubjects,
        10138 => ::NATS::JetStream::Error::OverlappingFilterSubjects,
        10139 => ::NATS::JetStream::Error::EmptyFilter,
        10148 => ::NATS::JetStream::Error::ConsumerAlreadyExists,
        10149 => ::NATS::JetStream::Error::ConsumerDoesNotExist,
        10164 => ::NATS::JetStream::Error::WrongLastSequence,
        10186 => ::NATS::JetStream::Error::MirrorWithMsgSchedules,
        10187 => ::NATS::JetStream::Error::SourceWithMsgSchedules,
        10188 => ::NATS::JetStream::Error::MessageSchedulesDisabled,
        10189 => ::NATS::JetStream::Error::SchedulePatternInvalid,
        10190 => ::NATS::JetStream::Error::ScheduleTargetInvalid,
        10191 => ::NATS::JetStream::Error::ScheduleTTLInvalid,
        10192 => ::NATS::JetStream::Error::ScheduleRollupInvalid,
        10203 => ::NATS::JetStream::Error::ScheduleSourceInvalid,
        10204 => ::NATS::JetStream::Error::ConsumerInvalidReset
      }.freeze

      # The errors for the descriptions of the 409 statuses that end pulls.
      CONFLICT_ERRORS = {
        "consumer deleted" => ::NATS::JetStream::Error::ConsumerDeleted,
        "leadership change" => ::NATS::JetStream::Error::ConsumerLeadershipChanged,
        "server shutdown" => ::NATS::JetStream::Error::ServerShutdown
      }.freeze

      class << self
        def next_req_to_json(next_req)
          req = {}
          req[:batch] = next_req[:batch]
          req[:expires] = next_req[:expires].to_i if next_req[:expires]
          req[:no_wait] = next_req[:no_wait] if next_req[:no_wait]
          req[:max_bytes] = next_req[:max_bytes] if next_req[:max_bytes]
          req[:idle_heartbeat] = next_req[:idle_heartbeat].to_i if next_req[:idle_heartbeat]
          # Priority groups (requires nats-server v2.11.0).
          req.merge!(next_req.slice(:group, :min_pending, :min_ack_pending, :priority, :id).compact)
          req.to_json
        end

        # parse_time parses a time from the server, which sends Go's zero
        # time for a time that is not set.
        def parse_time(time)
          return if time.nil?

          time = ::Time.parse(time)
          time unless time.year == 1
        end

        # is_status_msg tells whether the server sent a message as a status:
        # one with a Status header and no reply. A message of a stream can
        # have a Status header too, but a consumer delivers it with a reply
        # to ack it.
        def is_status_msg(msg)
          return false if msg.nil? || msg.header.nil?

          !msg.header[Header::Status].nil? && msg.reply.to_s.empty?
        end

        # check_503_error raises exception when a NATS::Msg has a 503 status header.
        # @param msg [NATS::Msg] The message with status headers.
        # @raise [NATS::JetStream::Error::ServiceUnavailable]
        def check_503_error(msg)
          return if msg.nil? || msg.header.nil?
          if msg.header[Header::Status] == Status::ServiceUnavailable
            raise ::NATS::JetStream::Error::ServiceUnavailable
          end
        end

        # from_msg takes a plain NATS::Msg and checks its headers to confirm
        # if it was an error:
        #
        # msg.header={"Status"=>"503"})
        # msg.header={"Status"=>"408", "Description"=>"Request Timeout"})
        #
        # @param msg [NATS::Msg] The message with status headers.
        # @return [NATS::JetStream::API::Error]
        def from_msg(msg)
          check_503_error(msg)
          code = msg.header[JS::Header::Status]
          desc = msg.header[JS::Header::Desc]
          return ::NATS::JetStream::Error::PinIdMismatch.new({description: desc}) if code == Status::PinIdMismatch
          return ::NATS::JetStream::Error::MaxBytesExceeded.new({description: desc}) if max_bytes_exceeded?(msg)

          klass = if code == Status::Conflict
            # Matched as nats.go matches them, by what the description has.
            CONFLICT_ERRORS.find { |text, _| desc.to_s.downcase.include?(text) }&.last
          end
          (klass || ::NATS::JetStream::API::Error).new({code: code, description: desc})
        end

        # max_bytes_exceeded? tells whether a status says that the server
        # ended a pull as its next message would exceed its max_bytes.
        def max_bytes_exceeded?(msg)
          msg.header[Header::Status] == Status::Conflict &&
            msg.header[Header::Desc].to_s.downcase.include?("message size exceeds maxbytes")
        end

        # msg_size is the size of a message as the server counts it against
        # the max_bytes of a pull: its subject, reply, header and data. The
        # header is counted as the client writes it, "Key: Value" lines.
        def msg_size(msg)
          size = msg.subject.to_s.bytesize + msg.reply.to_s.bytesize + msg.data.to_s.bytesize
          return size if msg.header.nil? || msg.header.empty?

          size + msg.header.sum("NATS/1.0\r\n\r\n".bytesize) { |k, v| "#{k}: #{v}\r\n".bytesize }
        end

        # from_error takes an API response that errored and maps the error
        # into a JetStream error type based on the status and error code.
        #
        # An err_code the client knows gives an error of its own, which is a
        # subclass of the error for the status code, so that rescuing that
        # one rescues it too. An err_code sent with another status code than
        # the server sends it with gives the error for the status code, and
        # an unknown status code an API::Error.
        def from_error(err)
          return unless err

          base = STATUS_ERRORS[err[:code]]
          return ::NATS::JetStream::API::Error.new(err) unless base

          klass = ERR_CODE_ERRORS[err[:err_code]]
          klass = base unless klass && klass < base
          klass.new(err)
        end
      end
    end
    private_constant :JS
  end
end
