# frozen_string_literal: true

module NATS
  class Service
    module Validator
      # The name and the version must match as a whole, like nameRegexp and
      # semVerRegexp of nats.go micro. A group name is checked as it always
      # was, as nats.go micro does not check it.
      REGEX = {
        name: /\A[A-Za-z0-9\-_]+\z/,
        group: /[A-Za-z0-9\-_]+$/,
        version: /\A(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?\z/,
        subject: /^[^ >]*>?$/,
        queue: /^[^ >]*>?$/
      }.freeze

      class << self
        def validate(values)
          unless valid?(values, :name)
            raise InvalidNameError, "invalid name #{values[:name].inspect}: it should not be empty " \
              "and should consist of alphanumerical characters, dashes and underscores"
          end
          raise InvalidNameError, "invalid group name #{values[:group].inspect}" unless valid?(values, :group)
          unless valid?(values, :version)
            raise InvalidVersionError, "invalid version #{values[:version].inspect}: it should not be empty " \
              "and should match the SemVer format"
          end
          raise InvalidSubjectError unless valid?(values, :subject) || nil?(values, :subject)
          raise InvalidQueueError unless valid?(values, :queue) || nil?(values, :queue)
        end

        def valid?(values, key)
          !values.has_key?(key) || values[key] =~ REGEX[key]
        end

        def nil?(values, key)
          values.has_key?(key) && values[key].nil?
        end
      end
    end
  end
end
