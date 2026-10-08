# frozen_string_literal: true

# Copyright 2016-2021 The NATS Authors
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

require_relative "parser"
require_relative "version"
require_relative "errors"
require_relative "msg"
require_relative "subscription"
require_relative "jetstream"

require "nats/nuid"
require "socket"
require "json"
require "monitor"
require "uri"
require "securerandom"
require "concurrent"

begin
  require "openssl"
rescue LoadError
end

module NATS
  class << self
    # NATS.connect creates a connection to the NATS Server.
    # @param uri [String] URL endpoint of the NATS Server or cluster.
    # @param opts [Hash] Options to customize the NATS connection.
    # @return [NATS::Client]
    #
    # @example
    #   require 'nats'
    #   nc = NATS.connect("demo.nats.io")
    #   nc.publish("hello", "world")
    #   nc.close
    #
    def connect(uri = nil, opts = {})
      nc = NATS::Client.new
      nc.connect(uri, opts)

      nc
    end
  end

  # Status represents the different states from a NATS connection.
  # A client starts from the DISCONNECTED state to CONNECTING during
  # the initial connect, then CONNECTED.  If the connection is reset
  # then it goes from DISCONNECTED to RECONNECTING until it is back to
  # the CONNECTED state.  In case the client gives up reconnecting or
  # the connection is manually closed then it will reach the CLOSED
  # connection state after which it will not reconnect again.
  module Status
    # When the client is not actively connected.
    DISCONNECTED = 0

    # When the client is connected.
    CONNECTED = 1

    # When the client will no longer attempt to connect to a NATS Server.
    CLOSED = 2

    # When the client has disconnected and is attempting to reconnect.
    RECONNECTING = 3

    # When the client is attempting to connect to a NATS Server for the first time.
    CONNECTING = 4

    # When the client is draining a connection before closing.
    DRAINING_SUBS = 5
    DRAINING_PUBS = 6
  end

  # Fork Detection handling
  # Based from similar approach as mperham/connection_pool: https://github.com/mperham/connection_pool/pull/166
  if Process.respond_to?(:fork) && Process.respond_to?(:_fork) # MRI 3.1+
    module ForkTracker
      def _fork
        super.tap do |pid|
          Client.after_fork if pid.zero? # in the child process
        end
      end
    end
    Process.singleton_class.prepend(ForkTracker)
  end

  # Client creates a connection to the NATS Server.
  class Client
    include MonitorMixin
    include Status

    attr_reader :status, :server_info, :server_pool, :options, :stats, :uri, :subscription_executor, :reloader

    DEFAULT_PORT = {nats: 4222, ws: 80, wss: 443}.freeze
    DEFAULT_URI = "nats://localhost:#{DEFAULT_PORT[:nats]}".freeze

    CR_LF = "\r\n"
    CR_LF_SIZE = CR_LF.bytesize

    PING_REQUEST = "PING#{CR_LF}".freeze
    PONG_RESPONSE = "PONG#{CR_LF}".freeze

    NATS_HDR_LINE = "NATS/1.0#{CR_LF}".freeze
    STATUS_MSG_LEN = 3
    STATUS_HDR = "Status"
    DESC_HDR = "Description"
    NATS_HDR_LINE_SIZE = NATS_HDR_LINE.bytesize

    SUB_OP = "SUB"
    EMPTY_MSG = ""

    # Replaces the password of the URL in connected_url_redacted.
    REDACTED = "xxxxx"
    private_constant :REDACTED

    # Errors for the -ERR texts of the server, by their lowercase prefix.
    SERVER_ERRORS = {
      "permissions violation" => NATS::IO::PermissionViolation,
      "maximum subscriptions exceeded" => NATS::IO::MaxSubscriptionsExceeded,
      "maximum connections exceeded" => NATS::IO::MaxConnectionsExceeded,
      "maximum account active connections exceeded" => NATS::IO::MaxAccountConnectionsExceeded,
      "authorization violation" => NATS::IO::AuthorizationViolation,
      "user authentication expired" => NATS::IO::AuthenticationExpired,
      "user authentication revoked" => NATS::IO::AuthenticationRevoked,
      "account authentication expired" => NATS::IO::AccountAuthenticationExpired
    }.freeze
    private_constant :SERVER_ERRORS

    INSTANCES = ObjectSpace::WeakMap.new # tracks all alive client instances
    private_constant :INSTANCES

    class << self
      # Reloader should free resources managed by external framework
      # that were implicitly acquired in subscription callbacks.
      attr_writer :default_reloader

      def default_reloader
        @default_reloader ||= proc { |&block| block.call }.tap { |r| Ractor.make_shareable(r) if defined? Ractor }
      end

      # Re-establish connection in a new process after forking to start new threads.
      def after_fork
        INSTANCES.each do |client|
          next if client.closed?

          if client.options[:reconnect]
            was_connected = !client.disconnected?
            client.send(:close_connection, Status::DISCONNECTED, true)
            client.connect if was_connected
          else
            client.send(:err_cb_call, self, NATS::IO::ForkDetectedError, nil)
            client.close
          end
        rescue => e
          warn "nats: Error during handling after_fork callback: #{e}" # TODO: Report as async error via error callback?
        end
      end
    end

    def initialize(uri = nil, opts = {})
      super() # required to initialize monitor
      @initial_uri = uri
      @initial_options = opts

      # Read/Write IO
      @io = nil

      # Queues for coalescing writes of commands we need to send to server.
      @flush_queue = nil
      @pending_queue = nil

      # Parser with state
      @parser = NATS::Protocol::Parser.new(self)

      # Threads for both reading and flushing command
      @flusher_thread = nil
      @read_loop_thread = nil
      @ping_interval_thread = nil

      # Info that we get from the server
      @server_info = {}

      # URI from server to which we are currently connected
      @uri = nil
      @server_pool = []

      @status = nil

      # Subscriptions
      @subs = {}
      @ssid = 0

      # Ping interval
      @pings_outstanding = 0
      @pongs_received = 0
      @pongs = []
      @pongs.extend(MonitorMixin)

      # Accounting
      @pending_size = 0
      @stats = {
        in_msgs: 0,
        out_msgs: 0,
        in_bytes: 0,
        out_bytes: 0,
        reconnects: 0
      }

      # Sticky error
      @last_err = nil

      # Async callbacks, no ops by default.
      @err_cb = proc {}
      @close_cb = proc {}
      @disconnect_cb = proc {}
      @reconnect_cb = proc {}
      @connect_cb = nil
      @discovered_servers_cb = nil
      @lame_duck_mode_cb = nil

      # Secure TLS options
      @tls = nil

      # Hostname of current server; used for when TLS host
      # verification is enabled.
      @hostname = nil
      @single_url_connect_used = false

      # Track whether connect has been already been called.
      @connect_called = false

      # Bumped by every close, so that a reconnect started earlier can tell
      # that the connection was closed meanwhile.
      @close_generation = 0

      # New style request/response implementation.
      @resp_sub = nil
      @resp_map = nil
      @resp_sub_prefix = nil
      @nuid = NATS::NUID.new

      # NKEYS
      @user_credentials = nil
      @nkeys_seed = nil
      @user_nkey_cb = nil
      @user_jwt_cb = nil
      @signature_cb = nil
      @user_credentials_data = nil
      @user_jwt = nil
      @user_seed = nil

      # Tokens
      @auth_token = nil
      @token_handler = nil

      # Callback that returns the user and password.
      @user_info_handler = nil

      @inbox_prefix = "_INBOX"

      # Draining
      @drain_t = nil

      # Service API
      @_services = nil

      # Internal listeners of connection events, see add_status_listener.
      @status_listeners = []

      # Prepare for calling connect or automatic delayed connection
      parse_and_validate_options if uri || opts.any?

      # Keep track of all client instances to handle them after process forking in Ruby 3.1+
      INSTANCES[self] = self if !defined?(Ractor) || Ractor.current == Ractor.main # Ractors doesn't work in forked processes

      @reloader = opts.fetch(:reloader, self.class.default_reloader)
    end

    # Prepare connecting to NATS, but postpone real connection until first usage.
    def connect(uri = nil, opts = {})
      if uri || opts.any?
        @initial_uri = uri
        @initial_options = opts
      end

      synchronize do
        # In case it has been connected already, then do not need to call this again.
        return if @connect_called
        @connect_called = true
      end

      parse_and_validate_options
      establish_connection!

      self
    end

    def force_reconnect
      synchronize do
        return true if reconnecting?

        if closed? || draining? || disconnected?
          raise NATS::IO::ConnectionClosedError
        end

        initiate_reconnect
        true
      end
    end

    private def parse_and_validate_options
      # Reset these in case we have reconnected via fork.
      @server_pool = []
      @resp_sub = nil
      @resp_map = nil
      @resp_sub_prefix = nil
      @nuid = NATS::NUID.new
      @stats = {
        in_msgs: 0,
        out_msgs: 0,
        in_bytes: 0,
        out_bytes: 0,
        reconnects: 0
      }
      @status = DISCONNECTED

      # Convert URI to string if needed.
      uri = @initial_uri.dup
      uri = uri.to_s if uri.is_a?(URI)

      opts = @initial_options.dup

      case uri
      when String
        srvs = opts[:servers] = process_uri(uri)
        @single_url_connect_used = true if srvs.size == 1
      when Hash
        opts = uri
      end

      # Initialize TLS defaults in case any url is using it, or the TLS
      # handshake comes first.
      if !opts[:tls] && (opts[:tls_handshake_first] || Array(opts[:servers]).any? { |u| u.to_s.start_with?("tls://", "wss://") })
        opts[:tls] = {}
      end

      opts[:verbose] = false if opts[:verbose].nil?
      opts[:pedantic] = false if opts[:pedantic].nil?
      opts[:reconnect] = true if opts[:reconnect].nil?
      opts[:old_style_request] = false if opts[:old_style_request].nil?
      opts[:ignore_discovered_urls] = false if opts[:ignore_discovered_urls].nil?
      opts[:reconnect_time_wait] = NATS::IO::RECONNECT_TIME_WAIT if opts[:reconnect_time_wait].nil?
      opts[:reconnect_jitter] = NATS::IO::RECONNECT_JITTER if opts[:reconnect_jitter].nil?
      opts[:reconnect_jitter_tls] = NATS::IO::RECONNECT_JITTER_TLS if opts[:reconnect_jitter_tls].nil?
      opts[:reconnect_buf_size] = NATS::IO::DEFAULT_RECONNECT_BUF_SIZE if opts[:reconnect_buf_size].nil?
      opts[:max_reconnect_attempts] = NATS::IO::MAX_RECONNECT_ATTEMPTS if opts[:max_reconnect_attempts].nil?
      opts[:ping_interval] = NATS::IO::DEFAULT_PING_INTERVAL if opts[:ping_interval].nil?
      opts[:max_outstanding_pings] = NATS::IO::DEFAULT_PING_MAX if opts[:max_outstanding_pings].nil?

      # Override with ENV
      opts[:verbose] = ENV["NATS_VERBOSE"].downcase == "true" unless ENV["NATS_VERBOSE"].nil?
      opts[:pedantic] = ENV["NATS_PEDANTIC"].downcase == "true" unless ENV["NATS_PEDANTIC"].nil?
      opts[:reconnect] = ENV["NATS_RECONNECT"].downcase == "true" unless ENV["NATS_RECONNECT"].nil?
      opts[:reconnect_time_wait] = ENV["NATS_RECONNECT_TIME_WAIT"].to_i unless ENV["NATS_RECONNECT_TIME_WAIT"].nil?
      opts[:ignore_discovered_urls] = ENV["NATS_IGNORE_DISCOVERED_URLS"].downcase == "true" unless ENV["NATS_IGNORE_DISCOVERED_URLS"].nil?
      opts[:max_reconnect_attempts] = ENV["NATS_MAX_RECONNECT_ATTEMPTS"].to_i unless ENV["NATS_MAX_RECONNECT_ATTEMPTS"].nil?
      opts[:ping_interval] = ENV["NATS_PING_INTERVAL"].to_i unless ENV["NATS_PING_INTERVAL"].nil?
      opts[:max_outstanding_pings] = ENV["NATS_MAX_OUTSTANDING_PINGS"].to_i unless ENV["NATS_MAX_OUTSTANDING_PINGS"].nil?
      opts[:connect_timeout] ||= NATS::IO::DEFAULT_CONNECT_TIMEOUT
      opts[:drain_timeout] ||= NATS::IO::DEFAULT_DRAIN_TIMEOUT
      opts[:close_timeout] ||= NATS::IO::DEFAULT_CLOSE_TIMEOUT
      @options = opts

      # Process servers in the NATS cluster and pick one to connect
      uris = opts[:servers] || [DEFAULT_URI]
      uris.shuffle! unless @options[:dont_randomize_servers]
      uris.each do |u|
        nats_uri = case u
        when URI
          u.dup
        else
          URI.parse(u)
        end
        @server_pool << {
          uri: nats_uri,
          hostname: nats_uri.hostname
        }
      end

      if @options[:old_style_request]
        # Replace for this instance the implementation
        # of request to use the old_request style.
        class << self; alias_method :request, :old_request; end
      end

      validate_auth_options!

      # NKEYS
      @signature_cb ||= opts[:user_signature_cb]
      @user_jwt_cb ||= opts[:user_jwt_cb]
      @user_nkey_cb ||= opts[:user_nkey_cb]
      @user_credentials ||= opts[:user_credentials]
      @user_credentials_data ||= opts[:user_credentials_data]
      @user_jwt ||= opts[:user_jwt]
      @user_seed ||= opts[:user_seed]
      @nkeys_seed ||= opts[:nkeys_seed]

      setup_nkeys_connect if @user_credentials || @user_credentials_data || @user_jwt || @nkeys_seed

      # Tokens, if set will take preference over the user@server uri token
      @auth_token ||= opts[:auth_token]
      @token_handler = opts[:token_handler]
      @user_info_handler = opts[:user_info_handler]

      # Check for TLS usage
      @tls = @options[:tls]
      @tls_context = nil

      @inbox_prefix = opts.fetch(:custom_inbox_prefix, @inbox_prefix)

      validate_settings!

      self
    end

    private def establish_connection!
      @ruby_pid = Process.pid # For fork detection

      srv = nil
      begin
        srv = select_next_server

        # Use the hostname from the server for TLS hostname verification.
        if client_using_secure_connection? && single_url_connect_used?
          # Always reuse the original hostname used to connect.
          @hostname ||= srv[:hostname]
        else
          @hostname = srv[:hostname]
        end

        # Create TCP socket connection to NATS.
        @io = create_socket
        @io.connect

        # Capture state that we have had a TCP connection established against
        # this server and could potentially be used for reconnecting.
        srv[:was_connected] = true

        # Connection established and now in process of sending CONNECT to NATS
        @status = CONNECTING

        # Established TCP connection successfully so can start connect
        process_connect_init

        # Reset reconnection attempts if connection is valid
        srv[:reconnect_attempts] = 0
        srv[:auth_required] ||= true if @server_info[:auth_required]

        # Add back to rotation since successfully connected
        server_pool << srv
      rescue NATS::IO::NoServersError => e
        @disconnect_cb.call(e) if @disconnect_cb
        raise @last_err || e
      rescue => e
        # Capture sticky error
        synchronize do
          @last_err = e
          srv[:auth_required] ||= true if @server_info[:auth_required]
          # The server will not support no_echo on a retry either.
          srv[:error_received] = true if e.is_a?(NATS::IO::NoEchoNotSupported)
          server_pool << srv if can_reuse_server?(srv)
        end

        err_cb_call(self, e, nil) if @err_cb

        if should_not_reconnect?
          @disconnect_cb.call(e) if @disconnect_cb
          raise e
        end

        # Clean up any connecting state and close connection without
        # triggering the disconnection/closed callbacks.
        close_connection(DISCONNECTED, false)

        # Always sleep here to safe guard against errors before current[:was_connected]
        # is set for the first time.
        sleep reconnect_delay(srv)

        # Continue retrying until there are no options left in the server pool
        retry
      end

      # Initialize queues and loops for message dispatching and processing engine
      @flush_queue = SizedQueue.new(NATS::IO::MAX_FLUSH_KICK_SIZE)
      @pending_queue = SizedQueue.new(NATS::IO::MAX_PENDING_SIZE)
      @pings_outstanding = 0
      @pongs_received = 0
      @pending_size = 0

      # Server roundtrip went ok so consider to be connected at this point
      @status = CONNECTED

      # Connected to NATS so Ready to start parser loop, flusher and ping interval
      start_threads!

      # Called before connect returns, like ConnectedCB of nats.go.
      async_cb_call(@connect_cb)

      self
    end

    def publish(subject, msg = EMPTY_MSG, opt_reply = nil, **options, &blk)
      raise NATS::IO::BadSubject if !subject || subject.empty?
      if options[:header]
        return publish_msg(NATS::Msg.new(subject: subject, data: msg, reply: opt_reply, header: options[:header]))
      end

      check_reconnect_buf!

      # Accounting
      msg_size = msg.bytesize
      check_max_payload!(msg_size)
      @stats[:out_msgs] += 1
      @stats[:out_bytes] += msg_size

      send_command("PUB #{subject} #{opt_reply} #{msg_size}\r\n#{msg}\r\n")
      @flush_queue << :pub if @flush_queue.empty?
    end

    # Publishes a NATS::Msg that may include headers.
    def publish_msg(msg)
      raise TypeError, "nats: expected NATS::Msg, got #{msg.class.name}" unless msg.is_a?(Msg)
      raise NATS::IO::BadSubject if !msg.subject || msg.subject.empty?
      if msg.header && !@server_info.empty? && !@server_info[:headers]
        raise NATS::IO::HeadersNotSupported.new("nats: headers not supported by this server")
      end

      check_reconnect_buf!

      msg.reply ||= "".dup
      msg.data ||= "".dup
      msg_size = msg.data.bytesize

      # Accounting
      @stats[:out_msgs] += 1
      @stats[:out_bytes] += msg_size

      if msg.header
        hdr = "".dup
        hdr << NATS_HDR_LINE
        # A name with an Array of values goes out once for each of them.
        Msg.header_lines(msg.header).each { |line| hdr << line }
        hdr << CR_LF
        hdr_len = hdr.bytesize
        total_size = msg_size + hdr_len
        check_max_payload!(total_size)
        send_command("HPUB #{msg.subject} #{msg.reply} #{hdr_len} #{total_size}\r\n#{hdr}#{msg.data}\r\n")
      else
        check_max_payload!(msg_size)
        send_command("PUB #{msg.subject} #{msg.reply} #{msg_size}\r\n#{msg.data}\r\n")
      end

      @flush_queue << :pub if @flush_queue.empty?
    end

    # Create subscription which is dispatched asynchronously
    # messages to a callback.
    def subscribe(subject, opts = {}, &callback)
      raise NATS::IO::ConnectionDrainingError.new("nats: connection draining") if draining?
      # Whitespace would change the meaning of the SUB protocol line, so it is
      # refused like in nats.go; other invalid subjects are left to the server.
      subj = subject.to_s
      raise NATS::IO::BadSubject.new("nats: invalid subject") if subj.empty? || subj.match?(/[ \t\r\n]/)
      raise NATS::IO::BadQueueName.new("nats: invalid queue name") if opts[:queue].to_s.match?(/[ \t\r\n]/)

      sid = nil
      sub = nil
      synchronize do
        sid = (@ssid += 1)
        sub = @subs[sid] = Subscription.new
        sub.nc = self
        sub.sid = sid
      end
      opts[:pending_msgs_limit] ||= NATS::IO::DEFAULT_SUB_PENDING_MSGS_LIMIT
      opts[:pending_bytes_limit] ||= NATS::IO::DEFAULT_SUB_PENDING_BYTES_LIMIT

      sub.subject = subject
      sub.callback = callback
      sub.received = 0
      sub.queue = opts[:queue] if opts[:queue]
      sub.max = opts[:max] if opts[:max]
      sub.pending_msgs_limit = opts[:pending_msgs_limit]
      sub.pending_bytes_limit = opts[:pending_bytes_limit]
      sub.pending_queue = SizedQueue.new(sub.pending_msgs_limit)
      sub.processing_concurrency = opts[:processing_concurrency] if opts.key?(:processing_concurrency)

      send_command("SUB #{subject} #{opts[:queue]} #{sid}#{CR_LF}")
      @flush_queue << :sub

      # Setup server support for auto-unsubscribe when receiving enough messages
      sub.unsubscribe(opts[:max]) if opts[:max]

      unless callback
        cond = sub.new_cond
        sub.wait_for_msgs_cond = cond
      end

      sub
    end

    # Sends a request using expecting a single response using a
    # single subscription per connection for receiving the responses.
    # It times out in case the request is not retrieved within the
    # specified deadline.
    # If given a callback, then the request happens asynchronously.
    def request(subject, payload = "", **opts, &blk)
      raise NATS::IO::BadSubject if !subject || subject.empty?

      # If a block was given then fallback to method using auto unsubscribe.
      return old_request(subject, payload, opts, &blk) if blk
      return old_request(subject, payload, opts) if opts[:old_style]

      if opts[:header]
        return request_msg(NATS::Msg.new(subject: subject, data: payload, header: opts[:header]), **opts)
      end

      token = nil
      inbox = nil
      future = nil
      response = nil
      timeout = opts[:timeout] ||= 0.5
      synchronize do
        start_resp_mux_sub! unless @resp_sub_prefix

        # Create token for this request.
        token = @nuid.next
        inbox = "#{@resp_sub_prefix}.#{token}"

        # Create the a future for the request that will
        # get signaled when it receives the request.
        future = @resp_sub.new_cond
        @resp_map[token][:future] = future
      end

      # Publish request and wait for reply.
      publish(subject, payload, inbox)
      begin
        MonotonicTime.with_nats_timeout(timeout) do
          @resp_sub.synchronize do
            future.wait(timeout)
          end
        end
      rescue NATS::Timeout => e
        synchronize { @resp_map.delete(token) }
        raise e
      end

      # Check if there is a response already.
      synchronize do
        result = @resp_map[token]
        response = result[:response]
        @resp_map.delete(token)
      end

      if response&.header
        status = response.header[STATUS_HDR]
        raise NATS::IO::NoRespondersError if status == "503"
      end

      response
    end

    # request_msg makes a NATS request using a NATS::Msg that may include headers.
    def request_msg(msg, **opts)
      raise TypeError, "nats: expected NATS::Msg, got #{msg.class.name}" unless msg.is_a?(Msg)
      raise NATS::IO::BadSubject if !msg.subject || msg.subject.empty?

      token = nil
      inbox = nil
      future = nil
      response = nil
      timeout = opts[:timeout] ||= 0.5
      synchronize do
        start_resp_mux_sub! unless @resp_sub_prefix

        # Create token for this request.
        token = @nuid.next
        inbox = "#{@resp_sub_prefix}.#{token}"

        # Create the a future for the request that will
        # get signaled when it receives the request.
        future = @resp_sub.new_cond
        @resp_map[token][:future] = future
      end
      msg.reply = inbox
      msg.data ||= ""
      msg.data.bytesize

      # Publish request and wait for reply.
      publish_msg(msg)
      begin
        MonotonicTime.with_nats_timeout(timeout) do
          @resp_sub.synchronize do
            future.wait(timeout)
          end
        end
      rescue NATS::Timeout => e
        synchronize { @resp_map.delete(token) }
        raise e
      end

      # Check if there is a response already.
      synchronize do
        result = @resp_map[token]
        response = result[:response]
        @resp_map.delete(token)
      end

      if response&.header
        status = response.header[STATUS_HDR]
        raise NATS::IO::NoRespondersError if status == "503"
      end

      response
    end

    # Sends a request creating an ephemeral subscription for the request,
    # expecting a single response or raising a timeout in case the request
    # is not retrieved within the specified deadline.
    # If given a callback, then the request happens asynchronously.
    def old_request(subject, payload, opts = {}, &blk)
      return unless subject
      inbox = new_inbox

      # If a callback was passed, then have it process
      # the messages asynchronously and return the sid.
      if blk
        opts[:max] ||= 1
        s = subscribe(inbox, opts) do |msg|
          case blk.arity
          when 0 then blk.call
          when 1 then blk.call(msg)
          when 2 then blk.call(msg.data, msg.reply)
          when 3 then blk.call(msg.data, msg.reply, msg.subject)
          else blk.call(msg.data, msg.reply, msg.subject, msg.header)
          end
        end
        publish(subject, payload, inbox)

        return s
      end

      # In case block was not given, handle synchronously
      # with a timeout and only allow a single response.
      timeout = opts[:timeout] ||= 0.5
      opts[:max] = 1

      sub = Subscription.new
      sub.subject = inbox
      sub.received = 0
      future = sub.new_cond
      sub.future = future
      sub.nc = self

      sid = nil
      synchronize do
        sid = (@ssid += 1)
        sub.sid = sid
        @subs[sid] = sub
      end

      send_command("SUB #{inbox} #{sid}#{CR_LF}")
      @flush_queue << :sub
      unsubscribe(sub, 1)

      sub.synchronize do
        # Publish the request and then wait for the response...
        publish(subject, payload, inbox)

        MonotonicTime.with_nats_timeout(timeout) do
          future.wait(timeout)
        end
      end
      response = sub.response

      if response&.header
        status = response.header[STATUS_HDR]
        raise NATS::IO::NoRespondersError if status == "503"
      end

      response
    end

    # Send a ping and wait for a pong back within a timeout.
    def flush(timeout = 10)
      raise NATS::IO::BadTimeout.new("nats: timeout invalid") unless timeout.is_a?(Numeric) && timeout > 0

      # Schedule sending a PING, and block until we receive PONG back,
      # or raise a timeout in case the response is past the deadline.
      pong = @pongs.new_cond
      @pongs.synchronize do
        @pongs << pong

        # Flush once pong future has been prepared
        @pending_queue << PING_REQUEST
        @flush_queue << :ping
        MonotonicTime.with_nats_timeout(timeout) do
          pong.wait(timeout)
        end
      end
    end

    # Measures the round trip time to the server: how long the server takes
    # to answer a PING with a PONG, like RTT of nats.go.
    # @return [Float] The round trip time, in seconds.
    # @raise [NATS::IO::ConnectionClosedError] When the connection is closed.
    # @raise [NATS::IO::Disconnected] When the connection is not connected,
    #   as while it reconnects.
    # @raise [NATS::Timeout] When the PONG does not come within 10 seconds.
    def rtt
      raise NATS::IO::ConnectionClosedError.new("nats: connection closed") if closed?
      raise NATS::IO::Disconnected.new("nats: server is disconnected") unless connected?

      start = MonotonicTime.now
      flush(10)
      # A close while waiting for the PONG ends the flush too.
      raise NATS::IO::ConnectionClosedError.new("nats: connection closed") if synchronize { closed? }

      MonotonicTime.since(start)
    end

    alias_method :servers, :server_pool

    # discovered_servers returns the NATS Servers that have been discovered
    # via INFO protocol updates.
    def discovered_servers
      servers.select { |s| s[:discovered] }
    end

    # Replaces the server pool with the given URLs, like SetServerPool of
    # nats.go. It does not reconnect: the connection stays with the current
    # server, and the next reconnect uses the new pool. A server that is in
    # both keeps its state, like its reconnect attempts; the current server
    # goes last, as it does after every connect. Servers that the cluster
    # announces still join the pool unless ignore_discovered_urls is set.
    #
    # @param urls [Array<String, URI>] URLs as for connect, like "nats://127.0.0.1:4222" or "127.0.0.1:4222".
    # @raise [ArgumentError] For an invalid URL, or when it mixes websocket
    #   and other URLs, like ErrMixingWebsocketSchemes of nats.go. The pool
    #   is left as it was.
    # @raise [NATS::IO::ConnectionClosedError] When the connection is closed.
    def set_server_pool(urls)
      synchronize do
        raise NATS::IO::ConnectionClosedError.new("nats: connection closed") if closed?

        uris = Array(urls).flat_map { |url| parse_server_urls(url) }
        current = @uri || server_pool.first&.fetch(:uri) || uris.first
        if uris.any? { |uri| %w[ws wss].include?(uri.scheme) != %w[ws wss].include?(current.scheme) }
          raise ArgumentError, "nats: mixing of websocket and non websocket URLs is not allowed"
        end

        pool = uris.map do |uri|
          # Keep the state of the servers that remain.
          old = server_pool.find { |srv| same_server?(srv[:uri], uri) }
          (old || {}).merge(uri: uri, hostname: uri.hostname, discovered: false)
        end

        # The current server goes last, as after a connect.
        idx = pool.index { |srv| @uri && same_server?(srv[:uri], @uri) }
        pool.push(pool.delete_at(idx)) if idx

        # Like connect, have a TLS context for tls:// and wss:// URLs.
        if !@tls && @options && pool.any? { |srv| %w[tls wss].include?(srv[:uri].scheme) }
          @tls = @options[:tls] = {}
        end
        @single_url_connect_used &&= pool.all? { |srv| srv[:hostname] == @hostname }
        @server_pool = pool
      end
      nil
    end

    # Runs the block once the messages that the subscriptions with a
    # callback received so far have been processed, like Barrier of nats.go:
    # the subscription that processes its last such message runs it, from
    # its thread. With no such subscriptions it runs right away. Errors that
    # the block raises go to on_error, as those of callbacks do.
    #
    # @example Wait for the messages published so far to be processed
    #   nc.flush
    #   done = Queue.new
    #   nc.barrier { done << true }
    #   done.pop
    # @raise [NATS::IO::ConnectionClosedError] When the connection is closed.
    def barrier(&block)
      raise ArgumentError, "nats: barrier needs a block" unless block

      subs = synchronize do
        raise NATS::IO::ConnectionClosedError.new("nats: connection closed") if closed?

        @subs.values.select { |sub| sub.callback && sub.pending_queue }
      end
      return block.call if subs.empty?

      barrier = Subscription::Barrier.new(subs.size, self, block)
      subs.each { |sub| sub.send(:add_barrier, barrier) }
      nil
    end

    # Close connection to NATS, flushing in case connection is alive
    # and there are any pending messages, should not be used while
    # holding the lock.
    def close
      close_connection(CLOSED, true)
    end

    # new_inbox returns a unique inbox used for subscriptions.
    # @return [String]
    def new_inbox
      "#{@inbox_prefix}.#{@nuid.next}"
    end

    def connected_server
      connected? ? @uri : nil
    end

    # The URL of the connected server, with its password, or its token,
    # replaced by "xxxxx", like ConnectedUrlRedacted of nats.go.
    # @return [String, nil] nil unless connected.
    def connected_url_redacted
      synchronize do
        return nil unless connected? && @uri

        uri = @uri.dup
        if uri.password
          uri.password = REDACTED
        elsif uri.user
          uri.user = REDACTED
        end
        uri.to_s
      end
    end

    # The address of the connected server, like ConnectedAddr of nats.go.
    # @return [String, nil] The IP address and port, as in "127.0.0.1:4222"
    #   or "[::1]:4222", or nil unless connected.
    def connected_addr
      socket_address(:remote_address)
    end

    # The local address of the connection, like LocalAddr of nats.go.
    # @return [String, nil] The IP address and port, as in
    #   "127.0.0.1:52144", or nil unless connected.
    def local_addr
      socket_address(:local_address)
    end

    # The number of subscriptions of the connection, like NumSubscriptions
    # of nats.go; it includes the one that receives the responses to requests.
    # @return [Integer]
    def num_subscriptions
      synchronize { @subs.size }
    end

    # The bytes of the commands that are waiting to be sent to the server,
    # as while reconnecting, like Buffered of nats.go.
    # @return [Integer]
    # @raise [NATS::IO::ConnectionClosedError] When the connection is closed.
    def buffered
      synchronize do
        raise NATS::IO::ConnectionClosedError.new("nats: connection closed") if closed?

        @pending_size
      end
    end

    # The id of the connected server, like ConnectedServerId of nats.go.
    # @return [String, nil] nil unless connected.
    def connected_server_id
      connected_server_info(:server_id)
    end

    # The name of the connected server, like ConnectedServerName of nats.go.
    # @return [String, nil] nil unless connected.
    def connected_server_name
      connected_server_info(:server_name)
    end

    # The version of the connected server, like ConnectedServerVersion of nats.go.
    # @return [String, nil] nil unless connected.
    def connected_server_version
      connected_server_info(:version)
    end

    # The name of the cluster of the connected server, like
    # ConnectedClusterName of nats.go.
    # @return [String, nil] nil unless connected, or when the server is not
    #   in a cluster.
    def connected_cluster_name
      connected_server_info(:cluster)
    end

    # The id that the server gave the connection, like GetClientID of
    # nats.go. It may change when the connection reconnects.
    # @return [Integer, nil] nil when the server does not tell it.
    # @raise [NATS::IO::ConnectionClosedError] When the connection is closed.
    def client_id
      server_info_unless_closed(:client_id)
    end

    # The IP address of the connection as the server sees it, like
    # GetClientIP of nats.go.
    # @return [String, nil] nil when the server does not tell it.
    # @raise [NATS::IO::ConnectionClosedError] When the connection is closed.
    def client_ip
      server_info_unless_closed(:client_ip)
    end

    # The largest message, in bytes, that the server takes, like MaxPayload of nats.go.
    # @return [Integer, nil] nil until connected.
    def max_payload
      synchronize { @server_info[:max_payload] }
    end

    # Whether the server supports headers, like HeadersSupported of nats.go.
    def headers_supported?
      synchronize { !!@server_info[:headers] }
    end

    # Whether the server requires authentication, like AuthRequired of nats.go.
    def auth_required?
      synchronize { !!@server_info[:auth_required] }
    end

    # Whether the server requires TLS, like TLSRequired of nats.go.
    def tls_required?
      synchronize { !!(@server_info[:tls_required] || @server_info[:ssl_required]) }
    end

    # Whether the server has JetStream enabled.
    def jetstream?
      synchronize { !!@server_info[:jetstream] }
    end

    def disconnected?
      !@status or @status == DISCONNECTED
    end

    # Whether the connection is connected, also while it drains, like
    # IsConnected of nats.go.
    def connected?
      @status == CONNECTED || @status == DRAINING_SUBS || @status == DRAINING_PUBS
    end

    def connecting?
      @status == CONNECTING
    end

    def reconnecting?
      @status == RECONNECTING
    end

    def closed?
      @status == CLOSED
    end

    def draining?
      if (@status == DRAINING_PUBS) || (@status == DRAINING_SUBS)
        return true
      end

      is_draining = false
      synchronize do
        is_draining = true if @drain_t
      end

      is_draining
    end

    # The callbacks set with on_error, on_disconnect, on_reconnect,
    # on_close, on_connect, on_discovered_servers and on_lame_duck_mode,
    # like ErrorHandler, DisconnectErrHandler and the like of nats.go.
    def error_handler = @err_cb

    def disconnect_handler = @disconnect_cb

    def reconnect_handler = @reconnect_cb

    def close_handler = @close_cb

    def connect_handler = @connect_cb

    def discovered_servers_handler = @discovered_servers_cb

    def lame_duck_mode_handler = @lame_duck_mode_cb

    def on_error(&callback)
      @err_cb = callback
    end

    def on_disconnect(&callback)
      @disconnect_cb = callback
    end

    def on_reconnect(&callback)
      @reconnect_cb = callback
    end

    def on_close(&callback)
      @close_cb = callback
    end

    # Sets the callback called when a connection to NATS is established for
    # the first time, before connect returns, like ConnectedCB of nats.go.
    # Reconnects call on_reconnect instead.
    def on_connect(&callback)
      @connect_cb = callback
    end

    # Sets the callback called when the server announces servers of its
    # cluster that the client did not know of, which join the server pool,
    # like DiscoveredServersCB of nats.go. Not called for those announced
    # when first connecting.
    def on_discovered_servers(&callback)
      @discovered_servers_cb = callback
    end

    # Sets the callback called when the server notifies that it entered lame
    # duck mode and will soon close its connections, so that the client can
    # move elsewhere before it does, like LameDuckModeHandler of nats.go.
    def on_lame_duck_mode(&callback)
      @lame_duck_mode_cb = callback
    end

    def last_error
      synchronize do
        @last_err
      end
    end

    # drain will put a connection into a drain state. All subscriptions will
    # immediately be put into a drain state. Upon completion, the publishers
    # will be drained and can not publish any additional messages. Upon draining
    # of the publishers, the connection will be closed. Use the `on_close`
    # callback option to know when the connection has moved from draining to closed.
    def drain
      return if draining?

      # Like nats.go, there is nothing to drain while (re)connecting.
      if connecting? || reconnecting?
        close
        raise NATS::IO::ConnectionReconnecting.new("nats: connection reconnecting")
      end

      synchronize do
        @drain_t ||= Thread.new { do_drain }
      end
    end

    # Create a JetStream context.
    # @param opts [Hash] Options to customize the JetStream context.
    # @option params [String] :prefix JetStream API prefix to use for the requests.
    # @option params [String] :domain JetStream Domain to use for the requests.
    # @option params [Float] :timeout Default timeout to use for JS requests.
    # @return [NATS::JetStream]
    def jetstream(opts = {})
      ::NATS::JetStream.new(self, opts)
    end
    alias_method :JetStream, :jetstream
    alias_method :jsm, :jetstream

    def services
      synchronize { @_services ||= Services.new(self) }
    end

    private

    def connected_server_info(key)
      synchronize { connected? ? @server_info[key] : nil }
    end

    def server_info_unless_closed(key)
      synchronize do
        raise NATS::IO::ConnectionClosedError.new("nats: connection closed") if closed?

        @server_info[key]
      end
    end

    def socket_address(kind)
      synchronize do
        return nil unless connected? && @io

        @io.public_send(kind)
      end
    rescue IOError, SystemCallError
      nil
    end

    # Rejects auth options that cannot be used together, like nats.go.
    def validate_auth_options!
      opts = @options

      %i[token_handler user_info_handler user_jwt_cb user_signature_cb user_nkey_cb].each do |opt|
        if opts[opt] && !opts[opt].respond_to?(:call)
          raise ArgumentError, "nats: #{opt} must respond to call"
        end
      end

      if opts[:token_handler]
        url_token = server_pool.any? { |srv| srv[:uri].user && !srv[:uri].password }
        raise ArgumentError, "nats: token and token handler both set" if opts[:auth_token] || url_token
      end

      if opts[:user_info_handler] && (opts[:user] || opts[:pass])
        raise ArgumentError, "nats: cannot set user info handler and user/pass"
      end

      if opts[:user_jwt].nil? != opts[:user_seed].nil?
        raise ArgumentError, "nats: user_jwt and user_seed must be given together"
      end

      users = %i[user_credentials user_credentials_data user_jwt user_jwt_cb].select { |opt| opts[opt] }
      raise ArgumentError, "nats: only one of #{users.join(", ")} may be set" if users.size > 1

      nkeys = %i[nkeys_seed user_nkey_cb].select { |opt| opts[opt] }
      raise ArgumentError, "nats: only one of #{nkeys.join(", ")} may be set" if nkeys.size > 1
      raise ArgumentError, "nats: user callback and nkey defined" if users.any? && nkeys.any?

      if !opts[:user_signature_cb]
        raise ArgumentError, "nats: user callback defined without a signature handler" if opts[:user_jwt_cb]
        raise ArgumentError, "nats: nkey defined without a signature handler" if opts[:user_nkey_cb]
      end
    end

    def validate_settings!
      raise ArgumentError, "nats: reconnect_buf_size must be an Integer" unless @options[:reconnect_buf_size].is_a?(Integer)

      if @tls
        files = @tls.slice(:cert_file, :key_file, :ca_file).compact
        if @tls[:context] && files.any?
          raise ArgumentError, "nats: tls context cannot be combined with #{files.keys.join(", ")}"
        end
        if files.key?(:cert_file) != files.key?(:key_file)
          raise ArgumentError, "nats: tls cert_file and key_file must be given together"
        end
        # Load the files now, so that a bad one fails the connect.
        tls_context if files.any?
      end

      %i[reconnect_jitter reconnect_jitter_tls].each do |opt|
        jitter = @options[opt]
        raise ArgumentError, "nats: #{opt} must be a number of seconds >= 0" unless jitter.is_a?(Numeric) && jitter >= 0
      end
      if @options[:custom_reconnect_delay] && !@options[:custom_reconnect_delay].respond_to?(:call)
        raise ArgumentError, "nats: custom_reconnect_delay must respond to call"
      end

      raise(NATS::IO::ClientError, "custom inbox may not include '>'") if @inbox_prefix.include?(">")
      raise(NATS::IO::ClientError, "custom inbox may not include '*'") if @inbox_prefix.include?("*")
      raise(NATS::IO::ClientError, "custom inbox may not end in '.'") if @inbox_prefix.end_with?(".")
      raise(NATS::IO::ClientError, "custom inbox may not begin with '.'") if @inbox_prefix.start_with?(".")
    end

    def process_info(line)
      parsed_info = JSON.parse(line)
      discovered = false

      # INFO can be received asynchronously too,
      # so has to be done under the lock.
      synchronize do
        # Symbolize keys from parsed info line
        @server_info = parsed_info.each_with_object({}) do |(k, v), info|
          info[k.to_sym] = v
        end

        # Detect any announced server that we might not be aware of...
        connect_urls = @server_info[:connect_urls]
        if !@options[:ignore_discovered_urls] && connect_urls
          srvs = []
          connect_urls.each do |url|
            # Use the same scheme as the currently in use URI.
            scheme = @uri.scheme
            u = URI.parse("#{scheme}://#{url}")

            # Skip in case it is the current server which we already know
            next if @uri.hostname == u.hostname && @uri.port == u.port

            present = server_pool.detect do |srv|
              srv[:uri].hostname == u.hostname && srv[:uri].port == u.port
            end

            if !present
              # Let explicit user and pass options set the credentials.
              u.user = options[:user] if options[:user]
              u.password = options[:pass] if options[:pass]

              # Use creds from the current server if not set explicitly.
              if @uri
                u.user ||= @uri.user if @uri.user
                u.password ||= @uri.password if @uri.password
              end

              # NOTE: Auto discovery won't work here when TLS host verification is enabled.
              srv = {uri: u, reconnect_attempts: 0, discovered: true, hostname: u.hostname}
              srvs << srv
            end
          end
          srvs.shuffle! unless @options[:dont_randomize_servers]

          # Include in server pool but keep current one as the first one.
          server_pool.push(*srvs)
          discovered = srvs.any?
        end
      end

      # Like nats.go, not when first connecting.
      unless connecting?
        async_cb_call(@discovered_servers_cb) if discovered
        async_cb_call(@lame_duck_mode_cb) if @server_info[:ldm]
      end

      @server_info
    end

    def process_hdr(header)
      hdr = nil
      if header
        hdr = {}
        lines = header.lines

        # Check if the first line has an inline status and description.
        if lines.count > 0
          status_hdr = lines.first.rstrip
          status = status_hdr.slice(NATS_HDR_LINE_SIZE - 1, STATUS_MSG_LEN)

          if status && !status.empty?
            hdr[STATUS_HDR] = status

            if NATS_HDR_LINE_SIZE + 2 < status_hdr.bytesize
              desc = status_hdr.slice(NATS_HDR_LINE_SIZE + STATUS_MSG_LEN, status_hdr.bytesize)
              hdr[DESC_HDR] = desc unless desc.empty?
            end
          end
        end
        begin
          lines.slice(1, header.size).each do |line|
            line.rstrip!
            next if line.empty?
            key, value = line.strip.split(/\s*:\s*/, 2)
            Msg.add_header_value(hdr, key, value)
          end
        rescue => e
          e
        end
      end

      hdr
    end

    # Methods only used by the parser

    def process_pong
      # Take first pong wait and signal any flush in case there was one
      @pongs.synchronize do
        pong = @pongs.pop
        pong&.signal
      end
      @pings_outstanding -= 1
      @pongs_received += 1
    end

    # Received a ping so respond back with a pong
    def process_ping
      @pending_queue << PONG_RESPONSE
      @flush_queue << :ping
      pong = @pongs.new_cond
      @pongs.synchronize { @pongs << pong }
    end

    # Handles protocol errors being sent by the server.
    def process_err(err)
      e = synchronize do
        current = server_pool.first
        @last_err = server_error_for(err, current && current[:auth_required])

        # We cannot recover from auth errors so mark it to avoid
        # retrying to unecessarily next time.
        current[:error_received] = true if current && @last_err.is_a?(NATS::IO::AuthError)

        # Like nats.go, the connection stays up after a permissions
        # violation or when a subscription is refused, so only dispatch the
        # error callback, while holding the lock.
        if @last_err.is_a?(NATS::IO::PermissionViolation) || @last_err.is_a?(NATS::IO::MaxSubscriptionsExceeded)
          err_cb_call(self, @last_err, nil) if @err_cb
          return
        end

        @last_err
      end
      process_op_error(e)
    end

    # Maps the text of an -ERR from the server to an error, like nats.go;
    # others are an AuthError when the server requires auth, otherwise a
    # ServerError.
    def server_error_for(err, auth_required)
      text = err.to_s.strip.delete_prefix("'").delete_suffix("'").strip.downcase
      return NATS::IO::StaleConnectionError.new(err) if text == "stale connection"

      _, klass = SERVER_ERRORS.find { |prefix, _| text.start_with?(prefix) }
      klass ||= auth_required ? NATS::IO::AuthError : NATS::IO::ServerError
      klass.new(err)
    end

    def process_msg(subject, sid, reply, data, header)
      @stats[:in_msgs] += 1
      @stats[:in_bytes] += data.size

      # Throw away in case we no longer manage the subscription
      sub = nil
      last = false
      synchronize { sub = @subs[sid] }
      return unless sub

      err = nil
      sub.synchronize do
        sub.received += 1

        # Check for auto_unsubscribe
        if sub.max
          case
          when sub.received > sub.max
            # Client side support in case server did not receive unsubscribe
            unsubscribe(sid)
            return
          when sub.received == sub.max
            # Cleanup here if we have hit the max..
            synchronize { @subs.delete(sid) }
            last = true
          end
        end

        # In case of a request which requires a future
        # do so here already while holding the lock and return
        if sub.future
          future = sub.future
          hdr = process_hdr(header)
          sub.response = Msg.new(subject: subject, reply: reply, data: data, header: hdr, nc: self, sub: sub)
          future.signal

          return
        elsif sub.pending_queue
          # Async subscribers use a sized queue for processing
          # and should be able to consume messages in parallel.
          if (sub.pending_queue.size >= sub.pending_msgs_limit) \
            || (sub.pending_size >= sub.pending_bytes_limit)
            err = NATS::IO::SlowConsumer.new("nats: slow consumer, messages dropped")
            sub.send(:dropped!)
          else
            hdr = process_hdr(header)

            # Only dispatch message when sure that it would not block
            # the main read loop from the parser.
            msg = Msg.new(subject: subject, reply: reply, data: data, header: hdr, nc: self, sub: sub)

            sub.dispatch(msg)
          end
        end

        # Once it is processed, as it was the last one.
        sub.send(:closed!) if last
      end

      if err
        synchronize do
          @last_err = err
          err_cb_call(self, err, sub) if @err_cb
        end
      end
    end

    def select_next_server
      raise NATS::IO::NoServersError.new("nats: No servers available") if server_pool.empty?

      # Pick next from head of the list
      srv = server_pool.shift

      # Track connection attempts to this server
      srv[:reconnect_attempts] ||= 0
      srv[:reconnect_attempts] += 1

      # Back off in case we are reconnecting to it and have been connected
      sleep reconnect_delay(srv) if should_delay_connect?(srv)

      # Set url of the server to which we would be connected
      @uri = srv[:uri]
      @uri.user = @options[:user] if @options[:user]
      @uri.password = @options[:pass] if @options[:pass]

      srv
    end

    def server_using_secure_connection?
      @server_info[:ssl_required] || @server_info[:tls_required]
    end

    def client_using_secure_connection?
      @uri.scheme == "tls" || @tls
    end

    def tls_context
      return nil unless @tls

      # Allow prepared context and customizations via :tls opts
      return @tls[:context] if @tls[:context]

      @tls_context ||= OpenSSL::SSL::SSLContext.new.tap do |tls_context|
        # Use the default verification options from Ruby:
        # https://github.com/ruby/ruby/blob/96db72ce38b27799dd8e80ca00696e41234db6ba/ext/openssl/lib/openssl/ssl.rb#L19-L29
        #
        # Insecure TLS versions not supported already:
        # https://github.com/ruby/openssl/commit/3e5a009966bd7f806f7180d82cf830a04be28986
        #
        tls_context.set_params

        # Only trust the given CAs, like RootCAs of nats.go.
        if @tls[:ca_file]
          store = OpenSSL::X509::Store.new
          store.add_file(@tls[:ca_file])
          tls_context.cert_store = store
        end

        # Present a client certificate, like ClientCert of nats.go.
        if @tls[:cert_file]
          tls_context.cert = OpenSSL::X509::Certificate.new(File.read(@tls[:cert_file]))
          tls_context.key = OpenSSL::PKey.read(File.read(@tls[:key_file]))
        end
      end
    end

    def single_url_connect_used?
      @single_url_connect_used
    end

    # While reconnecting, publishes are buffered until the connection is back,
    # up to reconnect_buf_size bytes, like nats.go; a negative size disables
    # the buffering. The buffer also holds at most MAX_PENDING_SIZE commands.
    # Like nats.go, refuse messages that the server would refuse, once its
    # max_payload is known.
    def check_max_payload!(size)
      max_payload = @server_info[:max_payload]
      if max_payload && size > max_payload
        raise NATS::IO::MaxPayload.new("nats: maximum payload exceeded")
      end
    end

    def check_reconnect_buf!
      return unless reconnecting?

      limit = @options[:reconnect_buf_size]
      if limit < 0 || @pending_size >= limit || @pending_queue.size >= @pending_queue.max
        raise NATS::IO::ReconnectBufExceeded.new("nats: outbound buffer limit exceeded")
      end
    end

    def send_command(command)
      raise NATS::IO::ConnectionClosedError if closed?

      establish_connection! if !status || (disconnected? && should_reconnect?)

      @pending_size += command.bytesize
      @pending_queue << command

      # TODO: kick flusher here in case pending_size growing large
    end

    # Auto unsubscribes the server by sending UNSUB command and throws away
    # subscription in case already present and has received enough messages.
    def unsubscribe(sub, opt_max = nil)
      sid = nil
      closed = nil
      sub.synchronize do
        sid = sub.sid
        closed = sub.closed
      end
      raise NATS::IO::BadSubscription.new("nats: invalid subscription") if closed

      opt_max_str = " #{opt_max}" unless opt_max.nil?
      send_command("UNSUB #{sid}#{opt_max_str}#{CR_LF}")
      @flush_queue << :unsub

      synchronize { sub = @subs[sid] }
      return unless sub
      removed = synchronize do
        sub.max = opt_max
        @subs.delete(sid) unless sub.max && (sub.received < sub.max)
      end

      sub.synchronize do
        sub.closed = true
      end
      sub.send(:closed!) if removed
    end

    # Drains a subscription for Subscription#drain: unsubscribes, and once
    # the server confirms it and the messages received until then were
    # processed, removes the subscription.
    def drain_subscription(sub)
      raise NATS::IO::ConnectionClosedError.new("nats: connection closed") if closed?
      raise NATS::IO::ConnectionDrainingError.new("nats: connection draining") if draining?
      raise NATS::IO::BadSubscription.new("nats: invalid subscription") if sub.synchronize { sub.closed }
      return if sub.draining?

      drain_sub(sub)
      Thread.new { finish_sub_drain(sub) }
      nil
    end

    def finish_sub_drain(sub)
      timeout = @options[:drain_timeout]
      deadline = MonotonicTime.now + timeout

      # Like nats.go, the PONG tells that the server processed the UNSUB,
      # so that no more messages come.
      begin
        flush(timeout)
      rescue NATS::IO::Error
        # Waits for the messages anyway, until the deadline.
      end

      sleep 0.05 until closed? || sub.send(:idle?) || MonotonicTime.now > deadline
      return if closed?

      unless sub.send(:idle?)
        err_cb_call(self, NATS::IO::DrainTimeoutError.new("nats: draining subscription timed out"), sub)
      end
      synchronize { @subs.delete(sub.sid) }
      sub.synchronize { sub.closed = true }
      sub.send(:closed!)
    rescue => e
      err_cb_call(self, e, sub)
    end

    def drain_sub(sub)
      sid = nil
      closed = nil
      sub.synchronize do
        sid = sub.sid
        closed = sub.closed
      end
      return if closed

      send_command("UNSUB #{sid}#{CR_LF}")
      @flush_queue << :drain

      sub.synchronize { sub.drained = true }
      synchronize { sub = @subs[sid] }
      nil unless sub
    end

    def do_drain
      synchronize { @status = DRAINING_SUBS }

      # Do unsubscribe protocol for all the susbcriptions, then have a single thread
      # waiting until all subs are done or drain timeout error reported to async error cb.
      subs = []
      @subs.each do |_, sub|
        next if sub == @resp_sub
        drain_sub(sub)
        subs << sub
      end
      force_flush!

      # Wait until all subs have no pending messages.
      drain_timeout = MonotonicTime.now + @options[:drain_timeout]
      to_delete = []

      loop do
        break if MonotonicTime.now > drain_timeout
        sleep 0.1

        # Wait until all subs are done.
        @subs.each do |_, sub|
          if (sub != @resp_sub) && (sub.pending_queue.size == 0)
            to_delete << sub
          end
        end
        next if to_delete.empty?

        to_delete.each do |sub|
          @subs.delete(sub.sid)
          sub.synchronize { sub.closed = true }
        end
        to_delete.clear

        # Wait until only the resp mux is remaining or there are no subscriptions.
        if @subs.count == 1
          _, sub = @subs.first
          if sub == @resp_sub
            break
          end
        elsif @subs.count == 0
          break
        end
      end

      subscription_executor.shutdown
      subscription_executor.wait_for_termination(@options[:drain_timeout])
      subs.each { |sub| sub.send(:closed!, wait: false) unless @subs.key?(sub.sid) }

      if MonotonicTime.now > drain_timeout
        e = NATS::IO::DrainTimeoutError.new("nats: draining connection timed out")
        err_cb_call(self, e, nil) if @err_cb
      end
      synchronize { @status = DRAINING_PUBS }

      # Remove resp mux handler in case there is one.
      unsubscribe(@resp_sub) if @resp_sub
      close
    end

    def send_flush_queue(s)
      @flush_queue << s
    end

    def delete_sid(sid)
      @subs.delete(sid)
    end

    # Registers a listener that parts of the library, like JetStream
    # contexts and services, use to learn about connection events without
    # replacing the callbacks of the user. It is called with :disconnect
    # when the connection is lost and starts to reconnect, and with :close
    # once the connection is closed, in the thread of the event. What it
    # raises goes to on_error. Returns the listener, for
    # remove_status_listener.
    def add_status_listener(&listener)
      synchronize { @status_listeners << listener }
      listener
    end

    def remove_status_listener(listener)
      synchronize { @status_listeners.delete(listener) }
    end

    def notify_status_listeners(event)
      synchronize { @status_listeners.dup }.each do |listener|
        listener.call(event)
      rescue => e
        err_cb_call(self, e, nil)
      end
    end

    # Calls a connection event callback, handing what it raises to on_error,
    # so that it does not break the thread that calls it.
    def async_cb_call(cb)
      cb&.call
    rescue => e
      err_cb_call(self, e, nil)
    end

    def err_cb_call(nc, e, sub)
      # Services stop on the errors of their subscriptions, like nats.go micro.
      @_services&.send(:handle_async_error, e, sub) if sub

      return unless @err_cb

      cb = @err_cb
      case cb.arity
      when 0 then cb.call
      when 1 then cb.call(e)
      when 2 then cb.call(e, sub)
      else cb.call(nc, e, sub)
      end
    end

    def auth_connection?
      !@uri.user.nil?
    end

    def connect_command
      # Like nats.go, refuse to connect when the server cannot honor no_echo,
      # which servers before protocol 1 ignore.
      if @options[:no_echo] && @server_info[:proto].to_i < 1
        raise NATS::IO::NoEchoNotSupported.new("nats: no echo option not supported by this server")
      end

      cs = {
        verbose: @options[:verbose],
        pedantic: @options[:pedantic],
        lang: NATS::IO::LANG,
        version: NATS::IO::VERSION,
        protocol: NATS::IO::PROTOCOL
      }
      cs[:name] = @options[:name] if @options[:name]
      cs[:echo] = false if @options[:no_echo]

      if auth_connection?
        if @uri.password
          cs[:user] = @uri.user
          cs[:pass] = @uri.password
        else
          cs[:auth_token] = @uri.user
        end
      elsif @user_jwt_cb && @signature_cb
        nonce = @server_info[:nonce]
        cs[:jwt] = @user_jwt_cb.call
        cs[:sig] = @signature_cb.call(nonce)
      elsif @user_nkey_cb && @signature_cb
        nonce = @server_info[:nonce]
        cs[:nkey] = @user_nkey_cb.call
        cs[:sig] = @signature_cb.call(nonce)
      end

      # Like nats.go, credentials in the URL take precedence over the handler.
      if @user_info_handler && !auth_connection?
        cs[:user], cs[:pass] = @user_info_handler.call
      end

      cs[:auth_token] = @auth_token if @auth_token
      cs[:auth_token] = @token_handler.call if @token_handler

      if @server_info[:headers]
        cs[:headers] = @server_info[:headers]
        cs[:no_responders] = if @options[:no_responders] == false
          @options[:no_responders]
        else
          @server_info[:headers]
        end
      end

      "CONNECT #{cs.to_json}#{CR_LF}"
    end

    # Handles errors from reading, parsing the protocol or stale connection.
    # the lock should not be held entering this function.
    def process_op_error(e)
      # A background thread being stopped by close or a reconnect sees
      # errors from that; it must not start another close or reconnect,
      # which would wait for the thread that is stopping it.
      return if stopping?

      should_bail = synchronize do
        connecting? || closed? || reconnecting?
      end
      return if should_bail

      synchronize do
        @last_err = e
        err_cb_call(self, e, nil) if @err_cb

        # If we were connected and configured to reconnect,
        # then trigger disconnect and start reconnection logic
        # Like nats.go, not while draining.
        if @status == CONNECTED && should_reconnect?
          initiate_reconnect
          Thread.exit
          return
        end

        # Otherwise, stop trying to reconnect and close the connection
        @status = DISCONNECTED
      end

      # Otherwise close the connection to NATS
      close
    end

    def initiate_reconnect
      @status = RECONNECTING
      old_io = @io
      @io = nil

      # Wake a read loop blocked on the socket by shutting it down, and
      # close the socket only once the loop has stopped: on JRuby a close
      # right after the shutdown can leave the read blocked for good.
      if @read_loop_thread&.alive? && @read_loop_thread != Thread.current
        old_io&.shutdown_read
      end

      # TODO: Reconnecting pending buffer?

      generation = @close_generation

      # Do reconnect under a different thread than the one
      # in which we got the error.
      Thread.new do
        stop_threads!
        old_io&.close

        @subscription_executor.shutdown

        attempt_reconnect(generation)
      rescue NATS::IO::NoServersError => e
        @last_err = e
        close
      end
    end

    # Gathers data from the socket and sends it to the parser.
    def read_loop
      loop do
        return if stopping?

        should_bail = synchronize do
          # FIXME: In case of reconnect as well?
          @status == CLOSED or @status == RECONNECTING
        end
        if !@io || @io.closed? || should_bail
          return
        end

        # TODO: Remove timeout and just wait to be ready
        data = @io.read(NATS::IO::MAX_SOCKET_READ_BYTES)
        @parser.parse(data) if data
      rescue Errno::ETIMEDOUT
        # FIXME: We do not really need a timeout here...
        retry
      rescue => e
        # Asked to stop: the error comes from the socket being shut down.
        return if stopping?

        # In case of reading/parser errors, trigger
        # reconnection logic in case desired.
        process_op_error(e)
      end
    end

    # Waits for client to notify the flusher that it will be
    # it is sending a command.
    def flusher_loop
      loop do
        # Blocks waiting for the flusher to be kicked...
        @flush_queue.pop
        return if stopping?

        should_bail = synchronize do
          (@status != CONNECTED && !draining?) || @status == CONNECTING
        end
        return if should_bail

        # Skip in case nothing remains pending already.
        next if @pending_queue.empty?

        force_flush!

        synchronize do
          @pending_size = 0
        end
      end
    end

    def force_flush!
      # FIXME: should limit how many commands to take at once
      # since producers could be adding as many as possible
      # until reaching the max pending queue size.
      cmds = []
      cmds << @pending_queue.pop until @pending_queue.empty?
      if @io
        begin
          @io.write(cmds.join) unless cmds.empty?
        rescue => e
          synchronize do
            @last_err = e
            err_cb_call(self, e, nil) if @err_cb
          end

          process_op_error(e)
          nil
        end
      end
    end

    def ping_interval_loop(stop)
      loop do
        return if stop.wait(@options[:ping_interval])

        # Skip ping interval until connected, and while draining, like nats.go.
        next if @status != CONNECTED

        if @pings_outstanding >= @options[:max_outstanding_pings]
          process_op_error(NATS::IO::StaleConnectionError.new("nats: stale connection"))
          return
        end

        @pings_outstanding += 1
        send_command(PING_REQUEST)
        @flush_queue << :ping
      end
    rescue => e
      process_op_error(e)
    end

    def process_connect_init
      # With tls_handshake_first the server expects the TLS handshake
      # before it sends INFO (nats-server tls { handshake_first: true }).
      @io.setup_tls! if @options[:tls_handshake_first]

      # FIXME: Can receive PING as well here in recent versions.
      line = @io.read_line(options[:connect_timeout])
      if !line || line.empty?
        raise NATS::IO::NoInfoReceived.new("nats: protocol exception, INFO not received")
      end

      if (match = line.match(NATS::Protocol::INFO))
        info_json = match.captures.first
        process_info(info_json)
      else
        raise NATS::IO::NoInfoReceived.new("nats: protocol exception, INFO not valid")
      end

      if server_using_secure_connection? && client_using_secure_connection?
        @io.setup_tls! unless @options[:tls_handshake_first]
      # Server > v2.9.19 returns tls_required regardless of no_tls for WebSocket config being used so need to check URI.
      elsif server_using_secure_connection? && !client_using_secure_connection? && (@uri.scheme != "ws")
        raise NATS::IO::SecureConnRequired.new("TLS/SSL required by server")
      # Server < v2.9.19 requiring TLS/SSL over websocket but not requiring it over standard protocol
      # doesn't send `tls_required` in its INFO so we need to check the URI scheme for WebSocket.
      elsif client_using_secure_connection? && !server_using_secure_connection? && (@uri.scheme != "wss")
        raise NATS::IO::SecureConnWanted.new("TLS/SSL not supported by server")
      else
        # Otherwise, use a regular connection.
      end

      # Send connect and process synchronously. If using TLS,
      # it should have handled upgrading at this point.
      # Send ping/pong after connect, in the same write: a server that
      # refuses the connection, as when it has too many, closes it right
      # after its -ERR, so that a second write would fail before the
      # -ERR is read.
      @io.write(connect_command + PING_REQUEST)

      next_op = @io.read_line(options[:connect_timeout])
      if @options[:verbose]
        # Need to get another command here if verbose
        raise NATS::IO::ConnectError.new("expected to receive +OK") unless next_op =~ NATS::Protocol::OK
        next_op = @io.read_line(options[:connect_timeout])
      end

      case next_op
      when NATS::Protocol::PONG
        # do nothing
      when NATS::Protocol::ERR
        raise server_error_for($1, @server_info[:auth_required])
      else
        raise NATS::IO::ConnectError.new("expected PONG, got #{next_op}")
      end
    end

    # Reconnect logic. generation is @close_generation from when the
    # reconnect started; a close since then cancels the reconnect.
    def attempt_reconnect(generation)
      return if closed_since?(generation)

      @disconnect_cb&.call(@last_err)
      notify_status_listeners(:disconnect)

      # Clear sticky error
      @last_err = nil

      # Do reconnect
      srv = nil
      begin
        return if closed_since?(generation)

        srv = select_next_server

        # Set hostname to use for TLS hostname verification
        if client_using_secure_connection? && single_url_connect_used?
          # Reuse original hostname name in case of using TLS.
          @hostname ||= srv[:hostname]
        else
          @hostname = srv[:hostname]
        end

        # Establish TCP connection with new server
        @io = create_socket
        @io.connect
        @stats[:reconnects] += 1

        # Established TCP connection successfully so can start connect
        process_connect_init

        # Reset reconnection attempts if connection is valid
        srv[:reconnect_attempts] = 0
        srv[:auth_required] ||= true if @server_info[:auth_required]

        # Add back to rotation since successfully connected
        server_pool << srv
      rescue NATS::IO::NoServersError => e
        raise e
      rescue => e
        # In case there was an error from the server check
        # to see whether need to take it out from rotation
        srv[:auth_required] ||= true if @server_info[:auth_required]
        srv[:error_received] = true if e.is_a?(NATS::IO::NoEchoNotSupported)
        server_pool << srv if can_reuse_server?(srv)

        @last_err = e

        # Trigger async error handler
        err_cb_call(self, e, nil) if @err_cb

        # Continue retrying until there are no options left in the server pool
        retry
      end

      # Under the lock, so that a concurrent close either cancels this or
      # finds the new connection in place and closes it.
      synchronize do
        if @close_generation != generation
          @io.close
          @io = nil
          return
        end

        # Clear pending flush calls and reset state before restarting loops
        @flush_queue.clear
        @pings_outstanding = 0
        @pongs_received = 0

        # Replay all subscriptions
        @subs.each_pair do |sid, sub|
          @io.write("SUB #{sub.subject} #{sub.queue} #{sid}#{CR_LF}")
        end

        # Flush anything which was left pending, in case of errors during flush
        # then we should raise error then retry the reconnect logic
        cmds = []
        cmds << @pending_queue.pop until @pending_queue.empty?
        @io.write(cmds.join) unless cmds.empty?
        @status = CONNECTED
        @pending_size = 0

        # Reset parser state here to avoid unknown protocol errors
        # on reconnect...
        @parser.reset!

        # Now connected to NATS, and we can restart parser loop, flusher
        # and ping interval
        start_threads!
      end

      @reconnect_cb&.call
    end

    def closed_since?(generation)
      synchronize { @close_generation != generation }
    end

    def close_connection(conn_status, do_cbs = true)
      synchronize do
        @connect_called = false
        if @status == CLOSED
          @status = conn_status
          return
        end
        @close_generation += 1
      end

      stop_threads!

      @subscription_executor&.shutdown
      @subscription_executor&.wait_for_termination(options[:close_timeout])

      # TODO: Delete any other state which we are not using here too.
      closed_subs = nil
      synchronize do
        @pongs.synchronize do
          @pongs.each do |pong|
            pong.signal
          end
          @pongs.clear
        end

        # Try to write any pending flushes in case
        # we have a connection then close it.
        should_flush = @pending_queue && @io && @io.socket && !@io.closed?
        if should_flush
          begin
            cmds = []
            cmds << @pending_queue.pop until @pending_queue.empty?

            # FIXME: Fails when empty on TLS connection?
            @io.write(cmds.join) unless cmds.empty?
          rescue => e
            @last_err = e
            err_cb_call(self, e, nil) if @err_cb
          end
        end

        # Destroy any remaining subscriptions.
        closed_subs = @subs.values
        @subs.clear

        if do_cbs
          @disconnect_cb&.call(@last_err)
          @close_cb&.call
        end

        @status = conn_status

        # Close the established connection in case
        # we still have it.
        if @io
          @io.close if @io.socket
          @io = nil
        end
      end

      return unless do_cbs

      # Like nats.go micro, services stop once their connection is closed,
      # and JetStream contexts fail the acks they wait for.
      notify_status_listeners(:close)

      closed_subs&.each { |sub| sub.send(:closed!, wait: false) }
    end

    # Asks the read loop, flusher and ping threads to stop, wakes them from
    # wherever they block, and waits for them to finish.
    #
    # They are never killed: Thread#exit on a thread that is waiting for
    # the client lock can swallow the lock's wakeup, so that the next
    # thread waiting for the lock sleeps forever on an unlocked lock (#183).
    def stop_threads!(timeout = NATS::IO::THREADS_STOP_TIMEOUT)
      threads = [@read_loop_thread, @flusher_thread, @ping_interval_thread].compact
      threads.each { |t| t[:nats_stop]&.stop! } # also wakes the ping thread

      begin
        @flush_queue&.push(:fallout, true)
      rescue ThreadError
        # Queue is full, so the flusher is awake already.
      end
      # Wake the read loop if it is blocked on the socket. Only while it
      # runs: shutdown acts on the socket itself, which a forked child
      # (whose threads are gone) shares with the parent.
      if @read_loop_thread&.alive? && @read_loop_thread != Thread.current
        @io&.shutdown_read
      end

      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
      threads.each do |t|
        next if t == Thread.current

        t.join([deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC), 0].max)
      end
    end

    def stopping?
      Thread.current[:nats_stop]&.stopped?
    end

    def start_thread(name, stop, &block)
      thread = Thread.new(&block)
      thread[:nats_stop] = stop
      thread.name = name
      thread.abort_on_exception = true
      thread
    end

    def start_threads!
      # Reading loop for gathering data
      @read_loop_thread = start_thread("nats:read_loop", NATS::IO::StopSignal.new) { read_loop }

      # Flusher loop for sending commands
      @flusher_thread = start_thread("nats:flusher_loop", NATS::IO::StopSignal.new) { flusher_loop }

      # Ping interval handling for keeping alive the connection
      ping_stop = NATS::IO::StopSignal.new
      @ping_interval_thread = start_thread("nats:ping_loop", ping_stop) { ping_interval_loop(ping_stop) }

      # Subscription handling thread pool
      @subscription_executor = Concurrent::ThreadPoolExecutor.new(
        name: "nats:subscription", # threads will be given names like nats:subscription-worker-1
        max_threads: NATS::IO::DEFAULT_TOTAL_SUB_CONCURRENCY,
        # JRuby has a bug on certain Java version of not creating new threads:
        # https://github.com/ruby-concurrency/concurrent-ruby/issues/864
        min_threads: defined?(JRUBY_VERSION) ? 2 : 0
      )
    end

    # Prepares requests subscription that handles the responses
    # for the new style request response.
    def start_resp_mux_sub!
      @resp_sub_prefix = new_inbox
      @resp_map = Hash.new { |h, k| h[k] = {} }

      @resp_sub = Subscription.new
      @resp_sub.subject = "#{@resp_sub_prefix}.*"
      @resp_sub.received = 0
      @resp_sub.nc = self

      # FIXME: Allow setting pending limits for responses mux subscription.
      @resp_sub.pending_msgs_limit = NATS::IO::DEFAULT_SUB_PENDING_MSGS_LIMIT
      @resp_sub.pending_bytes_limit = NATS::IO::DEFAULT_SUB_PENDING_BYTES_LIMIT
      @resp_sub.pending_queue = SizedQueue.new(@resp_sub.pending_msgs_limit)
      @resp_sub.callback = proc do |msg|
        # Pick the token and signal the request under the mutex
        # from the subscription itself.
        token = msg.subject.split(".").last
        future = nil
        synchronize do
          future = @resp_map[token][:future]
          @resp_map[token][:response] = msg
        end

        # Signal back that the response has arrived
        # in case the future has not been yet delete.
        @resp_sub.synchronize do
          future.signal if future
        end
      end

      sid = (@ssid += 1)
      @resp_sub.sid = sid
      @subs[sid] = @resp_sub
      send_command("SUB #{@resp_sub.subject} #{sid}#{CR_LF}")
      @flush_queue << :sub
    end

    def can_reuse_server?(server)
      return false if server.nil?

      # We can always reuse servers with infinite reconnects settings
      return true if @options[:max_reconnect_attempts] < 0

      # In case of hard errors like authorization errors, drop the server
      # already since won't be able to connect.
      return false if server[:error_received]

      # We will retry a number of times to reconnect to a server.
      server[:reconnect_attempts] <= @options[:max_reconnect_attempts]
    end

    # Seconds to wait before the next attempt to connect to server: what
    # custom_reconnect_delay returns for the attempts made to it so far, or
    # else reconnect_time_wait plus a random jitter of up to reconnect_jitter
    # (reconnect_jitter_tls for TLS connections).
    def reconnect_delay(server)
      attempts = server ? server[:reconnect_attempts].to_i : 0
      if (cb = @options[:custom_reconnect_delay])
        return [cb.call(attempts).to_f, 0].max
      end

      secure = @tls || (server && %w[tls wss].include?(server[:uri].scheme))
      jitter = secure ? @options[:reconnect_jitter_tls] : @options[:reconnect_jitter]
      wait = @options[:reconnect_time_wait].to_f
      wait += rand * jitter if jitter > 0
      wait
    end

    def should_delay_connect?(server)
      server[:was_connected] && server[:reconnect_attempts] >= 0
    end

    def should_not_reconnect?
      !@options[:reconnect]
    end

    def should_reconnect?
      @options[:reconnect]
    end

    def create_socket
      socket_class = case @uri.scheme
      when "nats", "tls"
        NATS::IO::Socket
      when "ws", "wss"
        require_relative "websocket"
        NATS::IO::WebSocket
      else
        raise NotImplementedError, "#{@uri.scheme} protocol is not supported, check NATS cluster URL spelling"
      end

      socket_class.new(
        uri: @uri,
        tls: {context: tls_context, hostname: @hostname},
        connect_timeout: @options[:connect_timeout]
      )
    end

    def setup_nkeys_connect
      begin
        require "nkeys"
        require "base64"
      rescue LoadError
        raise(Error, "nkeys is not installed")
      end

      if @nkeys_seed
        @user_nkey_cb = nkey_cb_for_nkey_file(@nkeys_seed)
        @signature_cb = signature_cb_for_nkey_file(@nkeys_seed)
      elsif @user_credentials
        # When the credentials are within a single decorated file.
        @user_jwt_cb = jwt_cb_for_creds_file(@user_credentials)
        @signature_cb = signature_cb_for_creds_file(@user_credentials)
      elsif @user_credentials_data
        # The contents of a decorated credentials file.
        jwt = creds_section(@user_credentials_data.lines, "BEGIN NATS USER JWT")
        seed = creds_section(@user_credentials_data.lines, "BEGIN USER NKEY SEED")
        raise(Error, "No JWT found in user_credentials_data") unless jwt
        raise(Error, "No nkey user seed found in user_credentials_data") unless seed

        @user_jwt_cb = proc { jwt }
        @signature_cb = signature_cb_for_seed(seed)
      elsif @user_jwt
        user_jwt = @user_jwt
        @user_jwt_cb = proc { user_jwt }
        @signature_cb = signature_cb_for_seed(@user_seed)
      end
    end

    # Returns the line that follows the marker line in a credentials file.
    def creds_section(lines, marker)
      idx = lines.index { |line| line.include?(marker) }
      lines[idx + 1]&.chomp if idx
    end

    def signature_cb_for_seed(seed)
      # Fail right away on an invalid seed. Each signature wipes the copy
      # of the seed it was made with.
      begin
        NKEYS.from_seed(seed.dup).wipe!
      rescue NKEYS::Error, ArgumentError => e
        raise ArgumentError, "nats: invalid nkey seed (#{e.message})"
      end
      proc { |nonce|
        kp = NKEYS.from_seed(seed.dup)
        raw_signed = kp.sign(nonce)
        kp.wipe!
        Base64.urlsafe_encode64(raw_signed).delete("=")
      }
    end

    def signature_cb_for_nkey_file(nkey)
      proc { |nonce|
        seed = File.read(nkey).chomp
        kp = NKEYS.from_seed(seed)
        raw_signed = kp.sign(nonce)
        kp.wipe!
        encoded = Base64.urlsafe_encode64(raw_signed)
        encoded.gsub("=", "")
      }
    end

    def nkey_cb_for_nkey_file(nkey)
      proc {
        seed = File.read(nkey).chomp
        kp = NKEYS.from_seed(seed)

        # Take a copy since original will be gone with the wipe.
        pub_key = kp.public_key.dup
        kp.wipe!

        pub_key
      }
    end

    def jwt_cb_for_creds_file(creds)
      proc {
        jwt_start = "BEGIN NATS USER JWT"
        found = false
        jwt = nil

        File.readlines(creds).each do |line|
          if found
            jwt = line.chomp
            break
          elsif line.include?(jwt_start)
            found = true
          end
        end

        raise(Error, "No JWT found in #{creds}") if !found

        jwt
      }
    end

    def signature_cb_for_creds_file(creds)
      proc { |nonce|
        seed_start = "BEGIN USER NKEY SEED"
        found = false
        seed = nil

        File.readlines(creds).each do |line|
          if found
            seed = line.chomp
            break
          elsif line.include?(seed_start)
            found = true
          end
        end

        raise(Error, "No nkey user seed found in #{creds}") if !found

        kp = NKEYS.from_seed(seed)
        raw_signed = kp.sign(nonce)

        # seed is a reference so also cleared when doing wipe,
        # which can be done since Ruby strings are mutable.
        kp.wipe
        encoded = Base64.urlsafe_encode64(raw_signed)

        # Remove padding
        encoded.gsub("=", "")
      }
    end

    # Parses a URL, or a comma separated list of them, given to
    # set_server_pool, like connect does.
    def parse_server_urls(url)
      uris = url.is_a?(URI) ? [url.dup] : process_uri(url.to_s)
      raise ArgumentError, "nats: invalid server URL #{url.inspect}" if uris.empty?

      uris.each do |uri|
        uri.port ||= DEFAULT_PORT.fetch(uri.scheme.to_sym, DEFAULT_PORT[:nats]) if uri.scheme
        unless %w[nats tls ws wss].include?(uri.scheme) && !uri.hostname.to_s.empty? && uri.port.between?(1, 65535)
          raise ArgumentError, "nats: invalid server URL #{url.inspect}"
        end
      end
    rescue URI::Error => e
      raise ArgumentError, "nats: invalid server URL #{url.inspect}: #{e.message}"
    end

    def same_server?(a, b)
      a.hostname == b.hostname && a.port == b.port
    end

    def process_uri(uris)
      uris.gsub(/\s+/, "").split(",").map do |uri|
        # Scheme
        uri = "nats://#{uri}" if !uri.include?("://")

        uri_object = URI(uri)

        # Host and Port
        uri_object.hostname ||= "localhost"
        uri_object.port ||= DEFAULT_PORT.fetch(uri_object.scheme.to_sym, DEFAULT_PORT[:nats])

        uri_object
      end
    end
  end

  module IO
    include Status

    # Client creates a connection to the NATS Server.
    Client = ::NATS::Client

    MAX_RECONNECT_ATTEMPTS = 10
    RECONNECT_TIME_WAIT = 2

    # Upper bounds of the random delay added to reconnect_time_wait, in seconds.
    RECONNECT_JITTER = 0.1
    RECONNECT_JITTER_TLS = 1

    # Maximum accumulated pending commands bytesize before forcing a flush.
    MAX_PENDING_SIZE = 32768

    # Maximum number of flush kicks that can be queued up before we block.
    MAX_FLUSH_KICK_SIZE = 1024

    # Maximum number of bytes which we will be gathering on a single read.
    # TODO: Make dynamic?
    MAX_SOCKET_READ_BYTES = 32768

    # Ping intervals
    DEFAULT_PING_INTERVAL = 120
    DEFAULT_PING_MAX = 2

    # Bytes of publishes buffered while reconnecting.
    DEFAULT_RECONNECT_BUF_SIZE = 8 * 1024 * 1024

    # Default IO timeouts
    DEFAULT_CONNECT_TIMEOUT = 2
    DEFAULT_READ_WRITE_TIMEOUT = 2
    DEFAULT_DRAIN_TIMEOUT = 30
    DEFAULT_CLOSE_TIMEOUT = 30

    # How long to wait for the read loop, flusher and ping threads to
    # stop on close or reconnect.
    THREADS_STOP_TIMEOUT = 5

    # Asks a background thread to stop, and lets it sleep until then.
    class StopSignal
      def initialize
        @mutex = Mutex.new
        @cond = ConditionVariable.new
        @stopped = false
      end

      def stop!
        @mutex.synchronize do
          @stopped = true
          @cond.broadcast
        end
      end

      def stopped?
        @stopped
      end

      # Sleeps up to timeout seconds; returns whether stop! was called.
      def wait(timeout)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        @mutex.synchronize do
          until @stopped
            left = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            break if left <= 0

            @cond.wait(@mutex, left)
          end
          @stopped
        end
      end
    end

    # Default Pending Limits
    DEFAULT_SUB_PENDING_MSGS_LIMIT = 65536
    DEFAULT_SUB_PENDING_BYTES_LIMIT = 65536 * 1024

    DEFAULT_TOTAL_SUB_CONCURRENCY = 24
    DEFAULT_SINGLE_SUB_CONCURRENCY = 1

    # Implementation adapted from https://github.com/redis/redis-rb
    class Socket
      attr_accessor :socket

      def initialize(options = {})
        @uri = options[:uri]
        @connect_timeout = options[:connect_timeout]
        @write_timeout = options[:write_timeout]
        @read_timeout = options[:read_timeout]
        @socket = nil
        @tls = options[:tls]
      end

      def connect
        addrinfo = ::Socket.getaddrinfo(@uri.hostname, nil, ::Socket::AF_UNSPEC, ::Socket::SOCK_STREAM)
        addrinfo.each_with_index do |ai, i|
          @socket = connect_addrinfo(ai, @uri.port, @connect_timeout)
          break
        rescue SystemCallError => e
          # Give up if no more available
          raise e if addrinfo.length == i + 1
        end

        # Set TCP no delay by default
        @socket.setsockopt(::Socket::IPPROTO_TCP, ::Socket::TCP_NODELAY, 1)
      end

      # (Re-)connect using secure connection if server and client agreed on using it.
      def setup_tls!
        # Setup TLS connection by rewrapping the socket
        tls_socket = OpenSSL::SSL::SSLSocket.new(@socket, @tls.fetch(:context))

        # Close TCP socket after closing TLS socket as well.
        tls_socket.sync_close = true

        # Required to enable hostname verification if Ruby runtime supports it (>= 2.4):
        # https://github.com/ruby/openssl/commit/028e495734e9e6aa5dba1a2e130b08f66cf31a21
        tls_socket.hostname = @tls[:hostname]

        tls_handshake(tls_socket)
        @socket = tls_socket
      end

      def read_line(deadline = nil)
        # FIXME: Should accumulate and read in a non blocking way instead
        unless ::IO.select([@socket], nil, nil, deadline)
          raise NATS::IO::SocketTimeoutError
        end
        @socket.gets
      end

      def read(max_bytes, deadline = nil)
        begin
          @socket.read_nonblock(max_bytes)
        rescue ::IO::WaitReadable
          if ::IO.select([@socket], nil, nil, deadline)
            retry
          else
            raise NATS::IO::SocketTimeoutError
          end
        rescue ::IO::WaitWritable
          if ::IO.select(nil, [@socket], nil, deadline)
            retry
          else
            raise NATS::IO::SocketTimeoutError
          end
        end
      rescue EOFError => e
        if (RUBY_ENGINE == "jruby") && (e.message == "No message available")
          # FIXME: <EOFError: No message available> can happen in jruby
          # even though seems it is temporary and eventually possible
          # to read from socket.
          return nil
        end
        raise Errno::ECONNRESET
      end

      def write(data, deadline = nil)
        length = data.bytesize
        total_written = 0

        loop do
          written = @socket.write_nonblock(data)

          total_written += written
          break total_written if total_written >= length
          data = data.byteslice(written..-1)
        rescue ::IO::WaitWritable
          if ::IO.select(nil, [@socket], nil, deadline)
            retry
          else
            raise NATS::IO::SocketTimeoutError
          end
        rescue ::IO::WaitReadable
          if ::IO.select([@socket], nil, nil, deadline)
            retry
          else
            raise NATS::IO::SocketTimeoutError
          end
        end
      rescue EOFError
        raise Errno::ECONNRESET
      end

      def close
        @socket.close
      end

      # Makes a read blocked on the socket in another thread return,
      # while writes keep working.
      def shutdown_read
        io = @socket.respond_to?(:to_io) ? @socket.to_io : @socket
        io.shutdown(::Socket::SHUT_RD)
      rescue IOError, SystemCallError
        # Already closed or not connected.
      end

      def closed?
        @socket.closed?
      end

      # The address of the server, as in "127.0.0.1:4222".
      def remote_address
        raw_socket.remote_address.inspect_sockaddr
      end

      # The local address of the connection, as in "127.0.0.1:52144".
      def local_address
        raw_socket.local_address.inspect_sockaddr
      end

      private

      # The TCP socket, also under TLS.
      def raw_socket
        @socket.respond_to?(:to_io) ? @socket.to_io : @socket
      end

      # Performs the TLS handshake, giving up after the connect timeout.
      def tls_handshake(tls_socket)
        return tls_socket.connect unless @connect_timeout

        deadline = MonotonicTime.now + @connect_timeout
        begin
          tls_socket.connect_nonblock
        rescue ::IO::WaitReadable, ::IO::WaitWritable => e
          left = deadline - MonotonicTime.now
          ready = if e.is_a?(::IO::WaitReadable)
            ::IO.select([tls_socket], nil, nil, [left, 0].max)
          else
            ::IO.select(nil, [tls_socket], nil, [left, 0].max)
          end
          raise NATS::IO::SocketTimeoutError, "nats: timeout during TLS handshake" unless ready

          retry
        end
      end

      def connect_addrinfo(ai, port, timeout)
        sock = ::Socket.new(::Socket.const_get(ai[0]), ::Socket::SOCK_STREAM, 0)
        sockaddr = ::Socket.pack_sockaddr_in(port, ai[3])

        begin
          sock.connect_nonblock(sockaddr)
        rescue Errno::EINPROGRESS, Errno::EALREADY, ::IO::WaitWritable
          unless ::IO.select(nil, [sock], nil, timeout)
            sock.close
            raise NATS::IO::SocketTimeoutError, "nats: timeout dialing #{ai[3]}:#{port}"
          end

          # Confirm that connection was established
          begin
            sock.connect_nonblock(sockaddr)
          rescue Errno::EISCONN
            # Connection was established without issues.
          end
        end

        sock
      rescue IOError => e
        # JRuby raises a plain IOError for a refused connection.
        if (RUBY_ENGINE == "jruby") && e.message.include?("Connection refused")
          raise Errno::ECONNREFUSED
        end
        raise
      end
    end
  end

  NANOSECONDS = 1_000_000_000

  class MonotonicTime
    # Implementation of MonotonicTime adapted from
    # https://github.com/ruby-concurrency/concurrent-ruby/
    class << self
      if defined?(Process::CLOCK_MONOTONIC)
        def now
          Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end
      elsif RUBY_ENGINE == "jruby"
        def now
          java.lang.System.nanoTime / 1_000_000_000.0
        end
      else
        def now
          # Fallback to regular time behavior
          ::Time.now.to_f
        end
      end

      def with_nats_timeout(timeout)
        start_time = now
        yield
        end_time = now
        duration = end_time - start_time
        if duration > timeout
          raise NATS::Timeout.new("nats: timeout")
        end
      end

      def since(t0)
        now - t0
      end
    end
  end
end
