# frozen_string_literal: true

require "digest/sha1"
require "securerandom"
require "zlib"

module NATS
  module IO
    # WebSocket to connect to NATS via WebSocket and automatically decode and encode frames.
    #
    # It does the HTTP upgrade and the framing of RFC 6455 itself, like
    # nats.go, including the permessage-deflate compression of RFC 7692.

    # @see https://docs.nats.io/running-a-nats-service/configuration/websocket

    class WebSocket < Socket
      class HandshakeError < RuntimeError; end

      # A frame that breaks RFC 6455, which fails the connection.
      class FrameError < RuntimeError; end

      # Opcodes, from https://tools.ietf.org/html/rfc6455#section-5.2
      CONTINUATION_FRAME = 0
      TEXT_FRAME = 1
      BINARY_FRAME = 2
      CLOSE_FRAME = 8
      PING_FRAME = 9
      PONG_FRAME = 10

      FINAL_BIT = 0x80
      # Set on the first frame of a compressed message, from https://tools.ietf.org/html/rfc7692#section-6
      RSV1_BIT = 0x40
      MASK_BIT = 0x80
      MAX_CONTROL_PAYLOAD_SIZE = 125

      GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

      # Per-message compression, without context takeover in either
      # direction, which is what nats.go asks for and nats-server offers.
      PMC_EXTENSION = "permessage-deflate"
      PMC_SERVER_NO_CONTEXT = "server_no_context_takeover"
      PMC_CLIENT_NO_CONTEXT = "client_no_context_takeover"
      PMC_REQUEST = "#{PMC_EXTENSION}; #{PMC_SERVER_NO_CONTEXT}; #{PMC_CLIENT_NO_CONTEXT}"

      # The end of a sync flushed deflate stream, which a compressed message
      # leaves out and inflating it puts back.
      DEFLATE_TAIL = "\x00\x00\xff\xff".b

      # Bound on the HTTP response to the upgrade request.
      MAX_HANDSHAKE_RESPONSE_SIZE = 64 * 1024

      attr_accessor :socket

      # @param options [Hash] Those of Socket, and :compression to ask the
      #   server to compress messages, and :headers, a Hash of HTTP headers,
      #   or :headers_handler, a Proc that returns them, to send with the
      #   upgrade request.
      def initialize(options = {})
        super
        @compression = options[:compression]
        @headers = options[:headers]
        @headers_handler = options[:headers_handler]
        @compressed = false
        @handshaked = false
        @rbuf = "".b
        @write_lock = Mutex.new
      end

      # Whether messages are compressed in both directions: compression was
      # asked for and the server agreed to it.
      def compressed?
        @compressed
      end

      def connect
        super

        setup_tls! if @uri.scheme == "wss" # WebSocket connection must be made over TLS from the beginning

        handshake
      end

      def setup_tls!
        return if @socket.is_a? OpenSSL::SSL::SSLSocket

        super
      end

      def read(max_bytes = MAX_SOCKET_READ_BYTES, deadline = nil)
        # Hand over what read_line decoded beyond its last line first,
        # otherwise those bytes are lost once the read loop takes over.
        if @line_buf && !@line_buf.empty?
          return @line_buf.slice!(0, @line_buf.bytesize)
        end

        read_frames(max_bytes, deadline)
      end

      def read_line(deadline = nil)
        @line_buf ||= "".b
        loop do
          if (idx = @line_buf =~ /\r?\n/)
            return @line_buf.slice!(0, idx + Regexp.last_match(0).length)
          end

          # Pull more data from the wire; never from @line_buf itself,
          # or a partial line would be fed back forever.
          data = read_frames(MAX_SOCKET_READ_BYTES, deadline)
          return nil unless data
          @line_buf << data
        end
      end

      def write(data, deadline = nil)
        raise HandshakeError, "Attempted to write to socket while WebSocket handshake is in progress" unless @handshaked

        write_frame(BINARY_FRAME, data, deadline, compress: @compressed)
      end

      private

      def raw_read(max_bytes, deadline)
        Socket.instance_method(:read).bind_call(self, max_bytes, deadline)
      end

      def raw_write(data, deadline = nil)
        Socket.instance_method(:write).bind_call(self, data, deadline)
      end

      # Upgrades the connection like nats.go: sends the HTTP request and
      # checks the response, and agrees on compression when asked to.
      def handshake
        key = [SecureRandom.random_bytes(16)].pack("m0")
        request = [
          "GET #{request_path} HTTP/1.1",
          "Host: #{@uri.host}:#{@uri.port}",
          "Upgrade: websocket",
          "Connection: Upgrade",
          "Sec-WebSocket-Key: #{key}",
          "Sec-WebSocket-Version: 13"
        ]
        request << "Sec-WebSocket-Extensions: #{PMC_REQUEST}" if @compression
        request.concat(header_lines)
        raw_write("#{request.join("\r\n")}\r\n\r\n", @connect_timeout)

        status, headers = read_handshake_response
        accept = [Digest::SHA1.digest(key + GUID)].pack("m0")
        unless status == 101 &&
            headers["upgrade"]&.first&.casecmp?("websocket") &&
            headers["connection"]&.first&.casecmp?("upgrade") &&
            headers["sec-websocket-accept"]&.first == accept
          raise HandshakeError, "nats: invalid websocket connection"
        end

        if @compression
          # Without compression on the server, go on uncompressed.
          offered, no_context_takeover = pmc_support(headers["sec-websocket-extensions"])
          raise HandshakeError, "nats: websocket compression negotiation error" if offered && !no_context_takeover

          @compressed = offered
        end

        @handshaked = true
      end

      # The lines of the headers of the user: those that the handler returns
      # for this connect, or else the static ones, like nats.go. A name with
      # an Array of values goes out once for each of them.
      def header_lines
        headers = @headers_handler ? @headers_handler.call : @headers
        return [] unless headers

        raise HandshakeError, "nats: websocket connection headers must be a Hash" unless headers.respond_to?(:each_pair)

        headers.each_pair.flat_map do |name, values|
          Array(values).map do |value|
            # Nothing that would end the header line, or the request.
            if name.to_s.empty? || name.to_s.match?(/[:\s]/) || value.to_s.match?(/[\r\n]/)
              raise HandshakeError, "nats: invalid websocket connection header #{name.to_s.inspect}"
            end

            "#{name}: #{value}"
          end
        end
      end

      def request_path
        path = @uri.path.to_s
        path = "/" if path.empty?
        path += "?#{@uri.query}" if @uri.query
        path
      end

      # Returns the status and the headers, by lowercase name, of the
      # response, leaving in the read buffer what follows it.
      def read_handshake_response
        until (idx = @rbuf.index("\r\n\r\n"))
          raise HandshakeError, "nats: websocket handshake response too large" if @rbuf.bytesize > MAX_HANDSHAKE_RESPONSE_SIZE

          data = raw_read(MAX_SOCKET_READ_BYTES, @connect_timeout)
          @rbuf << data if data
        end

        lines = @rbuf.byteslice(0, idx).split("\r\n")
        @rbuf = @rbuf.byteslice(idx + 4, @rbuf.bytesize)

        status = lines.shift.to_s[%r{\AHTTP/1\.1 (\d{3})}, 1].to_i
        headers = {}
        lines.each do |line|
          name, value = line.split(":", 2)
          (headers[name.strip.downcase] ||= []) << value.strip if value
        end
        [status, headers]
      end

      # Whether the server offers permessage-deflate, and whether it does
      # so without context takeover both ways, like nats.go.
      def pmc_support(values)
        Array(values).each do |list|
          list.split(",").each do |extension|
            params = extension.split(";").map(&:strip)
            next unless params.first.casecmp?(PMC_EXTENSION)

            no_context = [PMC_SERVER_NO_CONTEXT, PMC_CLIENT_NO_CONTEXT].all? do |param|
              params.any? { |p| p.casecmp?(param) }
            end
            return [true, no_context]
          end
        end
        [false, false]
      end

      # Reads from the socket and returns the payloads of all complete
      # messages decoded so far.
      def read_frames(max_bytes, deadline)
        data = decode_frames
        if data.empty? && !@close_received
          chunk = raw_read(max_bytes, deadline)
          return nil unless chunk

          @rbuf << chunk
          data = decode_frames
        end
        # The server closed the connection, once what came before is read.
        raise Errno::ECONNRESET if data.empty? && @close_received

        data
      end

      # Decodes the complete frames in the read buffer, answering pings,
      # and returns the data of the messages that they complete.
      def decode_frames
        out = "".b
        off = 0
        loop do
          avail = @rbuf.bytesize - off
          break if avail < 2

          b0 = @rbuf.getbyte(off)
          b1 = @rbuf.getbyte(off + 1)
          len = b1 & 0x7F
          pos = 2
          if len == 126
            break if avail < 4
            len = @rbuf.byteslice(off + 2, 2).unpack1("n")
            pos = 4
          elsif len == 127
            break if avail < 10
            len = @rbuf.byteslice(off + 2, 8).unpack1("Q>")
            pos = 10
          end
          key = nil
          if b1 & MASK_BIT != 0
            break if avail < pos + 4
            key = @rbuf.byteslice(off + pos, 4)
            pos += 4
          end
          break if avail < pos + len

          payload = @rbuf.byteslice(off + pos, len)
          payload = mask(payload, key) if key
          off += pos + len

          handle_frame(b0, payload, out)
        end
        @rbuf = @rbuf.byteslice(off, @rbuf.bytesize) if off > 0
        out
      end

      def handle_frame(b0, payload, out)
        opcode = b0 & 0x0F
        final = b0 & FINAL_BIT != 0
        compressed = b0 & RSV1_BIT != 0

        case opcode
        when CLOSE_FRAME, PING_FRAME, PONG_FRAME
          raise FrameError, "nats: websocket control frame should not be compressed" if compressed
          raise FrameError, "nats: websocket control frame does not have final bit set" unless final
          raise FrameError, "nats: websocket control frame too long" if payload.bytesize > MAX_CONTROL_PAYLOAD_SIZE

          case opcode
          when CLOSE_FRAME then @close_received = true
          when PING_FRAME then write_frame(PONG_FRAME, payload)
          end
        when TEXT_FRAME, BINARY_FRAME
          raise FrameError, "nats: websocket message started before the final frame of the previous one" if @fragmented
          raise FrameError, "nats: compressed websocket frame without compression" if compressed && !@compressed

          @fragmented = !final
          @message_compressed = compressed
          take_payload(payload, final, out)
        when CONTINUATION_FRAME
          raise FrameError, "nats: invalid websocket continuation frame" if !@fragmented || compressed

          @fragmented = !final
          take_payload(payload, final, out)
        else
          raise FrameError, "nats: unknown websocket opcode #{opcode}"
        end
      end

      # Uncompressed data goes out as it comes, while a compressed message
      # can only be inflated once its last frame is in.
      def take_payload(payload, final, out)
        unless @message_compressed
          out << payload
          return
        end

        (@cbuf ||= "".b) << payload
        return unless final

        out << inflate(@cbuf)
        @cbuf = nil
      end

      def inflate(data)
        @inflater ||= Zlib::Inflate.new(-Zlib::MAX_WBITS)
        @inflater.inflate(data + DEFLATE_TAIL)
      ensure
        # No context takeover: each message is inflated on its own.
        @inflater&.reset
      end

      def deflate(data)
        @deflater ||= Zlib::Deflate.new(Zlib::BEST_SPEED, -Zlib::MAX_WBITS)
        out = @deflater.deflate(data, Zlib::SYNC_FLUSH)
        out.end_with?(DEFLATE_TAIL) ? out.byteslice(0, out.bytesize - DEFLATE_TAIL.bytesize) : out
      ensure
        @deflater&.reset
      end

      # Writes a single, masked, frame, compressing its payload if asked to.
      def write_frame(opcode, payload, deadline = nil, compress: false)
        @write_lock.synchronize do
          payload = deflate(payload) if compress
          b0 = FINAL_BIT | opcode
          b0 |= RSV1_BIT if compress
          len = payload.bytesize
          frame = if len <= 125
            [b0, MASK_BIT | len].pack("CC")
          elsif len < 65536
            [b0, MASK_BIT | 126, len].pack("CCn")
          else
            [b0, MASK_BIT | 127, len].pack("CCQ>")
          end
          key = SecureRandom.random_bytes(4)
          frame << key << mask(payload, key)
          raw_write(frame, deadline)
        end
      end

      # Masks (or unmasks) data with a 4 byte key, from https://tools.ietf.org/html/rfc6455#section-5.3
      def mask(data, key)
        size = data.bytesize
        k = key.unpack1("N")
        words = (data.b + ("\0" * ((-size) % 4))).unpack("N*")
        words.map! { |w| w ^ k }
        words.pack("N*").byteslice(0, size)
      end
    end
  end
end
