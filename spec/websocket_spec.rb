# frozen_string_literal: true

require "nats/io/websocket"

describe NATS::IO::WebSocket do
  subject(:ws) { described_class.new(uri: URI.parse("ws://127.0.0.1:8080")) }

  let(:sockets) { UNIXSocket.pair }
  let(:client_io) { sockets[0] }
  let(:server_io) { sockets[1] }

  before do
    ws.socket = client_io
  end

  after { sockets.each { |s| s.close unless s.closed? } }

  # A final, unmasked, binary frame, as a server sends it.
  def server_frame(data, opcode: 2, first: 0x80)
    data = data.b
    len = data.bytesize
    header = if len <= 125
      [first | opcode, len].pack("CC")
    elsif len < 65536
      [first | opcode, 126, len].pack("CCn")
    else
      [first | opcode, 127, len].pack("CCQ>")
    end
    header + data
  end

  # A regression here spins forever instead of failing, so bound it.
  def bounded(&block)
    Timeout.timeout(5, &block)
  end

  # Reads and unmasks a frame that the client sent.
  def client_frame
    b0, b1 = server_io.read(2).unpack("CC")
    len = b1 & 0x7F
    len = server_io.read(2).unpack1("n") if len == 126
    len = server_io.read(8).unpack1("Q>") if len == 127
    key = server_io.read(4).bytes
    data = server_io.read(len).bytes.each_with_index.map { |b, i| b ^ key[i % 4] }.pack("C*")
    [b0, data]
  end

  describe "#read" do
    it "joins the frames of a fragmented message" do
      server_io.write(server_frame("MSG foo ", first: 0) + server_frame("1 2\r\n", opcode: 0, first: 0) + server_frame("hi\r\n", opcode: 0))
      data = +""
      bounded { data << ws.read(NATS::IO::MAX_SOCKET_READ_BYTES, 1) until data.end_with?("hi\r\n") }
      expect(data).to eq("MSG foo 1 2\r\nhi\r\n")
    end

    it "answers a ping with a pong, leaving it out of the data" do
      server_io.write(server_frame("ok", opcode: 9) + server_frame("PING\r\n"))
      expect(bounded { ws.read(NATS::IO::MAX_SOCKET_READ_BYTES, 1) }).to eq("PING\r\n")
      expect(bounded { client_frame }).to eq([0x8A, "ok"])
    end

    it "fails once the server closes, after the data that came before" do
      server_io.write(server_frame("-ERR 'bye'\r\n") + server_frame([1001].pack("n"), opcode: 8))
      expect(bounded { ws.read(NATS::IO::MAX_SOCKET_READ_BYTES, 1) }).to eq("-ERR 'bye'\r\n")
      expect { bounded { ws.read(NATS::IO::MAX_SOCKET_READ_BYTES, 1) } }.to raise_error(Errno::ECONNRESET)
    end

    it "refuses compressed frames when compression was not agreed on" do
      server_io.write(server_frame("x", first: 0xC0))
      expect { bounded { ws.read(NATS::IO::MAX_SOCKET_READ_BYTES, 1) } }.to raise_error(NATS::IO::WebSocket::FrameError)
    end

    it "inflates compressed messages, also fragmented ones" do
      ws.instance_variable_set(:@compressed, true)
      deflate = lambda do |data|
        z = Zlib::Deflate.new(Zlib::BEST_SPEED, -Zlib::MAX_WBITS)
        z.deflate(data, Zlib::SYNC_FLUSH).delete_suffix("\x00\x00\xff\xff".b)
      end
      first = deflate.call("PING\r\n" * 100)
      second = deflate.call("PONG\r\n" * 100)
      server_io.write(server_frame(first, first: 0xC0) + server_frame(second[0, 3], first: 0x40) + server_frame(second[3..], opcode: 0))

      data = +""
      bounded { data << ws.read(NATS::IO::MAX_SOCKET_READ_BYTES, 1) until data.bytesize >= 1200 }
      expect(data).to eq(("PING\r\n" * 100) + ("PONG\r\n" * 100))
    end
  end

  describe "#write" do
    before { ws.instance_variable_set(:@handshaked, true) }

    it "sends masked binary frames" do
      ws.write("PUB foo 2\r\nhi\r\n")
      expect(bounded { client_frame }).to eq([0x82, "PUB foo 2\r\nhi\r\n"])

      # More than the socket buffers, so read it meanwhile.
      big = "x" * 300_000
      reader = Thread.new { client_frame }
      ws.write(big)
      expect(bounded { reader.value }).to eq([0x82, big])
    end

    it "compresses each message on its own once compression was agreed on" do
      ws.instance_variable_set(:@compressed, true)
      2.times do
        ws.write("PUB foo 2\r\nhi\r\n" * 50)
        b0, data = bounded { client_frame }
        expect(b0).to eq(0xC2)
        expect(Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(data + "\x00\x00\xff\xff".b)).to eq("PUB foo 2\r\nhi\r\n" * 50)
      end
    end
  end

  describe "#read_line" do
    it "returns a line split across frames" do
      server_io.write(server_frame("PI"))
      Thread.new do
        sleep 0.2
        server_io.write(server_frame("NG\r\n"))
      end

      expect(bounded { ws.read_line(2) }).to eq("PING\r\n")
    end

    it "returns a line whose start was left over by the previous read_line" do
      server_io.write(server_frame("PONG\r\nPI"))
      expect(bounded { ws.read_line(1) }).to eq("PONG\r\n")

      server_io.write(server_frame("NG\r\n"))
      expect(bounded { ws.read_line(1) }).to eq("PING\r\n")
    end
  end

  describe "#read after #read_line" do
    it "returns bytes decoded by read_line beyond the last consumed line" do
      server_io.write(server_frame("PONG\r\nPING\r\n"))

      expect(bounded { ws.read_line(1) }).to eq("PONG\r\n")

      server_io.write(server_frame("MSG foo 1 0\r\n\r\n"))

      # A short read returning only the buffered bytes is fine; nothing
      # may be dropped and order must be preserved.
      expect(bounded { ws.read(NATS::IO::MAX_SOCKET_READ_BYTES, 1) }).to eq("PING\r\n")
      expect(bounded { ws.read(NATS::IO::MAX_SOCKET_READ_BYTES, 1) }).to eq("MSG foo 1 0\r\n\r\n")
    end

    it "returns a partial line left over by read_line" do
      server_io.write(server_frame("PONG\r\nPI"))
      expect(bounded { ws.read_line(1) }).to eq("PONG\r\n")

      server_io.write(server_frame("NG\r\n"))
      expect(bounded { ws.read(NATS::IO::MAX_SOCKET_READ_BYTES, 1) }).to eq("PI")
      expect(bounded { ws.read(NATS::IO::MAX_SOCKET_READ_BYTES, 1) }).to eq("NG\r\n")
    end

    it "reads from the wire when read_line consumed the whole buffer" do
      server_io.write(server_frame("PONG\r\n"))

      expect(bounded { ws.read_line(1) }).to eq("PONG\r\n")

      server_io.write(server_frame("PING\r\n"))
      expect(bounded { ws.read(NATS::IO::MAX_SOCKET_READ_BYTES, 1) }).to eq("PING\r\n")
    end
  end
end
