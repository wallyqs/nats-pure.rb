# frozen_string_literal: true

describe "Client - WebSocket proxy path" do
  let(:host) { "127.0.0.1" }
  let(:port) { 4794 }
  let(:ws_port) { 8794 }
  let(:proxy_port) { 8795 }

  before do
    config = <<~CONF
      net: "#{host}"
      port: #{port}
      websocket {
        port: #{ws_port}
        no_tls: true
      }
    CONF
    @natsctl = NatsServerControl.init_with_config_from_string(config, {
      "pid_file" => "/tmp/test-nats-ws-proxy-path.pid", "host" => host, "port" => port
    })
    @natsctl.start_server(true)
    # Stands for the HTTP proxy, which nats-server accepts any path from.
    @proxy = TCPProxy.new(proxy_port, ws_port).start
  end

  after do
    @proxy.stop
    @natsctl.kill_server
  end

  def request_line(url, **opts)
    nc = NATS.connect(url, reconnect: false, **opts)
    nc.subscribe("hello") { |msg| msg.respond("hi") }
    expect(nc.request("hello", "", timeout: 2).data).to eq("hi")
    nc.close
    up = @proxy.conns.last.up
    up[0, up.index("\r\n")]
  end

  # The cases of TestWSProxyPath of nats.go.
  it "requests the proxy path, with a leading slash" do
    url = "ws://#{host}:#{proxy_port}"
    expect(request_line(url, proxy_path: "/nats/ws")).to eq("GET /nats/ws HTTP/1.1")
    expect(request_line(url, proxy_path: "nats")).to eq("GET /nats HTTP/1.1")
    expect(request_line(url, proxy_path: "/a/b/c/")).to eq("GET /a/b/c/ HTTP/1.1")
  end

  it "requests the path of the URL without one" do
    expect(request_line("ws://#{host}:#{proxy_port}")).to eq("GET / HTTP/1.1")
    expect(request_line("ws://#{host}:#{proxy_port}/from/url")).to eq("GET /from/url HTTP/1.1")
  end

  it "takes the proxy path over that of the URL, keeping its query" do
    expect(request_line("ws://#{host}:#{proxy_port}/from/url", proxy_path: "/override")).to eq("GET /override HTTP/1.1")
    expect(request_line("ws://#{host}:#{proxy_port}/?token=abc", proxy_path: "/proxy")).to eq("GET /proxy?token=abc HTTP/1.1")
  end

  it "refuses a proxy path that is not a String" do
    expect do
      NATS.connect("ws://#{host}:#{proxy_port}", reconnect: false, proxy_path: 1)
    end.to raise_error(ArgumentError, /proxy_path must be a String/)
  end
end
