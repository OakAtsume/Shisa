require "socket"
require "./session"

class SecureClient
  enum ProtocolError
    Replay        = 0
    DecryptFailed = 1
    BadLength     = 2
    AuthFailed    = 3
    Generic       = 4
  end

  getter id : String

  def initialize(@host : String, @port : Int32,
                 @identity : Crypto::Ed25519::KeyPair,
                 @trusted_server_keys : Array(Bytes))
    @socket = nil.as(TCPSocket?)
    @id = Random::Secure.hex(8)
    @write_mutex = Mutex.new
    @running = false
    @session = Diffie::Session.new(Diffie::Role::Client)

    @on_connect = [] of String ->
    @on_message = [] of (String, String) ->
    @on_disconnect = [] of String ->
    @on_protocol_error = [] of (String, ProtocolError, String) ->
  end

  def on_connect(&block : String ->)
    @on_connect << block
  end

  def on_message(&block : String, String ->)
    @on_message << block
  end

  def on_disconnect(&block : String ->)
    @on_disconnect << block
  end

  def on_protocol_error(&block : String, ProtocolError, String ->)
    @on_protocol_error << block
  end

  def connect
    socket = TCPSocket.new(@host, @port)
    @socket = socket

    # X25519 key exchange: swap 32-byte public keys
    socket.write(@session.local_public_key)
    socket.flush
    peer = Bytes.new(Diffie::PUBKEY_BYTES)
    socket.read_fully(peer)
    @session.complete_handshake(peer)

    # Mutual auth: receive server challenge, verify, then respond
    challenge_record = read_one_record(socket)
    challenge = @session.decrypt(challenge_record)
    @session.verify_auth(challenge, @trusted_server_keys)

    response = @session.create_auth(@identity)
    socket.write(Diffie::Framing.frame(@session.encrypt(response)))
    socket.flush

    @running = true
    @on_connect.each &.call(@id)
    spawn read_loop(socket)
  end

  def send(text : String)
    send(text.to_slice)
  end

  def send(data : Bytes)
    socket = @socket
    raise "not connected" if socket.nil? || !@running

    @write_mutex.synchronize do
      socket.write(Diffie::Framing.frame(@session.encrypt(data)))
      socket.flush
    end
  end

  def disconnect
    return unless @running
    @running = false
    @socket.try &.close rescue nil
    @on_disconnect.each &.call(@id)
  end

  private def read_one_record(socket : TCPSocket) : Bytes
    header = Bytes.new(Diffie::Framing::HEADER_SIZE)
    socket.read_fully(header)
    length = IO::ByteFormat::BigEndian.decode(UInt32, header)
    raise Diffie::Error.new("frame length out of range") if length == 0 || length > Diffie::Framing::MAX_FRAME
    record = Bytes.new(length)
    socket.read_fully(record)
    record
  end

  private def read_loop(socket : TCPSocket)
    buf = Bytes.new(4096)
    parser = Diffie::FrameParser.new

    loop do
      n = socket.read(buf)
      break if n == 0
      break unless dispatch(parser, buf[0, n])
    end
  rescue ex : IO::Error
  ensure
    disconnect
  end

  private def dispatch(parser : Diffie::FrameParser, chunk : Bytes) : Bool
    parser.feed(chunk) do |record|
      begin
        plaintext = @session.decrypt(record)
        @on_message.each &.call(@id, String.new(plaintext))
      rescue ex : Diffie::ReplayError
        emit_error(ProtocolError::Replay, ex.message || "replay")
        return false
      rescue ex : Diffie::DecryptError
        emit_error(ProtocolError::DecryptFailed, ex.message || "decrypt failed")
        return false
      end
    end
    true
  rescue ex : Diffie::Error
    emit_error(ProtocolError::BadLength, ex.message || "bad frame")
    false
  end

  private def emit_error(err : ProtocolError, message : String)
    @on_protocol_error.each &.call(@id, err, message)
  end
end
