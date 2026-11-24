require "socket"
require "./session"

# SecureClient is the TCP binding of the Diffie protocol. All of the crypto and
# framing lives in `Diffie::Session` / `Diffie::Framing` — this class is just the
# socket plumbing on top, which doubles as a worked example of driving the
# transport-agnostic API. To run the protocol over something other than TCP
# (SMS, HTTP, …) use `Diffie::Session` directly; see the README.
class SecureClient
  # Errors surfaced through `on_protocol_error` (mirrors the server's IDs).
  enum ProtocolError
    Replay        = 0 # inbound nonce did not increase
    DecryptFailed = 1 # Poly1305 tag mismatch / corrupt ciphertext
    BadLength     = 2 # framing length was zero or absurdly large
    Generic       = 3 # anything else
  end

  getter id : String

  def initialize(@host : String, @port : Int32)
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

  # ---- event registration ----------------------------------------------------

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

  # ---- connection lifecycle --------------------------------------------------

  # Connects, performs the DH handshake, and starts the background reader.
  def connect
    socket = TCPSocket.new(@host, @port)
    @socket = socket

    # Handshake: swap 256-byte public keys, then derive directional keys.
    socket.write(@session.local_public_key)
    socket.flush
    peer = Bytes.new(Diffie::PUBKEY_BYTES)
    socket.read_fully(peer)
    @session.complete_handshake(peer)

    @running = true
    @on_connect.each &.call(@id)
    spawn read_loop(socket)
  end

  # ---- sending ---------------------------------------------------------------

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

  # ---- receiving -------------------------------------------------------------

  private def read_loop(socket : TCPSocket)
    buf = Bytes.new(4096)
    parser = Diffie::FrameParser.new

    loop do
      n = socket.read(buf)
      break if n == 0 # clean EOF
      break unless dispatch(parser, buf[0, n])
    end
  rescue ex : IO::Error
    # socket closed underneath us; fall through to disconnect
  ensure
    disconnect
  end

  # Decrypts every complete record in the chunk. Returns false to stop reading.
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

  def disconnect
    return unless @running
    @running = false
    @socket.try &.close rescue nil
    @on_disconnect.each &.call(@id)
  end

  private def emit_error(err : ProtocolError, message : String)
    @on_protocol_error.each &.call(@id, err, message)
  end
end
