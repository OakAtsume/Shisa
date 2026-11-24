require "socket"

# Thin, thread-safe TCP transport used by the Diffie client. It owns exactly one
# connection and a small state machine; all framing/crypto lives a layer up in
# `Diffie::Session`. The manager only moves bytes and reports why it can't.
#
#   sock = SocketManager.new("127.0.0.1", 8081)
#   sock.connect
#   key = Bytes.new(Diffie::PUBKEY_BYTES)
#   sock.receive_fully(key)        # exact read: no short-read on the handshake
#   sock.send_bytes(my_public_key)
#   ...
#   sock.close
module Transport
  class Error < Exception
    getter id : String

    def initialize(@id : String, message : String)
      super(message)
    end
  end

  class ManagerClosed < Error
    def initialize
      super("TR-001", "Transport manager is closed")
    end
  end

  class NotConnected < Error
    def initialize
      super("TR-002", "Transport is not connected")
    end
  end

  class ConnectionFailed < Error
    def initialize(message : String)
      super("TR-003", message)
    end
  end

  class ConnectionLost < Error
    def initialize(message : String = "Transport connection lost")
      super("TR-004", message)
    end
  end
end

class SocketManager
  enum State
    Disconnected
    Connecting
    Connected
    Closed
  end

  @socket : TCPSocket?
  # @mutex guards @state and @socket. @write_mutex serializes concurrent writes
  # so two fibers can't interleave halves of a frame. I/O happens OUTSIDE
  # @mutex: we grab the socket reference under the lock, then read/write without
  # holding it, so a blocking read never stalls a send.
  @mutex = Mutex.new
  @write_mutex = Mutex.new

  def initialize(
    @host : String,
    @port : Int32,
    @connect_timeout : Time::Span? = 10.seconds,
    @read_timeout : Time::Span? = nil,
    @write_timeout : Time::Span? = nil,
  )
    @state = State::Disconnected
  end

  def state : State
    @mutex.synchronize { @state }
  end

  def connected? : Bool
    state == State::Connected
  end

  # Peer address as "ip:port", or nil if not connected.
  def remote_address : String?
    sock = @mutex.synchronize { @socket }
    return nil unless sock
    addr = sock.remote_address
    "#{addr.address}:#{addr.port}"
  rescue
    nil
  end

  # Establish the TCP connection. Idempotent while connected; raises
  # Transport::ManagerClosed if the manager was closed, Transport::ConnectionFailed
  # if the connect/handshake setup fails.
  def connect : Nil
    @mutex.synchronize do
      raise Transport::ManagerClosed.new if @state == State::Closed
      return if @state == State::Connected
      @state = State::Connecting
    end

    socket =
      begin
        TCPSocket.new(@host, @port, connect_timeout: @connect_timeout)
      rescue ex
        @mutex.synchronize { @state = State::Disconnected unless @state == State::Closed }
        raise Transport::ConnectionFailed.new("#{@host}:#{@port}: #{ex.message}")
      end

    configure(socket)

    @mutex.synchronize do
      if @state == State::Closed
        socket.close
        raise Transport::ManagerClosed.new
      end
      @socket = socket
      @state = State::Connected
    end
  end

  # Write all of `data` and flush. Raises Transport::NotConnected if down,
  # Transport::ConnectionLost (after disconnecting) if the write fails.
  def send_bytes(data : Bytes) : Nil
    socket = active_socket
    @write_mutex.synchronize do
      socket.write(data)
      socket.flush
    end
  rescue ex : Transport::Error
    raise ex
  rescue ex : IO::Error
    disconnect
    raise Transport::ConnectionLost.new("send failed: #{ex.message}")
  end

  # Read whatever is available into `buffer`. Returns the byte count, or nil on
  # a clean EOF (peer closed). Raises Transport::ConnectionLost on error.
  def receive_bytes(buffer : Bytes) : Int32?
    socket = active_socket
    count = socket.read(buffer)
    count == 0 ? nil : count
  rescue ex : Transport::Error
    raise ex
  rescue ex : IO::Error
    disconnect
    raise Transport::ConnectionLost.new("receive failed: #{ex.message}")
  end

  # Fill `buffer` completely before returning. Use this for fixed-size reads such
  # as the 256-byte Diffie public key, where a short read corrupts the handshake.
  # Raises Transport::ConnectionLost if the peer closes before the buffer is full.
  def receive_fully(buffer : Bytes) : Nil
    socket = active_socket
    socket.read_fully(buffer)
  rescue ex : Transport::Error
    raise ex
  rescue ex : IO::EOFError
    disconnect
    raise Transport::ConnectionLost.new("peer closed mid-read (wanted #{buffer.size} bytes)")
  rescue ex : IO::Error
    disconnect
    raise Transport::ConnectionLost.new("receive_fully failed: #{ex.message}")
  end

  # Drop the current connection but allow reconnecting later.
  def disconnect : Nil
    socket = @mutex.synchronize do
      old = @socket
      @socket = nil
      @state = State::Disconnected unless @state == State::Closed
      old
    end
    socket.try &.close
  end

  # Permanently close the manager. After this, connect raises ManagerClosed.
  def close : Nil
    socket = @mutex.synchronize do
      old = @socket
      @socket = nil
      @state = State::Closed
      old
    end
    socket.try &.close
  end

  # Grab the live socket under the lock, raising if we aren't connected.
  private def active_socket : TCPSocket
    @mutex.synchronize do
      raise Transport::ManagerClosed.new if @state == State::Closed
      socket = @socket
      raise Transport::NotConnected.new unless @state == State::Connected && socket
      socket
    end
  end

  # Low-latency defaults: disable Nagle (interactive request/response), enable
  # keepalive to notice dead peers, and apply optional I/O timeouts.
  private def configure(socket : TCPSocket) : Nil
    socket.tcp_nodelay = true
    socket.keepalive = true
    socket.read_timeout = @read_timeout if @read_timeout
    socket.write_timeout = @write_timeout if @write_timeout
  end
end
