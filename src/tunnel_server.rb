# frozen_string_literal: true

# Server-side TCP tunnel manager.
# Implements SSH-style local forwarding (-L): the server listens on a local
# port and relays traffic through the encrypted Diffie channel to a target
# host:port reachable by the remote client.

require "socket"
require "securerandom"
require "base64"

class TunnelManager
  TunnelListener = Struct.new(
    :num, :client_id, :tcp_server, :local_port,
    :remote_host, :remote_port, :accept_thread,
    :connections, :active,
    keyword_init: true
  )

  TunnelConn = Struct.new(
    :conn_id, :listener_num, :socket, :client_id, :reader_thread,
    keyword_init: true
  )

  RemoteTunnel = Struct.new(
    :num, :client_id, :listener_id, :remote_port,
    :local_host, :local_port, :connections, :active,
    keyword_init: true
  )

  def initialize(server)
    @server    = server
    @listeners = {} # num => TunnelListener
    @rlisteners = {} # num => RemoteTunnel (-R)
    @conns     = {} # conn_id => TunnelConn
    @next_num  = 1
    @mutex     = Mutex.new
    @ready     = {} # conn_id => Queue (one-shot for tunnel_ready)
    register_handlers
  end

  # Open a local-forwarding tunnel (-L).
  # Listens on local_port and forwards connections to remote_host:remote_port
  # via the specified client.
  def forward_local(client_id, local_port, remote_host, remote_port)
    tcp = TCPServer.new("127.0.0.1", local_port)

    num = @mutex.synchronize do
      n = @next_num
      @next_num += 1
      n
    end

    listener = TunnelListener.new(
      num:         num,
      client_id:   client_id,
      tcp_server:  tcp,
      local_port:  local_port,
      remote_host: remote_host,
      remote_port: remote_port,
      connections: [],
      active:      true,
    )

    listener.accept_thread = Thread.new { accept_loop(listener) }
    @mutex.synchronize { @listeners[num] = listener }
    num
  rescue Errno::EADDRINUSE
    raise "port #{local_port} already in use"
  end

  def forward_remote(client_id, remote_port, local_host, local_port)
    listener_id = SecureRandom.hex(6)

    num = @mutex.synchronize do
      n = @next_num
      @next_num += 1
      n
    end

    rt = RemoteTunnel.new(
      num:         num,
      client_id:   client_id,
      listener_id: listener_id,
      remote_port: remote_port,
      local_host:  local_host,
      local_port:  local_port,
      connections: [],
      active:      true,
    )

    @mutex.synchronize do
      @rlisteners[num] = rt
      @ready[listener_id] = Queue.new
    end

    @server.send_envelope(client_id, Protocol::Envelope.new(
      event: "rtunnel_listen", id: listener_id,
      payload: { port: remote_port }
    ))

    ready_q = @mutex.synchronize { @ready[listener_id] }
    begin
      Timeout.timeout(15) do
        status = ready_q.pop
        unless status == :ready
          @mutex.synchronize { @rlisteners.delete(num) }
          raise "client rejected remote listen"
        end
      end
    rescue Timeout::Error
      @mutex.synchronize { @rlisteners.delete(num) }
      raise "client timed out starting remote listener"
    ensure
      @mutex.synchronize { @ready.delete(listener_id) }
    end

    num
  end

  def list
    @mutex.synchronize { @listeners.values.map(&:dup) }
  end

  def list_remote
    @mutex.synchronize { @rlisteners.values.map(&:dup) }
  end

  def connection_count(listener_num)
    @mutex.synchronize do
      l = @listeners[listener_num] || @rlisteners[listener_num]
      l ? l.connections.size : 0
    end
  end

  def close_listener(num)
    listener = @mutex.synchronize { @listeners.delete(num) }
    if listener
      listener.active = false
      listener.tcp_server.close rescue nil
      listener.connections.dup.each { |cid| close_conn(cid) }
      return true
    end

    rt = @mutex.synchronize { @rlisteners.delete(num) }
    if rt
      rt.active = false
      @server.send_envelope(rt.client_id, Protocol::Envelope.new(
        event: "rtunnel_stop", id: rt.listener_id
      )) rescue nil
      rt.connections.dup.each { |cid| close_conn(cid) }
      return true
    end

    false
  end

  def close_client_tunnels(client_id)
    nums = @mutex.synchronize do
      local  = @listeners.select  { |_, l| l.client_id == client_id }.keys
      remote = @rlisteners.select { |_, r| r.client_id == client_id }.keys
      local + remote
    end
    nums.each { |n| close_listener(n) }
  end

  # ── event handlers (called from dispatch thread) ────────────────────────

  def on_tunnel_ready(conn_id)
    @mutex.synchronize do
      @ready[conn_id]&.push(:ready)
    end
  end

  def on_tunnel_error(conn_id, payload)
    @mutex.synchronize do
      @ready[conn_id]&.push(:error)
    end
    close_conn(conn_id)
  end

  def on_tunnel_data(conn_id, payload)
    conn = @mutex.synchronize { @conns[conn_id] }
    return unless conn
    data = Base64.decode64(payload[:data].to_s)
    begin
      conn.socket.write(data)
    rescue
      close_conn(conn_id)
    end
  end

  def on_tunnel_close(conn_id)
    close_conn(conn_id)
  end

  private

  def register_handlers
    mgr = self
    %w[tunnel_ready tunnel_error tunnel_data tunnel_close].each do |evt|
      @server.on(evt) do |_client_id, _srv, env|
        next unless env.id
        case evt
        when "tunnel_ready" then mgr.on_tunnel_ready(env.id)
        when "tunnel_error" then mgr.on_tunnel_error(env.id, env.payload)
        when "tunnel_data"  then mgr.on_tunnel_data(env.id, env.payload)
        when "tunnel_close" then mgr.on_tunnel_close(env.id)
        end
      end
    end

    @server.on("rtunnel_ready") do |_client_id, _srv, env|
      mgr.on_tunnel_ready(env.id) if env.id
    end

    @server.on("rtunnel_error") do |_client_id, _srv, env|
      mgr.on_tunnel_error(env.id, env.payload) if env.id
    end

    @server.on("rtunnel_accept") do |client_id, _srv, env|
      next unless env.id && env.payload
      Thread.new { mgr.handle_rtunnel_accept(client_id, env.id, env.payload) }
    end
  end

  def accept_loop(listener)
    while listener.active
      begin
        socket = listener.tcp_server.accept
      rescue IOError, Errno::EBADF
        break
      end
      Thread.new { handle_connection(listener, socket) }
    end
  end

  def handle_connection(listener, local_socket)
    conn_id = SecureRandom.hex(6)
    conn = TunnelConn.new(
      conn_id:      conn_id,
      listener_num: listener.num,
      socket:       local_socket,
      client_id:    listener.client_id,
    )

    @mutex.synchronize do
      @conns[conn_id] = conn
      listener.connections << conn_id
      @ready[conn_id] = Queue.new
    end

    # Ask client to connect to the remote target.
    @server.send_envelope(listener.client_id, Protocol::Envelope.new(
      event: "tunnel_open", id: conn_id,
      payload: { host: listener.remote_host, port: listener.remote_port }
    ))

    # Wait for client to report ready.
    ready_q = @mutex.synchronize { @ready[conn_id] }
    begin
      Timeout.timeout(15) do
        status = ready_q.pop
        unless status == :ready
          close_conn(conn_id)
          return
        end
      end
    rescue Timeout::Error
      close_conn(conn_id)
      return
    ensure
      @mutex.synchronize { @ready.delete(conn_id) }
    end

    # Relay: local socket -> encrypted channel.
    begin
      buf = String.new(capacity: 4096)
      loop do
        chunk = local_socket.recv(4096)
        break if chunk.nil? || chunk.empty?
        b64 = Base64.strict_encode64(chunk)
        @server.send_envelope(listener.client_id, Protocol::Envelope.new(
          event: "tunnel_data", id: conn_id, payload: { data: b64 }
        ))
      end
    rescue IOError, Errno::EBADF, Errno::ECONNRESET
      # socket closed
    ensure
      @server.send_envelope(listener.client_id, Protocol::Envelope.new(
        event: "tunnel_close", id: conn_id
      )) rescue nil
      close_conn(conn_id)
    end
  end

  def handle_rtunnel_accept(client_id, conn_id, payload)
    listener_id = payload[:listener] || payload["listener"]
    return unless listener_id

    rt = @mutex.synchronize do
      @rlisteners.values.find { |r| r.listener_id == listener_id.to_s }
    end
    return unless rt && rt.active

    begin
      local_socket = TCPSocket.new(rt.local_host, rt.local_port)
      local_socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
    rescue => e
      @server.send_envelope(client_id, Protocol::Envelope.new(
        event: "tunnel_close", id: conn_id
      )) rescue nil
      return
    end

    conn = TunnelConn.new(
      conn_id:      conn_id,
      listener_num: rt.num,
      socket:       local_socket,
      client_id:    client_id,
    )

    @mutex.synchronize do
      @conns[conn_id] = conn
      rt.connections << conn_id
    end

    begin
      loop do
        chunk = local_socket.recv(4096)
        break if chunk.nil? || chunk.empty?
        b64 = Base64.strict_encode64(chunk)
        @server.send_envelope(client_id, Protocol::Envelope.new(
          event: "tunnel_data", id: conn_id, payload: { data: b64 }
        ))
      end
    rescue IOError, Errno::EBADF, Errno::ECONNRESET
    ensure
      @server.send_envelope(client_id, Protocol::Envelope.new(
        event: "tunnel_close", id: conn_id
      )) rescue nil
      close_conn(conn_id)
    end
  end

  def close_conn(conn_id)
    conn = @mutex.synchronize { @conns.delete(conn_id) }
    return unless conn
    conn.socket.close rescue nil
    @mutex.synchronize do
      @listeners[conn.listener_num]&.connections&.delete(conn_id)
      @rlisteners[conn.listener_num]&.connections&.delete(conn_id)
    end
  end
end
