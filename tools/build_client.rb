#!/usr/bin/env ruby
# frozen_string_literal: true

# Build a new GLOB-VM client binary with a unique compiled-in identity.
#
# Usage:
#   ruby tools/build_client.rb --host 10.0.0.1 --port 32435 --server-key <hex>
#   ruby tools/build_client.rb --host 10.0.0.1:32435 --host 10.0.0.1:443 --server-key <hex>
#   ruby tools/build_client.rb --host 10.0.0.1 --port 32435 --server-key <hex> \
#     --static --upx --output client-prod --register
#
# Options:
#   --host HOST[:PORT]      Control server address (repeatable for failover)
#   --port PORT             Default port when --host has no :PORT (default: 32435)
#   --server-key HEX        Server's Ed25519 public key (from keys/server.pub)
#   --output NAME           Output binary name (default: glob-client)
#   --static                Static build (uses Docker alpine if available)
#   --upx                   Compress binary with UPX after build
#   --register              Auto-register client pubkey in keys/authorized_clients/
#   --respect-tries BOOL    Per-host retry before failover (default: true)
#   --docker-image IMAGE    Docker image for static build (default: crystallang/crystal:latest-alpine)
#   --dry-run               Show what would be done without building
#   --help                  Show this help

require "openssl"
require "fileutils"
require "optparse"
require "tempfile"

PROJECT_ROOT = File.expand_path("..", __dir__)
CLIENT_SRC   = File.join(PROJECT_ROOT, "client.cr")
KEYS_DIR     = File.join(PROJECT_ROOT, "keys")

opts = {
  servers:       [],
  default_port:  32435,
  server_key:    nil,
  output:        "glob-client",
  static:        false,
  upx:           false,
  register:      false,
  respect_tries: true,
  docker_image:  "crystallang/crystal:latest-alpine",
  dry_run:       false,
}

OptionParser.new do |o|
  o.banner = "Usage: ruby tools/build_client.rb [options]"

  o.on("--host HOST", "Control server host[:port] (repeatable)") do |h|
    if h.match(/\A(.+):(\d+)\z/)
      opts[:servers] << { host: $1, port: $2.to_i }
    else
      opts[:servers] << { host: h, port: nil }
    end
  end

  o.on("--port PORT", Integer, "Default port (default: 32435)") { |p| opts[:default_port] = p }
  o.on("--server-key HEX", "Server Ed25519 public key hex") { |k| opts[:server_key] = k.strip }
  o.on("--output NAME", "Output binary name (default: glob-client)") { |n| opts[:output] = n }
  o.on("--static", "Static build") { opts[:static] = true }
  o.on("--upx", "Compress with UPX") { opts[:upx] = true }
  o.on("--register", "Register client key on this machine") { opts[:register] = true }
  o.on("--respect-tries BOOL", "Per-host retry (default: true)") { |v| opts[:respect_tries] = v.downcase != "false" }
  o.on("--docker-image IMAGE", "Docker image for static build") { |i| opts[:docker_image] = i }
  o.on("--dry-run", "Show plan without building") { opts[:dry_run] = true }
  o.on("-h", "--help", "Show help") { puts o; exit }
end.parse!

# ── Validate inputs ──────────────────────────────────────────────────────

if opts[:servers].empty?
  abort "Error: at least one --host is required"
end

opts[:servers].each { |s| s[:port] ||= opts[:default_port] }

server_key = opts[:server_key]
if server_key.nil? || server_key.empty?
  key_file = File.join(KEYS_DIR, "server.pub")
  if File.exist?(key_file)
    server_key = File.read(key_file).strip
    puts "[*] Using server key from #{key_file}"
  else
    abort "Error: --server-key required (or place server.pub in keys/)"
  end
end

unless server_key.match?(/\A[0-9a-fA-F]{64}\z/)
  abort "Error: server key must be 64 hex characters (32 bytes)"
end

# ── Generate client Ed25519 keypair ──────────────────────────────────────

puts "[*] Generating client Ed25519 keypair..."
client_key = OpenSSL::PKey.generate_key("ED25519")
client_priv_hex = client_key.raw_private_key.unpack1("H*")
client_pub_hex  = client_key.raw_public_key.unpack1("H*")
puts "    Public:  #{client_pub_hex}"
puts "    Fingerprint: #{client_pub_hex[0, 16]}..."

# ── Register if requested ────────────────────────────────────────────────

if opts[:register]
  auth_dir = File.join(KEYS_DIR, "authorized_clients")
  FileUtils.mkdir_p(auth_dir)
  pub_file = File.join(auth_dir, "#{client_pub_hex[0, 16]}.pub")
  File.write(pub_file, client_pub_hex)
  puts "[+] Registered in #{pub_file}"
  puts "    Run 'refresh' in the control shell to load without restart"
end

# ── Build server list Crystal code ───────────────────────────────────────

server_entries = opts[:servers].map { |s|
  "  {host: #{s[:host].inspect}, port: #{s[:port]}},"
}.join("\n")

servers_code = "SERVERS = [\n#{server_entries}\n] of NamedTuple(host: String, port: Int32)"
respect_code = "RESPECT_TRIES = #{opts[:respect_tries]}"

# ── Show plan ────────────────────────────────────────────────────────────

puts
puts "── Build plan ──────────────────────────────────────────────"
puts "  Servers:    #{opts[:servers].map { |s| "#{s[:host]}:#{s[:port]}" }.join(", ")}"
puts "  Server key: #{server_key[0, 16]}..."
puts "  Client key: #{client_pub_hex[0, 16]}..."
puts "  Respect:    #{opts[:respect_tries]}"
puts "  Static:     #{opts[:static]}"
puts "  UPX:        #{opts[:upx]}"
puts "  Output:     #{opts[:output]}"
puts "───────────────────────────────────────────────────────────"

if opts[:dry_run]
  puts "\n[dry-run] Would build with the above settings."
  puts "\nClient private key (save this if you need to rebuild):"
  puts "  #{client_priv_hex}"
  exit 0
end

# ── Prepare build directory ──────────────────────────────────────────────

build_dir = Dir.mktmpdir("glob-build-")
puts "\n[*] Preparing build in #{build_dir}..."

# Copy project source
%w[src client.cr shard.yml shard.lock].each do |entry|
  src = File.join(PROJECT_ROOT, entry)
  next unless File.exist?(src)
  if File.directory?(src)
    FileUtils.cp_r(src, File.join(build_dir, entry))
  else
    FileUtils.cp(src, File.join(build_dir, entry))
  end
end

# Patch client.cr with compiled-in values
client_src = File.read(File.join(build_dir, "client.cr"))

client_src.sub!(/TRUSTED_SERVER_KEYS = \[.*?\]\.map/m,
  "TRUSTED_SERVER_KEYS = [\n  \"#{server_key}\",\n].map")

client_src.sub!(/CLIENT_PRIVATE_KEY = ".*?"/,
  "CLIENT_PRIVATE_KEY = \"#{client_priv_hex}\"")

client_src.sub!(/SERVERS = \[.*?\] of NamedTuple\(host: String, port: Int32\)/m,
  servers_code)

client_src.sub!(/RESPECT_TRIES = (?:true|false)/, respect_code)

File.write(File.join(build_dir, "client.cr"), client_src)

# ── Build ────────────────────────────────────────────────────────────────

output_path = File.expand_path(opts[:output])

if opts[:static]
  puts "[*] Building static binary via Docker (#{opts[:docker_image]})..."
  docker_cmd = [
    "docker", "run", "--rm",
    "-v", "#{build_dir}:/app",
    "-w", "/app",
    opts[:docker_image],
    "crystal", "build", "client.cr",
    "-o", "/app/#{File.basename(opts[:output])}",
    "--release", "--static",
    "--no-debug",
  ]
  puts "    #{docker_cmd.join(' ')}"
  unless system(*docker_cmd)
    FileUtils.rm_rf(build_dir)
    abort "\n[!] Docker build failed"
  end
  built = File.join(build_dir, File.basename(opts[:output]))
else
  puts "[*] Building binary..."
  build_cmd = [
    "crystal", "build", File.join(build_dir, "client.cr"),
    "-o", output_path,
    "--release", "--no-debug",
  ]
  puts "    #{build_cmd.join(' ')}"
  unless system(*build_cmd)
    FileUtils.rm_rf(build_dir)
    abort "\n[!] Build failed"
  end
  built = output_path
end

# Copy out of build dir if static
if opts[:static] && File.exist?(File.join(build_dir, File.basename(opts[:output])))
  FileUtils.cp(File.join(build_dir, File.basename(opts[:output])), output_path)
end

size_before = File.size(output_path)
puts "[+] Built: #{output_path} (#{fmt_size(size_before)})"

# ── UPX compression ─────────────────────────────────────────────────────

if opts[:upx]
  if system("which upx > /dev/null 2>&1")
    puts "[*] Compressing with UPX..."
    system("upx", "--best", "--lzma", output_path)
    size_after = File.size(output_path)
    ratio = (size_after.to_f / size_before * 100).round(1)
    puts "[+] Compressed: #{fmt_size(size_after)} (#{ratio}% of original)"
  else
    puts "[!] UPX not found, skipping compression"
  end
end

# ── Cleanup ──────────────────────────────────────────────────────────────

FileUtils.rm_rf(build_dir)

puts
puts "── Done ────────────────────────────────────────────────────"
puts "  Binary:     #{output_path}"
puts "  Client pub: #{client_pub_hex}"
puts "  Servers:    #{opts[:servers].map { |s| "#{s[:host]}:#{s[:port]}" }.join(", ")}"
if opts[:register]
  puts "  Registered: yes (refresh server to activate)"
else
  puts "  Registered: no (use --register or copy pubkey manually)"
  puts "  To register later:"
  puts "    echo '#{client_pub_hex}' > keys/authorized_clients/#{client_pub_hex[0,16]}.pub"
end
puts "───────────────────────────────────────────────────────────"

BEGIN {
  def fmt_size(n)
    return "#{n} B" if n < 1024
    return "#{'%.1f' % (n / 1024.0)} KB" if n < 1024**2
    "#{'%.1f' % (n / 1024.0**2)} MB"
  end
}
