#!/usr/bin/env ruby
# frozen_string_literal: true

# Generate Ed25519 keypairs for server and client identity.
# Keys are stored as raw 32-byte hex strings for easy embedding.
#
# Usage:
#   ruby keys/generate.rb          # generates server + client keypairs
#   ruby keys/generate.rb server   # generates server keypair only
#   ruby keys/generate.rb client   # generates client keypair only

require "openssl"
require "fileutils"

def generate(name)
  dir = File.dirname(__FILE__)
  key = OpenSSL::PKey.generate_key("ED25519")

  priv_hex = key.raw_private_key.unpack1("H*")
  pub_hex  = key.raw_public_key.unpack1("H*")

  priv_path = File.join(dir, "#{name}.key")
  pub_path  = File.join(dir, "#{name}.pub")

  File.write(priv_path, priv_hex)
  File.chmod(0o600, priv_path)
  File.write(pub_path, pub_hex)

  puts "Generated #{name} keypair:"
  puts "  Private: #{priv_path}"
  puts "  Public:  #{pub_path}"
  puts "  Pubkey:  #{pub_hex}"

  if name == "client"
    client_dir = File.join(dir, "authorized_clients")
    FileUtils.mkdir_p(client_dir)
    File.write(File.join(client_dir, "#{pub_hex[0, 16]}.pub"), pub_hex)
    puts "  Added to authorized_clients/"
  end

  { private: priv_hex, public: pub_hex }
end

if ARGV.empty?
  puts "Generating server + client keypairs...\n\n"
  server = generate("server")
  puts
  client = generate("client")
  puts <<~SNIPPET

    ── Paste into client.cr before building ──────────────────────────

    TRUSTED_SERVER_KEYS = [
      "#{server[:public]}",
    ].map { |hex| hex.hexbytes }

    CLIENT_PRIVATE_KEY = "#{client[:private]}"

    ───────────────────────────────────────────────────────────────────
  SNIPPET
else
  ARGV.each do |name|
    result = generate(name)
    puts
    case name
    when "server"
      puts "  For client.cr TRUSTED_SERVER_KEYS:"
      puts "    \"#{result[:public]}\""
    when "client"
      puts "  For client.cr CLIENT_PRIVATE_KEY:"
      puts "    \"#{result[:private]}\""
    end
    puts
  end
end
