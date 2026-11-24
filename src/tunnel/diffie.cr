require "./client"

# Entry point: an interactive encrypted chat client for the Diffie server.
#
#   crystal run src/diffie.cr -- [host] [port]
#
# Type messages and press enter to send; type "exit" (or Ctrl-D) to quit.
module Diffie
  VERSION = "0.1.0"
end

host = ARGV[0]? || "127.0.0.1"
port = (ARGV[1]? || "8081").to_i

client = SecureClient.new(host, port)

client.on_connect do |id|
  puts "[+] Connected and handshake complete (#{id})"
  print "> "
end

client.on_message do |_id, message|
  print "\r\033[K"            # clear the current prompt line
  puts "[server] #{message}"
  print "> "
end

client.on_protocol_error do |_id, err, message|
  STDERR.puts "\n[protocol-error:#{err}] #{message}"
end

client.on_disconnect do |_id|
  puts "\n[-] Disconnected."
  exit 0
end

begin
  client.connect
rescue ex
  STDERR.puts "Could not connect to #{host}:#{port} — #{ex.message}"
  exit 1
end

# REPL on the main fiber; the reader runs in the background.
while line = gets
  line = line.chomp
  next if line.empty?
  break if line == "exit"
  client.send(line)
  print "> "
end

client.disconnect
