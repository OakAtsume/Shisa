@[Link("c")]
lib ProcessInfoC
  fun getpid : Int32
  fun getppid : Int32
  fun getpgrp : Int32
  fun getpgid(pid : Int32) : Int32
  fun getsid(pid : Int32) : Int32
  fun isatty(fd : Int32) : Int32
end

require "digest"
require "socket"

module Sysinfo
  extend self

  private def read_or_unknown(path : String) : String
    value = File.read(path).strip
    value.empty? ? "unknown" : value
  rescue
    "unknown"
  end

  private def hostname : String
    read_or_unknown("/proc/sys/kernel/hostname")
  end

  private def machine_id : String
    # Linux machine ID; may be absent in containers or minimal systems.
    id = read_or_unknown("/etc/machine-id")
    return id unless id == "unknown"

    read_or_unknown("/var/lib/dbus/machine-id")
  end

  private def os_info : Hash(String, String)
    result = {
      "os_name"    => "unknown",
      "os_version" => "unknown",
    }

    begin
      File.each_line("/etc/os-release") do |line|
        key, value = line.split("=", 2)
        next unless value

        value = value.strip.gsub(/\A["']|["']\z/, "")

        case key
        when "NAME"
          result["os_name"] = value
        when "VERSION_ID"
          result["os_version"] = value
        end
      end
    rescue
      # Keep unknown defaults.
    end

    result
  end

  private def kernel_release : String
    read_or_unknown("/proc/sys/kernel/osrelease")
  end

  private def architecture : String
    output = IO::Memory.new

    status = Process.run(
      "uname",
      ["-m"],
      output: output,
      error: Process::Redirect::Close
    )

    status.success? ? output.to_s.strip : "unknown"
  rescue
    "unknown"
  end

  private def hardware_info : Hash(String, String)
    {
      "system_vendor" => read_or_unknown(
        "/sys/class/dmi/id/sys_vendor"
      ),
      "product_name" => read_or_unknown(
        "/sys/class/dmi/id/product_name"
      ),
      "product_uuid" => read_or_unknown(
        "/sys/class/dmi/id/product_uuid"
      ),
      "board_name" => read_or_unknown(
        "/sys/class/dmi/id/board_name"
      ),
    }
  end

  private def local_addresses : String
    output = IO::Memory.new

    status = Process.run(
      "ip",
      ["-o", "-4", "addr", "show", "up"],
      output: output,
      error: Process::Redirect::Close
    )

    return "unknown" unless status.success?

    addresses = [] of String

    output.to_s.each_line do |line|
      fields = line.split
      next unless fields.size >= 4
      next unless fields[2] == "inet"

      interface = fields[1].split("@", 2)[0]
      address = fields[3].split("/", 2)[0]

      # Ignore loopback addresses.
      next if address.starts_with?("127.")

      addresses << "#{interface}=#{address}"
    end

    addresses.empty? ? "unknown" : addresses.uniq.join(", ")
  rescue
    "unknown"
  end

  private def hwid : String
    hw = hardware_info

    # Prefer a hardware-backed identifier when available.
    # Machine ID is a fallback for VMs/hosts without DMI data.
    uuid = hw["product_uuid"]
    mid = machine_id

    identity = if uuid != "unknown" &&
                  uuid != "00000000-0000-0000-0000-000000000000"
                 "dmi:#{uuid}"
               elsif mid != "unknown"
                 "machine:#{mid}"
               else
                 # Last-resort fingerprint; may change if these attributes change.
                 [
                   hostname,
                   hw["system_vendor"],
                   hw["product_name"],
                   hw["board_name"],
                   architecture,
                 ].join("|")
               end

    Digest::SHA256.hexdigest(identity)
  end

  private def proc_read(path : String) : String
    File.read(path).strip
  rescue
    "unknown"
  end

  private def proc_cmdline(pid : Int32) : String
    raw = File.read("/proc/#{pid}/cmdline")
    raw.split('\0').reject(&.empty?).join(" ")
  rescue
    "unknown"
  end

  private def executable_path : String
    File.readlink("/proc/self/exe")
  rescue
    "unknown"
  end

  def collect_process : Hash(String, String)
    pid = ProcessInfoC.getpid
    ppid = ProcessInfoC.getppid

    {
      "pid"         => pid.to_s,
      "ppid"        => ppid.to_s,
      "pgrp"        => ProcessInfoC.getpgrp.to_s,
      "parent_pgrp" => ProcessInfoC.getpgid(ppid).to_s,
      "session_id"  => ProcessInfoC.getsid(pid).to_s,

      # Linux-specific process metadata
      "executable_path" => executable_path,
      "parent_name"     => proc_read("/proc/#{ppid}/comm"),
      "parent_cmdline"  => proc_cmdline(ppid),
      "cmdline"         => proc_cmdline(pid),

      # Crystal's ARGV contains arguments excluding argv[0]
      "arguments" => ARGV.join(" "),

      # Terminal descriptors: stdin, stdout, stderr
      "stdin_tty"  => (ProcessInfoC.isatty(0) == 1).to_s,
      "stdout_tty" => (ProcessInfoC.isatty(1) == 1).to_s,
      "stderr_tty" => (ProcessInfoC.isatty(2) == 1).to_s,

      # Context clues, not proof of who launched us
      "sudo_user"      => ENV["SUDO_USER"]? || "unknown",
      "ssh_connection" => ENV["SSH_CONNECTION"]? || "unknown",
      "terminal"       => ENV["TERM"]? || "unknown",

      # Host identity
      "hostname"   => hostname,
      "machine_id" => machine_id,
      "hwid"       => hwid,

      # Operating system
      "os_name"        => os_info["os_name"],
      "os_version"     => os_info["os_version"],
      "kernel_release" => kernel_release,
      "architecture"   => architecture,

      # Hardware
      "system_vendor" => hardware_info["system_vendor"],
      "product_name"  => hardware_info["product_name"],
      "product_uuid"  => hardware_info["product_uuid"],
      "board_name"    => hardware_info["board_name"],

      # Network
      "local_addresses" => local_addresses,
    }
  end

  def print_process
    collect_process.each do |key, value|
      puts "#{key.ljust(18)}: #{value}"
    end
  end
end
