
@[Link("c")]
lib ProcessInfoC
  fun getpid : Int32
  fun getppid : Int32
  fun getpgrp : Int32
  fun getpgid(pid : Int32) : Int32
  fun getsid(pid : Int32) : Int32
  fun isatty(fd : Int32) : Int32
end

module WhoAmI
  extend self

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
    pid  = ProcessInfoC.getpid
    ppid = ProcessInfoC.getppid

    {
      "pid"             => pid.to_s,
      "ppid"            => ppid.to_s,
      "pgrp"            => ProcessInfoC.getpgrp.to_s,
      "parent_pgrp"     => ProcessInfoC.getpgid(ppid).to_s,
      "session_id"      => ProcessInfoC.getsid(pid).to_s,

      # Linux-specific process metadata
      "executable_path" => executable_path,
      "parent_name"     => proc_read("/proc/#{ppid}/comm"),
      "parent_cmdline"  => proc_cmdline(ppid),
      "cmdline"         => proc_cmdline(pid),

      # Crystal's ARGV contains arguments excluding argv[0]
      "arguments"       => ARGV.join(" "),

      # Terminal descriptors: stdin, stdout, stderr
      "stdin_tty"       => (ProcessInfoC.isatty(0) == 1).to_s,
      "stdout_tty"      => (ProcessInfoC.isatty(1) == 1).to_s,
      "stderr_tty"      => (ProcessInfoC.isatty(2) == 1).to_s,

      # Context clues, not proof of who launched us
      "sudo_user"       => ENV["SUDO_USER"]? || "unknown",
      "ssh_connection"  => ENV["SSH_CONNECTION"]? || "unknown",
      "terminal"        => ENV["TERM"]? || "unknown"
    }
  end

  def print_process
    collect_process.each do |key, value|
      puts "#{key.ljust(18)}: #{value}"
    end
  end
end

WhoAmI.print_process
