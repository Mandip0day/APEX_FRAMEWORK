# frozen_string_literal: true

module ApexFramework
  module Logger
    C_RESET  = "\e[0m"
    C_BOLD   = "\e[1m"
    C_RED    = "\e[1;31m"
    C_GREEN  = "\e[1;32m"
    C_YELLOW = "\e[1;33m"
    C_CYAN   = "\e[1;36m"

    def log_status(msg)
      $stdout.puts "#{C_CYAN}[*]#{C_RESET} #{msg}"
    end

    def log_good(msg)
      $stdout.puts "#{C_GREEN}[+]#{C_RESET} #{msg}"
    end

    def log_error(msg)
      $stdout.puts "#{C_RED}[-]#{C_RESET} #{msg}"
    end

    def log_warning(msg)
      $stdout.puts "#{C_YELLOW}[!]#{C_RESET} #{msg}"
    end

    def log_debug(msg)
      $stdout.puts "[*] debug: #{msg}" if instance_variable_defined?(:@debug) && @debug
    end

    def log_raw(msg)
      $stdout.puts msg
    end

    def log_divider
      $stdout.puts "-" * 60
    end

    def log_field(label, value)
      $stdout.puts "  #{label}: #{C_BOLD}#{value}#{C_RESET}"
    end
  end
end
