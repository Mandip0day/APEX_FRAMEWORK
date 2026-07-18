#!/usr/bin/env ruby
# frozen_string_literal: true

require 'readline'
require 'pathname'
require 'fileutils'

require_relative 'lib/logger'
require_relative 'lib/option_store'
require_relative 'lib/apex_module'

module ApexFramework
  VERSION     = '1.0.0'.freeze
  CODENAME    = 'Nightfall'.freeze
  BUILD_DATE  = '2026-07-19'.freeze

  C_RESET  = "\e[0m"
  C_BOLD   = "\e[1m"
  C_RED    = "\e[1;31m"
  C_GREEN  = "\e[1;32m"
  C_YELLOW = "\e[1;33m"
  C_CYAN   = "\e[1;36m"
  C_WHITE  = "\e[1;37m"

  P_BOLD   = "\001\e[1m\002"
  P_RESET  = "\001\e[0m\002"

  BANNER = "#{C_CYAN}#{C_BOLD}APEX FRAMEWORK | DEV: MANDIP | STATUS: RESEARCH | VER: #{VERSION}#{C_RESET}"

  class ModuleScanner
    attr_reader :modules, :base_path

    def initialize(base_path)
      @base_path = Pathname.new(base_path).expand_path
      @modules   = {}
    end

    def scan!
      @modules.clear
      ApexFramework::ApexModule.registry.clear

      modules_dir = @base_path.join('modules')
      Dir.glob(modules_dir.join('**', '*.rb')).each do |file_path|
        begin
          load file_path
        rescue StandardError, ScriptError => e
          puts "#{C_RED}[-]#{C_RESET} Failed to load #{file_path}: #{e.message}"
        end
      end

      ApexFramework::ApexModule.registry.each do |key, klass|
        meta = klass.module_metadata || {}
        @modules[key] = {
          class:    klass,
          path:     modules_dir.join("#{key}.rb").to_s,
          category: meta[:category] || 'uncategorized',
          name:     meta[:name] || key.split('/').last,
          key:      key,
          metadata: meta
        }
      end

      @modules.size
    end

    def list
      puts
      header = format(
        "  %-30s  %-12s  %-10s  %s",
        'Module Name', 'Category', 'Rank', 'Description'
      )
      puts "#{C_CYAN}#{header}#{C_RESET}"
      puts "-" * 100

      @modules.values.sort_by { |m| m[:key] }.each do |mod|
        meta = mod[:metadata]
        desc = meta[:description] || ''
        desc = "#{desc[0..42]}..." if desc.length > 45

        puts format(
          "  %-30s  %-12s  %-10s  %s",
          mod[:key], mod[:category], meta[:rank] || 'unknown', desc
        )
      end
      puts
    end

    def find(key)
      return @modules[key] if @modules.key?(key)
      matches = @modules.keys.select { |k| k.include?(key) }
      return @modules[matches.first] if matches.size == 1
      nil
    end
  end

  class Console
    PROMPT_DEFAULT  = "#{P_BOLD}apex > #{P_RESET}".freeze
    PROMPT_MODULE   = "#{P_BOLD}apex(%s) > #{P_RESET}".freeze

    HELP_TEXT = <<~HELP.freeze
      Commands:
        list                    List available modules
        select <name>           Select a module
        info                    Show selected module info
        options                 Show selected module options
        set <name> <value>      Set an option value
        run                     Execute the active module
        search <term>           Search modules by keyword
        reload                  Scan modules folder
        banner                  Show framework banner
        clear                   Clear terminal buffer
        back                    Deselect active module
        help                    Show commands list
        exit / quit             Exit framework
    HELP

    def initialize(base_path)
      @scanner                 = ModuleScanner.new(base_path)
      @selected_module_meta    = nil
      @selected_module_instance = nil
      @running                 = false
    end

    def start
      cmd_clear
      load_modules
      @running = true
      command_loop
    ensure
      print C_RESET
    end

    private

    def display_banner
      puts BANNER
    end

    def load_modules
      count = @scanner.scan!
      puts "#{C_WHITE}[*]#{C_RESET} Scanned workspace: #{@scanner.base_path}"
      puts "#{C_WHITE}[*]#{C_RESET} Modules loaded: #{count}"
      puts
    end

    def current_prompt
      if @selected_module_meta
        format(PROMPT_MODULE, @selected_module_meta[:key])
      else
        PROMPT_DEFAULT
      end
    end

    def command_loop
      Readline.completion_proc = method(:tab_complete)

      while @running
        begin
          line = Readline.readline(current_prompt, true)
          if line.nil?
            puts
            cmd_exit
            next
          end

          line.strip!
          next if line.empty?

          if Readline::HISTORY.length > 1 && Readline::HISTORY[-2] == line
            Readline::HISTORY.pop
          end

          dispatch(line)
        rescue Interrupt
          puts
          cmd_exit
        end
      end
    end

    def dispatch(input)
      parts = input.split(/\s+/, 3)
      cmd   = parts[0].downcase
      args1 = parts[1]
      args2 = parts[2]

      case cmd
      when 'list', 'ls'          then cmd_list
      when 'select', 'use'       then cmd_select(args1)
      when 'info', 'show'        then cmd_info
      when 'options'             then cmd_options
      when 'set'                 then cmd_set(args1, args2)
      when 'run', 'execute'      then cmd_run
      when 'search', 'find'      then cmd_search(args1)
      when 'reload'              then cmd_reload
      when 'banner'              then display_banner
      when 'clear'               then cmd_clear
      when 'back'                then cmd_back
      when 'help', '?'           then puts HELP_TEXT
      when 'exit', 'quit'        then cmd_exit
      else
        puts "#{C_RED}[-]#{C_RESET} Error: Unknown command '#{cmd}'"
      end
    end

    def cmd_list
      if @scanner.modules.empty?
        puts "#{C_RED}[-]#{C_RESET} Error: No modules loaded"
        return
      end
      @scanner.list
    end

    def cmd_select(name)
      unless name && !name.empty?
        puts "#{C_RED}[-]#{C_RESET} Error: Usage: select <module_name>"
        return
      end

      mod = @scanner.find(name.strip)
      if mod
        @selected_module_meta     = mod
        @selected_module_instance = mod[:class].new
        puts "#{C_GREEN}[+]#{C_RESET} Selected: #{mod[:key]}"
      else
        puts "#{C_RED}[-]#{C_RESET} Error: Module not found: #{name}"
      end
    end

    def cmd_info
      unless @selected_module_instance
        puts "#{C_RED}[-]#{C_RESET} Error: No module selected"
        return
      end
      @selected_module_instance.show_info
    end

    def cmd_options
      unless @selected_module_instance
        puts "#{C_RED}[-]#{C_RESET} Error: No module selected"
        return
      end
      @selected_module_instance.show_options
    end

    def cmd_set(option, value)
      unless @selected_module_instance
        puts "#{C_RED}[-]#{C_RESET} Error: No module selected"
        return
      end
      unless option && value
        puts "#{C_RED}[-]#{C_RESET} Error: Usage: set <option> <value>"
        return
      end

      begin
        @selected_module_instance.set(option, value)
        puts "#{C_GREEN}[+]#{C_RESET} #{option.upcase} => #{value}"
      rescue StandardError => e
        puts "#{C_RED}[-]#{C_RESET} Error: #{e.message}"
      end
    end

    def cmd_run
      unless @selected_module_instance
        puts "#{C_RED}[-]#{C_RESET} Error: No module selected"
        return
      end
      @selected_module_instance.execute
    end

    def cmd_search(term)
      unless term && !term.empty?
        puts "#{C_RED}[-]#{C_RESET} Error: Usage: search <term>"
        return
      end

      term_down = term.downcase
      results = @scanner.modules.select do |key, mod|
        key.downcase.include?(term_down) ||
          (mod[:metadata][:name] || '').downcase.include?(term_down) ||
          (mod[:metadata][:description] || '').downcase.include?(term_down)
      end

      if results.empty?
        puts "#{C_CYAN}[*]#{C_RESET} No matching modules found"
        return
      end

      puts "\nSearch results:"
      results.each do |key, mod|
        meta = mod[:metadata]
        puts "  #{key.ljust(35)} [#{meta[:rank] || '?'}]"
        puts "    #{meta[:description]}" if meta[:description]
      end
      puts
    end

    def cmd_reload
      puts "#{C_WHITE}[*]#{C_RESET} Reloading..."
      load_modules
    end

    def cmd_clear
      if Gem.win_platform?
        system('cls')
      else
        system('clear')
      end
      display_banner
    end

    def cmd_back
      if @selected_module_meta
        @selected_module_meta     = nil
        @selected_module_instance = nil
      else
        puts "#{C_RED}[-]#{C_RESET} Error: No active module"
      end
    end

    def cmd_exit
      @running = false
    end

    def tab_complete(input)
      commands = %w[list select info options set run search reload banner clear back help exit quit]

      if Readline.line_buffer =~ /^(select|use)\s+/i
        prefix = input.downcase
        return @scanner.modules.keys.select { |k| k.downcase.start_with?(prefix) }
      elsif Readline.line_buffer =~ /^set\s+/i && @selected_module_instance
        prefix = input.downcase
        opts = @selected_module_instance.option_store.options.keys.map(&:to_s)
        return opts.select { |o| o.downcase.start_with?(prefix) }
      end

      commands.select { |c| c.start_with?(input.downcase) }
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  base_path = File.expand_path(File.dirname(__FILE__))
  console = ApexFramework::Console.new(base_path)
  console.start
end
