# frozen_string_literal: true

module ApexFramework
  class OptionStore

    Option = Struct.new(:name, :type, :required, :default, :description, :value, keyword_init: true) do
      def display_value
        return '' if value.nil? && default.nil?
        (value.nil? ? default : value).to_s
      end

      def resolved
        value.nil? ? default : value
      end

      def set?
        !value.nil? || !default.nil?
      end
    end

    VALID_TYPES = %i[string integer boolean port path].freeze

    attr_reader :options

    def initialize
      @options = {}
    end

    def register(name, type:, required: false, default: nil, description: '')
      name = name.to_s.upcase.to_sym
      unless VALID_TYPES.include?(type)
        raise ArgumentError, "Invalid type: #{type}"
      end

      @options[name] = Option.new(
        name:        name,
        type:        type,
        required:    required,
        default:     default,
        description: description,
        value:       nil
      )
    end

    def set(name, raw_value)
      key = name.to_s.upcase.to_sym
      opt = @options[key]
      raise "Unknown option: #{name}" unless opt

      opt.value = coerce(raw_value, opt.type)
    end

    def get(name)
      key = name.to_s.upcase.to_sym
      opt = @options[key]
      return nil unless opt

      opt.resolved
    end

    def [](name)
      get(name)
    end

    def unset(name)
      key = name.to_s.upcase.to_sym
      opt = @options[key]
      raise "Unknown option: #{name}" unless opt

      opt.value = nil
    end

    def missing_required
      @options.values
              .select { |opt| opt.required && !opt.set? }
              .map(&:name)
    end

    def validate!
      missing = missing_required
      unless missing.empty?
        raise "Missing required options: #{missing.join(', ')}"
      end
    end

    def display
      puts "\nOptions:"
      header = format(
        "  %-15s %-8s %-8s %-12s %s",
        'Name', 'Type', 'Required', 'Value', 'Description'
      )
      puts "\e[1m#{header}\e[0m"
      puts "-" * 75

      @options.values.sort_by { |o| o.required ? 0 : 1 }.each do |opt|
        req_str     = opt.required ? 'yes' : 'no'
        val_str     = opt.display_value
        val_display = opt.set? ? val_str : '<nil>'

        puts format(
          "  %-15s %-8s %-8s %-12s %s",
          opt.name, opt.type, req_str, val_display, opt.description
        )
      end
      puts
    end

    def to_h
      @options.transform_values(&:resolved)
    end

    private

    def coerce(raw, type)
      return nil if raw.nil?

      case type
      when :string
        raw.to_s
      when :integer
        Integer(raw)
      when :boolean
        %w[true 1 yes on].include?(raw.to_s.strip.downcase)
      when :port
        port = Integer(raw)
        raise ArgumentError, "Port range error" unless (1..65_535).include?(port)
        port
      when :path
        expanded = File.expand_path(raw.to_s)
        raise ArgumentError, "Path not found" unless File.exist?(expanded)
        expanded
      else
        raw
      end
    rescue ArgumentError, TypeError => e
      raise ArgumentError, "Coercion error: #{e.message}"
    end
  end
end
