# frozen_string_literal: true

require_relative 'logger'
require_relative 'option_store'

module ApexFramework
  class ApexModule

    include ApexFramework::Logger

    @registry = {}

    class << self
      attr_reader :registry

      def register_module(key, klass)
        @registry[key] = klass
      end

      def lookup(key)
        @registry[key]
      end

      def registered_keys
        @registry.keys
      end
    end

    class << self
      attr_reader :module_metadata, :option_definitions

      def info(hash)
        @module_metadata = hash.freeze
      end

      def register_option(name, type:, required: false, default: nil, description: '')
        @option_definitions ||= []
        @option_definitions << {
          name:        name,
          type:        type,
          required:    required,
          default:     default,
          description: description
        }
      end

      def inherited(subclass)
        super
        if option_definitions
          subclass.instance_variable_set(:@option_definitions, option_definitions.dup)
        end
      end
    end

    attr_reader :option_store

    def initialize
      @option_store = OptionStore.new
      (self.class.option_definitions || []).each do |defn|
        @option_store.register(
          defn[:name],
          type:        defn[:type],
          required:    defn[:required],
          default:     defn[:default],
          description: defn[:description]
        )
      end
    end

    def options
      @option_store.to_h
    end

    def set(name, value)
      @option_store.set(name, value)
    end

    def get(name)
      @option_store.get(name)
    end

    def show_options
      @option_store.display
    end

    def validate!
      @option_store.validate!
    end

    def module_name
      self.class.module_metadata&.dig(:name) || self.class.name
    end

    def module_category
      self.class.module_metadata&.dig(:category) || 'uncategorized'
    end

    def module_rank
      self.class.module_metadata&.dig(:rank) || 'unknown'
    end

    def module_description
      self.class.module_metadata&.dig(:description) || ''
    end

    def module_authors
      self.class.module_metadata&.dig(:authors) || []
    end

    def module_references
      self.class.module_metadata&.dig(:references) || []
    end

    def module_disclosure_date
      self.class.module_metadata&.dig(:disclosure_date)
    end

    def module_platform
      self.class.module_metadata&.dig(:platform)
    end

    def module_arch
      self.class.module_metadata&.dig(:arch)
    end

    def show_info
      meta = self.class.module_metadata || {}

      puts "\nModule info:"
      log_field 'Name',           meta[:name]
      log_field 'Category',       meta[:category]
      log_field 'Rank',           meta[:rank]
      log_field 'Platform',       meta[:platform]
      log_field 'Arch',           meta[:arch]
      log_field 'Authors',        meta[:authors]&.join(', ')
      log_field 'Disclosure',     meta[:disclosure_date]

      if meta[:references]&.any?
        refs = meta[:references].map { |r| "#{r[:type]}-#{r[:id]}" }.join(', ')
        log_field 'References', refs
      end

      if meta[:description]
        puts "\nDescription:"
        puts "  #{meta[:description]}"
      end
      puts
    end

    def run
      raise NotImplementedError, "run method not implemented"
    end

    def execute
      validate!
      log_status "Executing: #{module_name}"
      log_divider
      run
    rescue NotImplementedError => e
      log_error e.message
    rescue StandardError => e
      log_error "Failed: #{e.message}"
    end
  end
end
