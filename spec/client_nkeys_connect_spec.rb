require 'spec_helper'

describe 'Client - NATS v2 Auth' do

  context 'with NKEYS and JWT' do
    before(:each) do
      config_opts = {
        'pid_file'      => '/tmp/nats_nkeys_jwt.pid',
        'host'          => '127.0.0.1',
        'port'          => 4722,
      }
      @s = NatsServerControl.init_with_config_from_string(%Q(
        authorization {
          timeout: 2
        }

        port = #{config_opts['port']}
        operator = "./spec/configs/nkeys/op.jwt"

        # This is for account resolution.
        resolver = MEMORY

         # This is a map that can preload keys:jwts into a memory resolver.
         resolver_preload = {
           # foo
           AD7SEANS6BCBF6FHIB7SQ3UGJVPW53BXOALP75YXJBBXQL7EAFB6NJNA : "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJqdGkiOiIyUDNHU1BFSk9DNlVZNE5aM05DNzVQVFJIV1pVRFhPV1pLR0NLUDVPNjJYSlZESVEzQ0ZRIiwiaWF0IjoxNTUzODQwNjE1LCJpc3MiOiJPRFdJSUU3SjdOT1M3M1dWQk5WWTdIQ1dYVTRXWFdEQlNDVjRWSUtNNVk0TFhUT1Q1U1FQT0xXTCIsIm5hbWUiOiJmb28iLCJzdWIiOiJBRDdTRUFOUzZCQ0JGNkZISUI3U1EzVUdKVlBXNTNCWE9BTFA3NVlYSkJCWFFMN0VBRkI2TkpOQSIsInR5cGUiOiJhY2NvdW50IiwibmF0cyI6eyJsaW1pdHMiOnsic3VicyI6LTEsImNvbm4iOi0xLCJpbXBvcnRzIjotMSwiZXhwb3J0cyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwid2lsZGNhcmRzIjp0cnVlfX19.COiKg5EFK4Gb2gA7vtKHQK7vjMEUx-RMWYuN-Bg-uVOFs9GLwW7Dxc4TcN-poBGBEkwKnleiA9SjYO3y4-AqBQ"

           # bar
           AAXPTP32BD73YW3ACUY6DPXKWBSUW4VEZNE3LD4FUOFDP6KDU43PQVU2 : "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJqdGkiOiJPQ1dUQkRQTzVETjRSV0lFNEtJQ1BQWkszUEhHV0dQUVFKNFVET1pQSTVaRzJQUzZKVkpBIiwiaWF0IjoxNTUzODQwNjE5LCJpc3MiOiJPRFdJSUU3SjdOT1M3M1dWQk5WWTdIQ1dYVTRXWFdEQlNDVjRWSUtNNVk0TFhUT1Q1U1FQT0xXTCIsIm5hbWUiOiJiYXIiLCJzdWIiOiJBQVhQVFAzMkJENzNZVzNBQ1VZNkRQWEtXQlNVVzRWRVpORTNMRDRGVU9GRFA2S0RVNDNQUVZVMiIsInR5cGUiOiJhY2NvdW50IiwibmF0cyI6eyJsaW1pdHMiOnsic3VicyI6LTEsImNvbm4iOi0xLCJpbXBvcnRzIjotMSwiZXhwb3J0cyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwid2lsZGNhcmRzIjp0cnVlfX19.KY2fBvYyNCA0dYS7I6_rETGHT4YGkWZSh03XhXxwAvJ8XCfKlVJRY82U-0ERg01SFtPTZ-6BYu-sty1E67ioDA"
         }
      ), config_opts)
      @s.start_server(true)
    end

    after(:each) do
      @s.kill_server
    end

    it 'should connect to server and publish messages' do
      mon = Monitor.new
      done = mon.new_cond

      errors = []
      msgs = []
      nats = NATS::IO::Client.new
      nats.on_error do |e|
        errors << e
      end
      nats.connect(servers: ['nats://127.0.0.1:4722'],
                   reconnect: false,
                   user_credentials: "./spec/configs/nkeys/foo-user.creds")
      nats.subscribe("hello") do |msg|
        msgs << msg
        done.signal
      end
      nats.flush
      nats.publish("hello", 'world')

      mon.synchronize do
        done.wait(1)
      end
      nats.close
      expect(msgs.count).to eql(1)
    end

    it 'should support user supplied credential callbacks' do
      mon = Monitor.new
      done = mon.new_cond

      errors = []
      msgs = []
      nats = NATS::IO::Client.new
      nats.on_error do |e|
        errors << e
      end

      user_sig_called = false
      sig_cb = proc { |nonce|
        user_sig_called = true
        nats.send(:signature_cb_for_creds_file, "./spec/configs/nkeys/foo-user.creds").call(nonce)
      }

      user_jwt_called = false
      jwt_cb = proc {
        user_jwt_called = true
        nats.send(:jwt_cb_for_creds_file, "./spec/configs/nkeys/foo-user.creds").call()
      }

      nats.connect(servers: ['nats://127.0.0.1:4722'],
                   reconnect: false,
                   user_signature_cb: sig_cb,
                   user_jwt_cb: jwt_cb)

      expect(user_sig_called).to be(true)
      expect(user_jwt_called).to be(true)

      nats.subscribe("hello") do |msg|
        msgs << msg
        done.signal
      end
      nats.flush
      nats.publish("hello", 'world')

      mon.synchronize do
        done.wait(1)
      end
      nats.close
      expect(msgs.count).to eql(1)
    end

    it 'should fail with auth error if no user credentials present' do
      mon = Monitor.new
      done = mon.new_cond

      errors = []
      msgs = []
      nats = NATS::IO::Client.new
      nats.on_error do |e|
        errors << e
      end

      expect do
        nats.connect(servers: ['nats://127.0.0.1:4722'],
                     reconnect: false)
      end.to raise_error(NATS::IO::AuthError)

      expect(errors.count).to eql(1)
    end
  end

  context 'with NKEYS only' do
    before(:each) do
      config_opts = {
        'pid_file'      => '/tmp/nats_nkeys.pid',
        'host'          => '127.0.0.1',
        'port'          => 4723,
      }
      @s = NatsServerControl.init_with_config_from_string(%Q(
        authorization {
          timeout: 2
        }

        port = #{config_opts['port']}

        accounts {
          acme {
            users [
              {
                 nkey = "UCK5N7N66OBOINFXAYC2ACJQYFSOD4VYNU6APEJTAVFZB2SVHLKGEW7L",
                 permissions = {
                   subscribe = {
                     allow = ["hello", "_INBOX.>"]
                     deny = ["foo"]
                   }
                   publish = {
                     allow = ["hello", "_INBOX.>"]
                     deny = ["foo"]
                   }
                 }
              }
            ]
          }
        }
      ), config_opts)
      @s.start_server(true)
    end

    after(:each) do
      @s.kill_server
    end

    it 'should connect to the server and publish messages' do
      mon = Monitor.new
      done = mon.new_cond

      errors = []
      msgs = []
      nats = NATS::IO::Client.new
      nats.on_error do |e|
        errors << e
      end
      nats.connect(servers: ['nats://127.0.0.1:4723'],
                   reconnect: false,
                   nkeys_seed: "./spec/configs/nkeys/foo-user.nk")
      nats.subscribe("hello") do |msg|
        msgs << msg
        done.signal
      end
      nats.flush
      nats.publish("hello", 'world')

      mon.synchronize do
        done.wait(1)
      end
      nats.close
      expect(msgs.count).to eql(1)
    end

    it 'should support user supplied nkey callbacks' do
      mon = Monitor.new
      done = mon.new_cond

      errors = []
      msgs = []
      nats = NATS::IO::Client.new
      nats.on_error do |e|
        errors << e
      end

      user_nkey_called = false
      user_nkey_cb = proc {
        user_nkey_called = true
        nats.send(:nkey_cb_for_nkey_file, "./spec/configs/nkeys/foo-user.nk").call()
      }

      user_sig_called = false
      sig_cb = proc { |nonce|
        user_sig_called = true
        nats.send(:signature_cb_for_nkey_file, "./spec/configs/nkeys/foo-user.nk").call(nonce)
      }

      nats.connect(servers: ['nats://127.0.0.1:4723'],
                   reconnect: false,
                   user_nkey_cb: user_nkey_cb,
                   user_signature_cb: sig_cb)

      expect(user_sig_called).to be(true)
      expect(user_nkey_called).to be(true)

      nats.subscribe("hello") do |msg|
        msgs << msg
        done.signal
      end
      nats.flush
      nats.publish("hello", 'world')

      mon.synchronize do
        done.wait(1)
      end
      nats.close
      expect(msgs.count).to eql(1)
    end
  end

  context "with 3-node cluster" do
    before(:all) do
      auth_options = {
        'timeout'  => 5
      }

      s1_config_opts = {
        'pid_file'      => '/tmp/nats_cluster_s1.pid',
        'authorization' => auth_options,
        'host'          => '127.0.0.1',
        'port'          => 4722,
        'cluster_port'  => 6222
      }

      s2_config_opts = {
        'pid_file'      => '/tmp/nats_cluster_s2.pid',
        'authorization' => auth_options,
        'host'          => '127.0.0.1',
        'port'          => 4723,
        'cluster_port'  => 6223
      }

      s3_config_opts = {
        'pid_file'      => '/tmp/nats_cluster_s3.pid',
        'authorization' => auth_options,
        'host'          => '127.0.0.1',
        'port'          => 4724,
        'cluster_port'  => 6224
      }

      nodes = []
      configs = [s1_config_opts, s2_config_opts, s3_config_opts]
      configs.each do |config_opts|
        nodes << NatsServerControl.init_with_config_from_string(%Q(
        host: '#{config_opts['host']}'
        port:  #{config_opts['port']}
        pid_file: '#{config_opts['pid_file']}'
        authorization {
          timeout: #{auth_options["timeout"]}
        }
        cluster {
          name: "TEST"
          host: '#{config_opts['host']}'
          port: #{config_opts['cluster_port']}

          authorization {
            timeout: 5
          }

          routes = [
            'nats://127.0.0.1:#{s1_config_opts['cluster_port']}',
            'nats://127.0.0.1:#{s2_config_opts['cluster_port']}',
            'nats://127.0.0.1:#{s3_config_opts['cluster_port']}'
          ]
        }

        operator = "./spec/configs/nkeys/op.jwt"

        # This is for account resolution.
        resolver = MEMORY

         # This is a map that can preload keys:jwts into a memory resolver.
         resolver_preload = {
           # foo
           AD7SEANS6BCBF6FHIB7SQ3UGJVPW53BXOALP75YXJBBXQL7EAFB6NJNA : "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJqdGkiOiIyUDNHU1BFSk9DNlVZNE5aM05DNzVQVFJIV1pVRFhPV1pLR0NLUDVPNjJYSlZESVEzQ0ZRIiwiaWF0IjoxNTUzODQwNjE1LCJpc3MiOiJPRFdJSUU3SjdOT1M3M1dWQk5WWTdIQ1dYVTRXWFdEQlNDVjRWSUtNNVk0TFhUT1Q1U1FQT0xXTCIsIm5hbWUiOiJmb28iLCJzdWIiOiJBRDdTRUFOUzZCQ0JGNkZISUI3U1EzVUdKVlBXNTNCWE9BTFA3NVlYSkJCWFFMN0VBRkI2TkpOQSIsInR5cGUiOiJhY2NvdW50IiwibmF0cyI6eyJsaW1pdHMiOnsic3VicyI6LTEsImNvbm4iOi0xLCJpbXBvcnRzIjotMSwiZXhwb3J0cyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwid2lsZGNhcmRzIjp0cnVlfX19.COiKg5EFK4Gb2gA7vtKHQK7vjMEUx-RMWYuN-Bg-uVOFs9GLwW7Dxc4TcN-poBGBEkwKnleiA9SjYO3y4-AqBQ"

           # bar
           AAXPTP32BD73YW3ACUY6DPXKWBSUW4VEZNE3LD4FUOFDP6KDU43PQVU2 : "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJqdGkiOiJPQ1dUQkRQTzVETjRSV0lFNEtJQ1BQWkszUEhHV0dQUVFKNFVET1pQSTVaRzJQUzZKVkpBIiwiaWF0IjoxNTUzODQwNjE5LCJpc3MiOiJPRFdJSUU3SjdOT1M3M1dWQk5WWTdIQ1dYVTRXWFdEQlNDVjRWSUtNNVk0TFhUT1Q1U1FQT0xXTCIsIm5hbWUiOiJiYXIiLCJzdWIiOiJBQVhQVFAzMkJENzNZVzNBQ1VZNkRQWEtXQlNVVzRWRVpORTNMRDRGVU9GRFA2S0RVNDNQUVZVMiIsInR5cGUiOiJhY2NvdW50IiwibmF0cyI6eyJsaW1pdHMiOnsic3VicyI6LTEsImNvbm4iOi0xLCJpbXBvcnRzIjotMSwiZXhwb3J0cyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwid2lsZGNhcmRzIjp0cnVlfX19.KY2fBvYyNCA0dYS7I6_rETGHT4YGkWZSh03XhXxwAvJ8XCfKlVJRY82U-0ERg01SFtPTZ-6BYu-sty1E67ioDA"
         }
      ), config_opts)
      end

      @s1, @s2, @s3 = nodes
    end

    context "using JWT creds" do
      before(:each) do
        [@s1, @s2, @s3].each do |s|
          s.start_server(true)
        end
      end

      after(:each) do
        [@s1, @s2, @s3].each do |s|
          s.kill_server
        end
      end

      it 'should connect to server and publish messages' do
        recon = Monitor.new
        reconnected = recon.new_cond

        errors = []
        nc = NATS::IO::Client.new
        nc.on_error do |e|
          errors << e
        end

        nc.on_reconnect do |e|
          recon.synchronize do
            reconnected.signal
          end
        end
        
        nc.connect(servers: ['nc://127.0.0.1:4722'],
                   reconnect: true,
                   reconnect_time_wait: 0.5,
                   user_credentials: "./spec/configs/nkeys/foo-user.creds")
        nc.subscribe("hello") do |msg|
          msg.respond('ok') if msg.reply
        end
        nc.flush
        nc.request("hello", 'world')

        Thread.new do
          sleep 0.5
          @s1.kill_server
        end

        recon.synchronize do
          reconnected.wait(1)
        end
        expect(nc.connected_server).not_to eql(@s1.uri)

        sleep 1
        resp = nc.request('hello', '', timeout: 1)
        expect(resp.data).to eql('ok')

        # Now kill all servers and wait for a bit, it should be a reasonable
        # numbers of retries.
        @s2.kill_server
        @s3.kill_server

        sleep 1
        expect(errors.count < 10).to eql(true)

        s1_config_opts = {
          'pid_file'      => '/tmp/nats_cluster_s1.pid',
          'host'          => '127.0.0.1',
          'port'          => 4722,
          'cluster_port'  => 6222
        }

        # Restart one of the servers but with the missing account, it should not be possible to connect either.
        nodes = []
        configs = [s1_config_opts]
        configs.each do |config_opts|
          nodes << NatsServerControl.init_with_config_from_string(%Q(
          host: '#{config_opts['host']}'
          port:  #{config_opts['port']}
          pid_file: '#{config_opts['pid_file']}'

          cluster {
            name: "TEST"
            host: '#{config_opts['host']}'
            port: #{config_opts['cluster_port']}

            authorization {
              timeout: 5
            }
          }

          operator = "./spec/configs/nkeys/op.jwt"

          # This is for account resolution.
          resolver = MEMORY

           # This is a map that can preload keys:jwts into a memory resolver.
           resolver_preload = {
             # foo
             # AD7SEANS6BCBF6FHIB7SQ3UGJVPW53BXOALP75YXJBBXQL7EAFB6NJNA : "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJqdGkiOiIyUDNHU1BFSk9DNlVZNE5aM05DNzVQVFJIV1pVRFhPV1pLR0NLUDVPNjJYSlZESVEzQ0ZRIiwiaWF0IjoxNTUzODQwNjE1LCJpc3MiOiJPRFdJSUU3SjdOT1M3M1dWQk5WWTdIQ1dYVTRXWFdEQlNDVjRWSUtNNVk0TFhUT1Q1U1FQT0xXTCIsIm5hbWUiOiJmb28iLCJzdWIiOiJBRDdTRUFOUzZCQ0JGNkZISUI3U1EzVUdKVlBXNTNCWE9BTFA3NVlYSkJCWFFMN0VBRkI2TkpOQSIsInR5cGUiOiJhY2NvdW50IiwibmF0cyI6eyJsaW1pdHMiOnsic3VicyI6LTEsImNvbm4iOi0xLCJpbXBvcnRzIjotMSwiZXhwb3J0cyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwid2lsZGNhcmRzIjp0cnVlfX19.COiKg5EFK4Gb2gA7vtKHQK7vjMEUx-RMWYuN-Bg-uVOFs9GLwW7Dxc4TcN-poBGBEkwKnleiA9SjYO3y4-AqBQ"

             # bar
             AAXPTP32BD73YW3ACUY6DPXKWBSUW4VEZNE3LD4FUOFDP6KDU43PQVU2 : "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJqdGkiOiJPQ1dUQkRQTzVETjRSV0lFNEtJQ1BQWkszUEhHV0dQUVFKNFVET1pQSTVaRzJQUzZKVkpBIiwiaWF0IjoxNTUzODQwNjE5LCJpc3MiOiJPRFdJSUU3SjdOT1M3M1dWQk5WWTdIQ1dYVTRXWFdEQlNDVjRWSUtNNVk0TFhUT1Q1U1FQT0xXTCIsIm5hbWUiOiJiYXIiLCJzdWIiOiJBQVhQVFAzMkJENzNZVzNBQ1VZNkRQWEtXQlNVVzRWRVpORTNMRDRGVU9GRFA2S0RVNDNQUVZVMiIsInR5cGUiOiJhY2NvdW50IiwibmF0cyI6eyJsaW1pdHMiOnsic3VicyI6LTEsImNvbm4iOi0xLCJpbXBvcnRzIjotMSwiZXhwb3J0cyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwid2lsZGNhcmRzIjp0cnVlfX19.KY2fBvYyNCA0dYS7I6_rETGHT4YGkWZSh03XhXxwAvJ8XCfKlVJRY82U-0ERg01SFtPTZ-6BYu-sty1E67ioDA"
           }
        ), config_opts)

          nodes.each { |node| node.start_server(true) }
          sleep 5
          nodes.each { |node| node.kill_server }
          auth_errors = errors.select { |e| e.is_a? NATS::IO::AuthError}
          expect(auth_errors.count > 0).to eql(true)
          expect(auth_errors.count < 20).to eql(true)
        end
      end
    end
  end
end
